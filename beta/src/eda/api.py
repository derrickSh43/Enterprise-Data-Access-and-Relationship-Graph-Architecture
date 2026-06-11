"""HTTP API: each component exposed under its own prefix, plus the governed
request flow at POST /requests.

Run:  uvicorn eda.api:app --reload
Docs: http://127.0.0.1:8000/docs
"""

from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import access_graph, actions, audit, feedback, gateway, identity, ingestion, policy
from .config import settings
from .db import get_session, init_db
from .identity_providers import get_identity_provider, map_principal
from .models import AuditRecord, Recommendation
from .seed import seed


def _bearer(authorization: str | None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "missing bearer token")
    return authorization[7:].strip()


def _verified_principal(db: Session, authorization: str | None):
    """Authenticate a caller and map them to a graph principal (fail closed)."""
    try:
        session = get_identity_provider().verify(_bearer(authorization))
    except identity.InvalidSession as exc:
        raise HTTPException(401, str(exc))
    principal = map_principal(db, session)
    if principal is None:
        raise HTTPException(403, "no mapped graph principal for this identity")
    return session, principal


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    from .db import SessionLocal

    with SessionLocal() as db:
        seed(db)
    yield


app = FastAPI(
    title="EDA Control Plane",
    description="Local-first governed enterprise control plane (reference implementation)",
    version="0.1.0",
    lifespan=lifespan,
)


# ---- Identity ----------------------------------------------------------------
# Dev-only session minting for tests and local demos. In OIDC mode this
# endpoint is disabled: identity, MFA status, and risk are never
# caller-supplied - they come from validated provider claims.
class SessionRequest(BaseModel):
    subject: str
    mfa: bool = True
    risk_score: int = Field(default=0, ge=0, le=100)
    tags: dict = Field(default_factory=dict)


@app.post("/identity/sessions", tags=["identity"])
def create_session(body: SessionRequest):
    if settings.auth_mode != "dev":
        raise HTTPException(403, "self-issued sessions are disabled outside dev mode")
    token = identity.issue_session(
        body.subject, mfa=body.mfa, risk_score=body.risk_score, tags=body.tags
    )
    return {"session_token": token}


# ---- Access Graph -----------------------------------------------------------
@app.get("/access-graph/path", tags=["access-graph"])
def get_path(subject: str, action: str, resource: str, db: Session = Depends(get_session)):
    path = access_graph.resolve_path(db, subject, action, resource)
    if path is None:
        return {"exists": False, "hops": [], "allowed_actions": []}
    return {"exists": True, "hops": path.hops, "allowed_actions": path.allowed_actions}


# ---- Policy Engine ----------------------------------------------------------
@app.get("/policy/active", tags=["policy"])
def get_active_policy(db: Session = Depends(get_session)):
    record = policy.active_policy(db)
    return {"version": record.version, "document": record.document}


@app.post("/policy/evaluate", tags=["policy"])
def evaluate_policy(policy_input: dict, db: Session = Depends(get_session)):
    return policy.evaluate(db, policy_input).as_json()


# ---- Action registry --------------------------------------------------------
@app.get("/actions", tags=["actions"])
def list_actions():
    return [
        {
            "name": a.name,
            "description": a.description,
            "cloud_action": a.cloud_action,
            "read_only": a.read_only,
            "risk": a.risk,
            "blast_radius": a.blast_radius,
            "required_inputs": list(a.required_inputs),
            "rollback": a.rollback,
        }
        for a in actions.REGISTRY.values()
    ]


# ---- Governed request flow --------------------------------------------------
class GovernedRequest(BaseModel):
    action: str
    resource: str
    inputs: dict = Field(default_factory=dict)
    justification: dict = Field(default_factory=dict)
    approval_id: str | None = None


@app.post("/requests", tags=["requests"])
def submit_request(
    body: GovernedRequest,
    db: Session = Depends(get_session),
    authorization: str | None = Header(default=None),
):
    return gateway.handle_request(
        db,
        bearer_token=_bearer(authorization),
        action_name=body.action,
        resource=body.resource,
        inputs=body.inputs,
        justification=body.justification,
        approval_id=body.approval_id,
    )


# ---- Approvals ---------------------------------------------------------------
class ApprovalDecision(BaseModel):
    approve: bool


@app.post("/approvals/{approval_id}/decision", tags=["approvals"])
def decide_approval(
    approval_id: str,
    body: ApprovalDecision,
    db: Session = Depends(get_session),
    authorization: str | None = Header(default=None),
):
    _, approver = _verified_principal(db, authorization)
    try:
        record = gateway.decide_approval(
            db, approval_id, approver=approver.name, approve=body.approve
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return {"approval_id": record.id, "status": record.status, "approver": record.approver}


# ---- Relationship ingestion (collector endpoint) ------------------------------
class EntityRef(BaseModel):
    kind: str
    id: str


class RelationshipIn(BaseModel):
    subject: EntityRef
    relation: str
    target: EntityRef
    attributes: dict = Field(default_factory=dict)


class RelationshipBatch(BaseModel):
    relationships: list[RelationshipIn]
    observed_at: datetime | None = None  # collection time; defaults to receipt time


@app.post("/relationship-sources/{source_id}/relationships", tags=["ingestion"])
def ingest_relationships(
    source_id: str,
    body: RelationshipBatch,
    db: Session = Depends(get_session),
    authorization: str | None = Header(default=None),
):
    try:
        source = ingestion.authenticate_collector(db, source_id, _bearer(authorization))
        summary = ingestion.ingest(
            db,
            source=source,
            relationships=[r.model_dump() for r in body.relationships],
            observed_at=body.observed_at,
        )
        db.commit()
    except ingestion.IngestError as exc:
        db.rollback()
        raise HTTPException(exc.status, exc.detail)
    return summary


# ---- Audit / Evidence ----------------------------------------------------------
@app.get("/audit/records", tags=["audit"])
def list_audit(limit: int = 50, db: Session = Depends(get_session)):
    rows = db.scalars(select(AuditRecord).order_by(AuditRecord.seq.desc()).limit(limit)).all()
    return [
        {
            "seq": r.seq,
            "correlation_id": r.correlation_id,
            "ts": r.ts.isoformat(),
            "subject": r.subject,
            "event": r.event,
            "action": r.action,
            "target": r.target,
            "result": r.result,
            "policy_version": r.policy_version,
            "hash": r.hash,
        }
        for r in rows
    ]


@app.get("/audit/records/{correlation_id}", tags=["audit"])
def get_audit_chain(correlation_id: str, db: Session = Depends(get_session)):
    rows = db.scalars(
        select(AuditRecord).where(AuditRecord.correlation_id == correlation_id).order_by(AuditRecord.seq)
    ).all()
    if not rows:
        raise HTTPException(404, "no audit records for that correlation id")
    return [
        {c.name: getattr(r, c.name) for c in AuditRecord.__table__.columns}
        for r in rows
    ]


@app.get("/audit/verify", tags=["audit"])
def verify_audit(db: Session = Depends(get_session)):
    return audit.verify_chain(db)


# ---- Local AI Feedback Loop ------------------------------------------------------
@app.post("/feedback/run", tags=["feedback"])
def run_feedback(db: Session = Depends(get_session)):
    proposals = feedback.run_analyzers(db)
    db.commit()
    return [
        {"id": p.id, "kind": p.kind, "summary": p.summary, "status": p.status} for p in proposals
    ]


@app.get("/feedback/recommendations", tags=["feedback"])
def list_recommendations(db: Session = Depends(get_session)):
    rows = db.scalars(select(Recommendation).order_by(Recommendation.created_at)).all()
    return [
        {"id": r.id, "kind": r.kind, "summary": r.summary, "status": r.status,
         "decided_by": r.decided_by}
        for r in rows
    ]


class RecommendationDecision(BaseModel):
    approve: bool


@app.post("/feedback/recommendations/{rec_id}/decision", tags=["feedback"])
def decide_recommendation(
    rec_id: str,
    body: RecommendationDecision,
    db: Session = Depends(get_session),
    authorization: str | None = Header(default=None),
):
    _, approver = _verified_principal(db, authorization)
    try:
        rec = feedback.decide(db, rec_id, approver=approver.name, approve=body.approve)
        db.commit()
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return {"id": rec.id, "status": rec.status, "decided_by": rec.decided_by}
