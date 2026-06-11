"""End-to-end demo: the architecture doc's 'Cloud Investigation Request',
plus the secure enterprise front (bearer auth + collector ingestion).

Runs the full governed flow over the HTTP API (in-process), printing each
stage. Uses a throwaway SQLite database (demo.db). Identity here uses the
dev provider (EDA_AUTH_MODE=dev); production deployments set
EDA_AUTH_MODE=oidc and point at Okta/Entra, which disables self-issued
sessions entirely.

    python demo.py
"""

import json
import os
import pathlib

DB_FILE = pathlib.Path(__file__).parent / "demo.db"
if DB_FILE.exists():
    DB_FILE.unlink()
os.environ["EDA_DATABASE_URL"] = f"sqlite:///{DB_FILE}"
os.environ["EDA_AUTH_MODE"] = "dev"

from fastapi.testclient import TestClient  # noqa: E402

from eda.api import app  # noqa: E402


def banner(title: str) -> None:
    print(f"\n{'=' * 78}\n  {title}\n{'=' * 78}")


def show(label: str, data) -> None:
    print(f"\n--- {label} ---")
    print(json.dumps(data, indent=2, default=str)[:2400])


def auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def main() -> None:
    with TestClient(app) as client:
        def session_for(subject, mfa=True, risk=0):
            return client.post(
                "/identity/sessions",
                json={"subject": subject, "mfa": mfa, "risk_score": risk},
            ).json()["session_token"]

        # ------------------------------------------------------------------
        banner("1. SSO: derrick authenticates (MFA, low session risk)")
        derrick = session_for("derrick", risk=10)
        print("bearer token issued (dev provider; OIDC mode validates Okta/Entra tokens)")

        # ------------------------------------------------------------------
        banner("2. Governed request: inspect ec2-prod-1 for incident INC-42")
        trace = client.post(
            "/requests",
            json={
                "action": "inspect_instance",
                "resource": "ec2-prod-1",
                "justification": {"case_id": "INC-42"},
            },
            headers=auth(derrick),
        ).json()
        print(f"\nOUTCOME: {trace['outcome'].upper()}")
        show("identity (validated, mapped to graph principal)", trace["stages"]["identity"])
        show("access path (proof)", trace["stages"]["access_path"])
        show("policy decision", trace["stages"]["policy"])
        show("brokered grant (credentials redacted in every external view)",
             trace["stages"]["grant"])
        show("scoped object-graph context (sensitive neighbors redacted)",
             trace["stages"]["context"])
        show("action result (read-only inspection)", trace["stages"]["action_result"])

        # ------------------------------------------------------------------
        banner("3. The same request is refused without authority, MFA, or a case ID")
        for label, token, body in [
            ("eve (contractor, no access path)", session_for("eve"),
             {"action": "inspect_instance", "resource": "ec2-prod-1",
              "justification": {"case_id": "INC-42"}}),
            ("derrick without MFA", session_for("derrick", mfa=False),
             {"action": "inspect_instance", "resource": "ec2-prod-1",
              "justification": {"case_id": "INC-42"}}),
            ("derrick without a case ID", derrick,
             {"action": "inspect_instance", "resource": "ec2-prod-1"}),
        ]:
            result = client.post("/requests", json=body, headers=auth(token)).json()
            print(f"  {label:42s} -> {result['outcome'].upper():18s} ({result.get('error', '')})")

        # ------------------------------------------------------------------
        banner("4. High-risk action: rotate db-creds-prod (approval + controlled runner)")
        first = client.post(
            "/requests",
            json={"action": "rotate_secret", "resource": "db-creds-prod",
                  "justification": {"case_id": "INC-42"}},
            headers=auth(derrick),
        ).json()
        print(f"first attempt -> {first['outcome'].upper()}: {first['stages']['policy']['reason']}")
        approval_id = first["stages"]["approval"]["approval_id"]

        lead = session_for("security-lead")
        client.post(f"/approvals/{approval_id}/decision", json={"approve": True},
                    headers=auth(lead))
        print(f"approval {approval_id} granted by security-lead (self-approval is rejected)")

        second = client.post(
            "/requests",
            json={"action": "rotate_secret", "resource": "db-creds-prod",
                  "justification": {"case_id": "INC-42"}, "approval_id": approval_id},
            headers=auth(derrick),
        ).json()
        print(f"resubmit -> {second['outcome'].upper()}, "
              f"execution_mode={second['stages']['action_result']['execution_mode']}")
        show("rotation result", second["stages"]["action_result"]["outputs"])

        # ------------------------------------------------------------------
        banner("5. Collector ingestion: a registered Okta feed populates the graph")
        from eda import ingestion
        from eda.db import SessionLocal

        with SessionLocal() as db:
            _, collector_secret = ingestion.register_source(
                db, source_id="okta-directory-prod", tenant_id="acme",
                provider="okta", allowed_namespace="okta:",
            )
            db.commit()
        print("source okta-directory-prod registered (namespace 'okta:', tenant 'acme')")

        batch = {"relationships": [
            {"subject": {"kind": "user", "id": "okta:00u123"}, "relation": "member_of",
             "target": {"kind": "group", "id": "okta:g-sec"}, "attributes": {}},
            {"subject": {"kind": "group", "id": "okta:g-sec"}, "relation": "assigned",
             "target": {"kind": "permission_set", "id": "okta:ps-readonly"}, "attributes": {}},
        ]}
        accepted = client.post(
            "/relationship-sources/okta-directory-prod/relationships",
            json=batch, headers=auth(collector_secret),
        ).json()
        show("ingest accepted (source + observed_at recorded on every node/edge)", accepted)

        blocked = client.post(
            "/relationship-sources/okta-directory-prod/relationships",
            json={"relationships": [
                {"subject": {"kind": "user", "id": "entra:alien"}, "relation": "member_of",
                 "target": {"kind": "group", "id": "okta:g-sec"}, "attributes": {}}]},
            headers=auth(collector_secret),
        )
        print(f"\ncross-namespace write (entra: id via okta collector) -> "
              f"HTTP {blocked.status_code}: {blocked.json()['detail'][0]}")
        forged = client.post(
            "/relationship-sources/okta-directory-prod/relationships",
            json=batch, headers=auth("wrong-secret"),
        )
        print(f"forged collector credential -> HTTP {forged.status_code}")

        # ------------------------------------------------------------------
        banner("6. Audit / Evidence Layer: hash-chained, fully reconstructable")
        print(json.dumps(client.get("/audit/verify").json(), indent=2))
        records = client.get("/audit/records").json()
        print(f"\n{len(records)} audit records; latest first:")
        for r in records[:9]:
            print(f"  seq={r['seq']:<3} {r['result']:<18} {r['subject']:<26} "
                  f"{r['action'] or '-':<22} hash={r['hash'][:12]}...")

        # ------------------------------------------------------------------
        banner("7. Local AI Feedback Loop: observes, proposes - humans decide")
        proposals = client.post("/feedback/run").json()
        if not proposals:
            print("no patterns crossed thresholds yet")
        for p in proposals:
            print(f"\n[{p['kind']}] ({p['status']})\n  {p['summary']}")
            decision = client.post(
                f"/feedback/recommendations/{p['id']}/decision",
                json={"approve": True}, headers=auth(lead),
            ).json()
            print(f"  -> human decision: {decision['status']} by {decision['decided_by']}")

        print(json.dumps(client.get("/audit/verify").json(), indent=2))
        print("\nDone. Inspect the API interactively: uvicorn eda.api:app --reload "
              "then open http://127.0.0.1:8000/docs")


if __name__ == "__main__":
    main()
