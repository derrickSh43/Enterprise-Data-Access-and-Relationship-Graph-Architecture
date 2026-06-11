from eda import audit


def append_some(db, n=3):
    for i in range(n):
        audit.append(
            db,
            correlation_id=f"c{i}",
            subject="derrick",
            session_id="s1",
            event="request",
            action="inspect_instance",
            target="ec2-prod-1",
            result="allowed",
        )
    db.commit()


def test_chain_verifies_clean(db):
    append_some(db)
    assert audit.verify_chain(db) == {"ok": True, "records": 3, "first_broken_seq": None}


def test_chain_links_to_previous_record(db):
    append_some(db, 2)
    from sqlalchemy import select

    from eda.models import AuditRecord

    first, second = db.scalars(select(AuditRecord).order_by(AuditRecord.seq)).all()
    assert first.prev_hash == audit.GENESIS
    assert second.prev_hash == first.hash


def test_tampering_breaks_the_chain(db):
    append_some(db)
    from sqlalchemy import select

    from eda.models import AuditRecord

    victim = db.scalars(select(AuditRecord).order_by(AuditRecord.seq)).all()[1]
    victim.result = "denied"  # retroactive edit
    db.commit()
    report = audit.verify_chain(db)
    assert report["ok"] is False
    assert report["first_broken_seq"] == victim.seq
