import json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from eda import audit
from test_audit_hardening import anchor_file, append


def test_missing_or_empty_anchor_storage_fails(db, anchor_file):
    assert audit.verify_anchors(db)["ok"] is False
    anchor_file.write_text("")
    assert audit.verify_anchors(db)["ok"] is False


def test_replacement_key_even_with_valid_signature_rejected(db, anchor_file):
    append(db)
    db.commit()
    anchor = audit.anchor_chain(db)
    attacker = Ed25519PrivateKey.generate()
    payload = {k: anchor[k] for k in ("seq", "hash", "anchored_at")}
    anchor["public_key"] = attacker.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    anchor["signature"] = attacker.sign(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hex()
    anchor_file.write_text(json.dumps(anchor))
    report = audit.verify_anchors(db)
    assert not report["ok"]
    assert report["failures"][0]["reason"] == "untrusted signing key"


def test_tenant_change_breaks_new_chain(db):
    record = append(db, tenant_id="one")
    db.commit()
    assert audit.verify_chain(db)["ok"]
    record.tenant_id = "two"
    db.commit()
    assert not audit.verify_chain(db)["ok"]


def test_truncation_below_independent_checkpoint_fails(db, anchor_file, monkeypatch):
    from dataclasses import replace
    append(db)
    db.commit()
    audit.anchor_chain(db)
    monkeypatch.setattr(audit, "settings", replace(audit.settings, audit_anchor_min_seq=2))
    assert not audit.verify_anchors(db)["ok"]


def test_malformed_anchor_is_failure_not_server_crash(db, anchor_file):
    anchor_file.write_text("not json")
    assert not audit.verify_anchors(db)["ok"]
