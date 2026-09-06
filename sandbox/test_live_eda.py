"""Host-side live test runner. Credentials stay in memory; raw logs stay private."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parent.parent
STAMP = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
PRIVATE = ROOT / "private-test-results" / STAMP
PUBLIC = ROOT / "public-test-results" / STAMP
RESULTS = []
SECRETS = []


def redact(raw):
    for value in sorted(SECRETS, key=len, reverse=True):
        if value:
            raw = raw.replace(value, "[CREDENTIAL REDACTED]")
    raw = re.sub(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", "[ACCESS KEY REDACTED]", raw)
    return re.sub(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", "[TOKEN REDACTED]", raw)


def run(label, args, env=None, timeout=180):
    try:
        p = subprocess.run(args, cwd=ROOT, env=env, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=timeout)
        output, error, code = p.stdout, p.stderr, p.returncode
    except subprocess.TimeoutExpired:
        output, error, code = "", "Command timed out; inspect the owned test container before retrying.", 124
    except OSError as exc:
        output, error, code = "", type(exc).__name__, 127
    (PRIVATE / f"{label}.txt").write_text(redact(f"Exit code: {code}\nSTDOUT\n{output}\nSTDERR\n{error}"), encoding="utf-8")
    return code, output


def settings():
    values = {}
    for line in (ROOT / "sandbox/.env").read_text(encoding="utf-8-sig").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip("'\"")
    for key, value in values.items():
        if any(part in key for part in ["SECRET", "PASSWORD", "TOKEN", "ANCHOR_KEY"]):
            SECRETS.append(value)
    return values


def result(name, status):
    RESULTS.append({"check": name, "status": status})
    print(name + ": " + status, flush=True)


def http_checks():
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    cases = [
        ("api_readiness", "/readyz", None, {}, 200),
        ("anonymous_audit_denied", "/audit/records", None, {}, 401),
        ("invalid_token_denied", "/audit/records", None, {"Authorization": "Bearer invalid-test-token"}, 401),
        ("demo_identity_creation_disabled", "/identity/sessions", {"subject": "security-lead"}, {}, 403)]
    for label, path, body, headers, expected in cases:
        request = urllib.request.Request("http://127.0.0.1:8000" + path,
            data=json.dumps(body).encode() if body else None, headers={**headers, "Content-Type": "application/json"})
        try:
            response = opener.open(request, timeout=10)
        except urllib.error.HTTPError as exc:
            response = exc
        except Exception as exc:
            (PRIVATE / f"{label}.txt").write_text(type(exc).__name__)
            result(label, "BLOCKED")
            continue
        with response:
            code, raw = response.code, response.read(65536).decode(errors="replace")
        (PRIVATE / f"{label}.txt").write_text(redact(f"HTTP {code}\n{raw}"), encoding="utf-8")
        passed = code == expected
        if label == "api_readiness":
            try:
                passed = passed and json.loads(raw) == {"status": "ready"}
            except ValueError:
                passed = False
        result(label, "PASS" if passed else "FAIL")


def probe(label, environment):
    args = ["docker", "compose", "--env-file", "sandbox/.env", "-f", "sandbox/compose.yaml",
            "run", "--rm", "-T", "--no-deps",
            "-v", str(ROOT / "sandbox/live_probe.py") + ":/sandbox/live_probe.py:ro"]
    if label in {"aws", "aws-permissions"}:
        args += ["-e", "AWS_TEST_INSTANCE_ID", "-e", "AWS_TEST_BUCKET"]
    args += ["sync", "python", "/sandbox/live_probe.py", label]
    code, output = run(label + "_live_probe", args, env=environment)
    allowed = {"aws_target_instance_read_allowed", "aws_target_security_group_read_allowed", "aws_file_content_read_denied", "aws_scoped_role_and_account_match", "aws_expected_sandbox_resources_present",
               "entra_users_and_groups_observed"}
    for source in ["entra", "aws"]:
        allowed.update(source + "_" + suffix for suffix in ["import_matches_observed_records",
            "interrupted_import_preserves_inventory", "repeat_import_matches_latest_observation", "audit_chain_valid"])
    found = False
    for line in output.splitlines():
        if line.startswith("EDA_RESULT "):
            try:
                item = json.loads(line[len("EDA_RESULT "):])
                if item.get("check") in allowed and item.get("status") in {"PASS", "FAIL"}:
                    result(item["check"], item["status"])
                    found = True
            except ValueError:
                pass
    if code != 0 or not found:
        result(label + "_probe_completed", "FAIL")


def main():
    PRIVATE.mkdir(parents=True, exist_ok=False)
    PUBLIC.mkdir(parents=True, exist_ok=False)
    values = settings()
    http_checks()
    probe("entra", dict(os.environ))
    # Acquire only the declared read-only collector role, with credentials captured
    # in memory. Never save the AssumeRole success response in raw logs.
    args = ["aws", "sts", "assume-role", "--role-arn", values["AWS_COLLECTOR_ROLE_ARN"],
            "--role-session-name", "eda-live-validation", "--duration-seconds", "900", "--output", "json"]
    p = subprocess.run(args, capture_output=True, text=True, timeout=45)
    if p.returncode:
        (PRIVATE / "aws_role_acquisition.txt").write_text(redact(p.stderr), encoding="utf-8")
        result("aws_role_acquisition", "BLOCKED")
    else:
        credentials = json.loads(p.stdout)["Credentials"]
        SECRETS.extend([credentials["AccessKeyId"], credentials["SecretAccessKey"], credentials["SessionToken"]])
        environment = {**os.environ, "AWS_ACCESS_KEY_ID": credentials["AccessKeyId"],
            "AWS_SECRET_ACCESS_KEY": credentials["SecretAccessKey"], "AWS_SESSION_TOKEN": credentials["SessionToken"],
            "AWS_TEST_INSTANCE_ID": values["AWS_TEST_INSTANCE_ID"], "AWS_TEST_BUCKET": values["AWS_TEST_BUCKET"]}
        result("aws_role_acquisition", "PASS")
        probe("aws", environment)
    for check in ["interactive_human_sign_in", "provider_membership_revocation", "agent_user_delegation",
                  "native_effective_data_permissions", "container_restart_recovery"]:
        result(check, "NOT TESTED")
    (PUBLIC / "results.json").write_text(json.dumps({"collected_at_utc": STAMP, "results": RESULTS}, indent=2), encoding="utf-8")
    rows = ["# EDA live sandbox test results", "", f"Collected UTC: {STAMP}", "",
            "| Check | Result |", "| --- | --- |"]
    rows.extend(f"| {r['check'].replace('_', ' ')} | {r['status']} |" for r in RESULTS)
    rows += ["", "Import checks compare stored facts with the records observed by each connector. This tests ingestion fidelity, not complete provider permission semantics.",
             "", "Interrupted-import checks inject a local collection failure and verify transaction rollback against the live PostgreSQL inventory. They do not simulate a provider-side revocation or a machine crash.",
             "", "Raw diagnostics are stored separately and are PRIVATE. This report includes only predefined check names and outcomes; it contains no identities, cloud IDs, secrets or logs."]
    (PUBLIC / "README.md").write_text("\n".join(rows) + "\n", encoding="utf-8")
    print("Private diagnostics: private-test-results/" + STAMP, flush=True)
    print("Shareable results: public-test-results/" + STAMP, flush=True)


if __name__ == "__main__":
    main()
