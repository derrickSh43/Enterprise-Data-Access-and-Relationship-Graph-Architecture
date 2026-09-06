"""Public evidence by allowlisting fields, never by copying/redacting raw logs."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
from datetime import datetime, timezone
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parent.parent


def command(args, timeout=60):
    try:
        p = subprocess.run(args, cwd=ROOT, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=timeout)
        return p.returncode, p.stdout
    except (OSError, subprocess.TimeoutExpired):
        return None, ""


def collect():
    report = {"format_version": 1, "collected_at_utc": datetime.now(timezone.utc).isoformat(),
              "scope": "Local sandbox evidence; not production certification"}
    code, output = command(["git", "rev-parse", "HEAD"])
    commit = output.strip()
    report["base_commit"] = commit if code == 0 and re.fullmatch(r"[0-9a-f]{40,64}", commit) else "unavailable"
    code, output = command(["git", "status", "--porcelain"])
    report["working_tree_has_changes"] = bool(output.strip()) if code == 0 else "unavailable"
    report["configuration_sha256"] = {}
    for name in ["sandbox/entra/main.tf", "sandbox/aws/main.tf", "sandbox/compose.yaml", "deploy/Dockerfile"]:
        path = ROOT / name
        if path.is_file():
            report["configuration_sha256"][name] = hashlib.sha256(path.read_bytes()).hexdigest()

    report["terraform"] = {}
    for folder in ["sandbox/entra", "sandbox/aws"]:
        code, output = command(["terraform", f"-chdir={folder}", "validate", "-json"])
        try:
            result = json.loads(output)
        except (ValueError, TypeError):
            result = {}
        valid = result.get("valid")
        report["terraform"][folder] = {
            "validation": "pass" if code == 0 and valid is True else "failed_or_unavailable"}
        # Mock-provider tests only. No apply, real plan, state export or account calls.
        code, output = command(["terraform", f"-chdir={folder}", "test", "-json"], timeout=60)
        summary = None
        for line in output.splitlines():
            try:
                event = json.loads(line)
                if isinstance(event.get("test_summary"), dict):
                    summary = event["test_summary"]
            except (ValueError, AttributeError):
                continue
        entry = report["terraform"][folder]
        entry["mock_tests"] = "pass" if code == 0 else "failed_or_unavailable"
        if summary:
            for key in ["passed", "failed", "skipped"]:
                if type(summary.get(key)) is int:
                    entry[key] = summary[key]

    code, output = command(["docker", "ps", "-a", "--filter", "label=com.docker.compose.project=eda-sandbox",
                            "--format", '{{.ID}}'], timeout=20)
    report["docker"] = {"inspection": "available" if code == 0 else "unavailable", "services": []}
    for container in output.splitlines() if code == 0 else []:
        if not re.fullmatch(r"[0-9a-f]{12,64}", container.strip()):
            continue
        template = '{{index .Config.Labels "com.docker.compose.service"}}|{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}|{{.State.ExitCode}}'
        status, raw = command(["docker", "inspect", "--format", template, container.strip()], timeout=20)
        parts = raw.strip().split("|")
        if status == 0 and len(parts) == 4:
            service, state, health, exit_code = parts
            if (service in {"api", "database", "migrate", "sync"}
                    and state in {"created", "restarting", "running", "removing", "paused", "exited", "dead"}
                    and health in {"none", "starting", "healthy", "unhealthy"}
                    and exit_code.isdigit() and 0 <= int(exit_code) <= 255):
                report["docker"]["services"].append({"service": service, "state": state, "health": health, "exit_code": int(exit_code) if state == "exited" else None})
    report["docker"]["services"].sort(key=lambda item: (item["service"], item["state"]))
    try:
        # Bypass local proxy configuration; do not follow redirects off localhost.
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        with opener.open("http://127.0.0.1:8000/readyz", timeout=5) as response:
            body = response.read(1024)
            report["api_readiness"] = "pass" if response.status == 200 and json.loads(body) == {"status": "ready"} else "unexpected_response"
    except Exception:
        report["api_readiness"] = "unavailable_or_not_ready"
    report["not_verified_by_this_collection"] = [
        "Live Entra directory ingestion", "Live AWS inventory ingestion", "Interactive identity mapping",
        "Agent and human delegation enforcement", "Native effective data permissions", "Production readiness"]
    return report


def main():
    report = collect()
    files = {}
    files["evidence.json"] = json.dumps(report, indent=2) + "\n"
    rows = []
    for folder, values in report["terraform"].items():
        rows.append(f"| {folder} | {values['validation']} | {values['mock_tests']} |")
    services = report["docker"]["services"]
    service_rows = [f"| {s['service']} | {s['state']} | {s['health']} | {s['exit_code'] if s['exit_code'] is not None else '-'} |" for s in services]
    files["README.md"] = "\n".join([
        "# EDA sandbox: public evidence", "", f"Collected UTC: {report['collected_at_utc']}", "",
        "## Observed checks", "", "| Terraform module | Validation | Mock tests |", "| --- | --- | --- |", *rows,
        "", f"Docker inspection: {report['docker']['inspection']}", "",
        "| Local service | Container state | Health | Exit code |", "| --- | --- | --- | --- |", *service_rows,
        "", f"API readiness: {report['api_readiness']}", "",
        "Container state and API readiness do not prove live cloud access. No observed services means no runtime evidence was collected.", "",
        "## Architecture", "", "```mermaid", "flowchart LR",
        '  Entra["Entra test directory"] -->|"Directory metadata"| EDA["Local EDA container"]',
        '  EDA <--> DB["Local PostgreSQL container"]',
        '  AWS["AWS APIs: restricted metadata reads"] --> EDA',
        '  AWS --- EC2["Small EC2 inspection target"]',
        '  AWS --- S3["Private S3 test bucket"]', "```", "",
        "Architecture depicts intended connections, not proof that every connection succeeded.", "",
        "## Limits", "", *[f"- Not verified: {item}." for item in report["not_verified_by_this_collection"]], "",
        "The source tree has local changes; the recorded base commit alone does not reproduce this build. Configuration hashes identify the checked files without exposing their contents.", "",
        "## Public sharing scope", "",
        "This bundle contains only predefined service labels, status enums, timestamps, configuration hashes and validation outcomes. No raw logs or provider error text are included.",
        "Credentials, account/tenant/user IDs, ARNs, host paths, container IDs, environment values, Terraform state/plans, private inventory and customer data are excluded.",
        "Share this bundle only, not the repository, terminal history, .env, Terraform files containing real settings, or Docker inspection/log exports.", "",
        "Collection does not publish anything. This is a prototype evidence snapshot, not a security certification.", ""])
    combined = "\n".join(files.values())
    forbidden = [r"arn:aws", r"\b[0-9]{12}\b", r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
                 r"https://login\.microsoftonline\.com/", r"C:\\\\Users", r"-----BEGIN .*PRIVATE KEY-----"]
    if any(re.search(pattern, combined) for pattern in forbidden):
        raise RuntimeError("Public export rejected by identifier/secret pattern check")
    files["SHA256SUMS.txt"] = "".join(f"{hashlib.sha256(content.encode()).hexdigest()}  {name}\n" for name, content in sorted(files.items()))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    destination = ROOT / "public-evidence" / stamp
    destination.mkdir(parents=True, exist_ok=False)
    for name, content in files.items():
        (destination / name).write_bytes(content.encode("utf-8"))
    archive = destination.parent / f"eda-public-evidence-{stamp}.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as output:
        for name in files:
            output.writestr(name, files[name].encode())
    print(f"Public bundle: public-evidence/{archive.name}")
    print(f"Report: public-evidence/{stamp}/README.md")
    print("No publication performed. Only allowlisted evidence was exported.")


if __name__ == "__main__":
    main()
