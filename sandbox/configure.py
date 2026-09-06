"""Write ignored local settings from Terraform outputs without printing secrets."""
import json
import secrets
import subprocess
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parent


def output(folder, name):
    result = subprocess.run(["terraform", f"-chdir={ROOT / folder}", "output", "-json", name],
                            capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(f"Terraform output unavailable for {folder}; apply it first")
    return json.loads(result.stdout)


def main():
    values = {**output("entra", "local_settings"), **output("aws", "local_settings")}
    values["ENTRA_COLLECTOR_CLIENT_SECRET"] = output("entra", "collector_client_secret")
    values["POSTGRES_PASSWORD"] = secrets.token_urlsafe(32)
    key = secrets.token_bytes(32)
    values["EDA_AUDIT_ANCHOR_KEY"] = key.hex()
    values["EDA_AUDIT_TRUSTED_KEYS"] = Ed25519PrivateKey.from_private_bytes(key).public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw).hex()
    # Single-quoted dotenv values preserve dollar signs without interpolation.
    if any(any(c in str(v) for c in "\r\n'\\") for v in values.values()):
        raise ValueError("Unsupported character in setting; configure securely by hand")
    with (ROOT / ".env").open("x", encoding="utf-8") as stream:
        stream.write("".join(f"{key}='{value}'\n" for key, value in values.items()))
    print("Created sandbox/.env. Keep it private; existing files are never overwritten.")


if __name__ == "__main__":
    main()
