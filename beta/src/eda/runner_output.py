"""Defense in depth for declared action outputs; not a general exfiltration proof."""
import json


def reject_credentials(payload, credentials):
    from .runner import RunnerError
    encoded = json.dumps(payload, default=str)
    for key in ("AccessKeyId", "SecretAccessKey", "SessionToken"):
        value = credentials.get(key)
        if isinstance(value, str) and len(value) >= 4 and value in encoded:
            raise RunnerError("credential material in runner response")
