"""Opt-in isolated offline runner. Native network actions require an egress design.

Only immutable reviewed images are accepted. No host mounts or Docker socket are
provided. Credentials travel through stdin, never command arguments or env vars.
"""
import json
import re
import subprocess
import threading
import uuid
from .config import settings


def command(image, name):
    if not re.fullmatch(r"[A-Za-z0-9._/:_-]+@sha256:[0-9a-f]{64}", image):
        raise ValueError("runner image must be pinned by sha256 digest")
    return ["docker", "run", "--rm", "--name", name, "--network", "none", "--read-only",
            "--user", "65532:65532", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--memory", "256m", "--cpus", "1", "--pids-limit", "64", "--log-driver", "none",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m", "-i", image, "python", "-m", "eda.runner_worker"]


def run_container(handler_path, *, credentials, resource, inputs, allowed_outputs,
                  timeout_seconds=None, max_output_bytes=None):
    from .runner import RunnerError, RunnerTimeout
    from .runner_output import reject_credentials
    name = "eda-job-" + uuid.uuid4().hex
    limit = max_output_bytes or settings.runner_max_output_bytes
    timeout = timeout_seconds or settings.runner_timeout_seconds
    proc = subprocess.Popen(command(settings.runner_image, name), stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    chunks = {"stdout": bytearray(), "stderr": bytearray()}
    exceeded = threading.Event()
    def read(stream, label):
        while True:
            data = stream.read(4096)
            if not data:
                return
            if len(chunks[label]) + len(data) > limit:
                exceeded.set()
                proc.kill()
                return
            chunks[label].extend(data)
    readers = [threading.Thread(target=read, args=(proc.stdout, "stdout"), daemon=True),
               threading.Thread(target=read, args=(proc.stderr, "stderr"), daemon=True)]
    for thread in readers:
        thread.start()
    try:
        request = json.dumps({"handler": handler_path, "credentials": credentials,
                              "resource": resource, "inputs": inputs}).encode()
        if len(request) > limit:
            raise RunnerError("runner request exceeds byte limit")
        def write_input():
            try:
                proc.stdin.write(request)
                proc.stdin.close()
            except (BrokenPipeError, OSError):
                pass
        threading.Thread(target=write_input, daemon=True).start()
        try:
            code = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            raise RunnerTimeout("container runner timed out; outcome requires reconciliation")
        for thread in readers:
            thread.join(2)
        if exceeded.is_set() or any(thread.is_alive() for thread in readers):
            raise RunnerError("container output limit exceeded")
        if code != 0:
            raise RunnerError("container runner failed")
        try:
            result = json.loads(chunks["stdout"])
            if not result.get("ok"):
                raise RunnerError("container action failed")
            outputs = {k: v for k, v in result["outputs"].items() if k in allowed_outputs}
            calls = result["api_calls"]
            if not isinstance(calls, list):
                raise ValueError("invalid call evidence")
        except (ValueError, KeyError, TypeError) as exc:
            raise RunnerError("invalid container response") from exc
        reject_credentials({"outputs": outputs, "api_calls": calls}, credentials)
        return outputs, calls
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=5)
        # Killing the Docker CLI alone does not guarantee that the job stopped.
        subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=15, check=False)
