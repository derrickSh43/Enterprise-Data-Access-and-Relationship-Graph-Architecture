"""Controlled runner: a real execution boundary, not a label.

High-risk and write actions run in a separate OS process: credentials are
passed only into that process (never to the caller), a wall-clock timeout
terminates runaway jobs, output size is capped, and only the action's
declared output keys are returned. Each job is its own process - no shared
interpreter state with the control plane or other jobs.

Production hardening seam: swap process spawn for a container/jail with CPU
and memory limits (job objects on Windows, cgroups on Linux) and a separate
service account; the contract here stays the same.
"""

import importlib
import json
import multiprocessing
import time

from .config import settings


class RunnerError(Exception):
    pass


class RunnerTimeout(RunnerError):
    pass


def _child(conn, handler_path: str, credentials: dict, resource: str, inputs: dict) -> None:
    try:
        module_name, func_name = handler_path.rsplit(".", 1)
        handler = getattr(importlib.import_module(module_name), func_name)
        outputs, api_calls = handler(credentials, resource, inputs)
        conn.send({"ok": True, "outputs": outputs, "api_calls": api_calls})
    except Exception as exc:  # report, never crash silently
        conn.send({"ok": False, "error": f"{type(exc).__name__}: {exc}"})
    finally:
        conn.close()


def run_controlled(
    handler_path: str,
    *,
    credentials: dict,
    resource: str,
    inputs: dict,
    allowed_outputs: tuple,
    timeout_seconds: int | None = None,
    max_output_bytes: int | None = None,
) -> tuple[dict, list]:
    """Execute a handler in an isolated process; return (outputs, api_calls)
    with outputs filtered to the action's approved keys."""
    timeout = timeout_seconds or settings.runner_timeout_seconds
    ctx = multiprocessing.get_context("spawn")
    parent_conn, child_conn = ctx.Pipe(duplex=False)
    proc = ctx.Process(
        target=_child,
        args=(child_conn, handler_path, credentials, resource, inputs),
        daemon=True,
    )
    proc.start()
    child_conn.close()
    try:
        if not parent_conn.poll(timeout):
            raise RunnerTimeout(f"controlled runner exceeded {timeout}s; job terminated")
        result = parent_conn.recv()
    finally:
        if proc.is_alive():
            proc.terminate()
        proc.join(5)
        parent_conn.close()

    if not result.get("ok"):
        raise RunnerError(result.get("error", "controlled runner failed"))

    limit = max_output_bytes or settings.runner_max_output_bytes
    payload = json.dumps(result, default=str)
    if len(payload.encode()) > limit:
        raise RunnerError(f"runner output exceeds {limit} byte limit")

    outputs = {k: v for k, v in result["outputs"].items() if k in allowed_outputs}
    return outputs, result["api_calls"]


def _selftest_sleep(credentials: dict, resource: str, inputs: dict):
    """Importable slow handler used by the runner's own timeout tests."""
    time.sleep(inputs.get("seconds", 60))
    return {"slept": True}, []


def _selftest_leaky(credentials: dict, resource: str, inputs: dict):
    """Importable handler that tries to exfiltrate credentials and extra keys
    through its outputs; the runner's output filter must strip them."""
    return {"approved_key": "fine", "stolen_credentials": credentials}, []
