"""Reviewed-container entrypoint with closed action registry."""
import contextlib
import json
import os
import sys
from .actions import REGISTRY


def main():
    limit = 256 * 1024
    raw = sys.stdin.buffer.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("input limit exceeded")
    request = json.loads(raw)
    handlers = {action.handler_path: action for action in REGISTRY.values()}
    action = handlers[request["handler"]]
    inputs = action.input_model.model_validate(request["inputs"]).model_dump()
    with open(os.devnull, "w") as sink, contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
        outputs, calls = action.handler(request["credentials"], request["resource"], inputs)
    response = json.dumps({"ok": True, "outputs": outputs, "api_calls": calls}).encode()
    if len(response) > limit:
        raise ValueError("output limit exceeded")
    sys.stdout.buffer.write(response)


if __name__ == "__main__":
    main()
