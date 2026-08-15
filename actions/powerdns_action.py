#!/usr/bin/env python3
"""Shared stdin/JSON entry point for PowerDNS actions."""

from __future__ import annotations

import json
import os
import sys

_PACK_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PACK_ROOT not in sys.path:
    sys.path.insert(0, _PACK_ROOT)

from lib.powerdns_client import PowerDNSPackError, execute_action


def main() -> int:
    try:
        raw = sys.stdin.read()
        params = json.loads(raw) if raw.strip() else {}
        if not isinstance(params, dict):
            raise PowerDNSPackError("action parameters must be a JSON object")
        operation = os.environ.get("ATTUNE_ACTION", "").rsplit(".", 1)[-1]
        result = execute_action(operation, params)
        json.dump({"operation": operation, "result": result}, sys.stdout, separators=(",", ":"))
        sys.stdout.write("\n")
        return 0
    except PowerDNSPackError as exc:
        print(f"powerdns action failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    except json.JSONDecodeError:
        print("powerdns action failed: invalid stdin JSON", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001
        # Unexpected remote/library exceptions can include request headers or bodies.
        print(f"powerdns action failed: {type(exc).__name__}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
