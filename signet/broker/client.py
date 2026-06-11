"""The agent-side broker client: request a capability over the Unix socket.

The agent holds NO elevated credential. Its only way to touch the database is to ask the broker
for a short-lived, effect-bound JWT through this client. The client carries no secret — peer
authentication is by the OS (SO_PEERCRED), established by the kernel when the socket connects.
"""
from __future__ import annotations

import socket

from .protocol import CapabilityRequest, CapabilityResponse


class BrokerClient:
    def __init__(self, socket_path: str):
        self._path = socket_path

    def request_capability(self, req: CapabilityRequest,
                           timeout: float = 5.0) -> CapabilityResponse:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect(self._path)
            s.sendall((req.to_json() + "\n").encode())
            data = b""
            while not data.endswith(b"\n"):
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
            return CapabilityResponse.from_json(data.decode().strip())
        finally:
            s.close()

    def request_db(self, *, database: str, schema: str, table: str, op: str,
                   task_id: str, agent_id: str = "agent", predicate: str = None,
                   request_nonce: str = "", timeout: float = 5.0) -> CapabilityResponse:
        params = {"database": database, "schema": schema, "table": table, "op": op}
        if predicate is not None:
            params["predicate"] = predicate
        return self.request_capability(CapabilityRequest(
            effect_kind="db.query", effect_params=params, task_id=task_id,
            agent_id=agent_id, request_nonce=request_nonce), timeout=timeout)
