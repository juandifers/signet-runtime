"""The agent's-eye view from inside the netns — run UNPRIVILEGED by NetnsController.exec_agent.

This is what a sandboxed agent can actually do. It imports NO signet code and makes no Signet
client call: egress needs ZERO agent adoption — the agent just opens normal sockets and (for
HTTPS) speaks the ordinary HTTP CONNECT a proxy client speaks. Everything here is stdlib.

It probes, from inside the agent netns, the six facts the keystone test asserts and prints them as
one JSON line on stdout:

  honest            : CONNECT <allowed host> via the proxy tunnels and round-trips         -> ok
  direct_evil       : a DIRECT socket to the evil upstream (battery #8's move)             -> BLOCKED
  direct_offsubnet  : a DIRECT socket to an off-subnet/raw IP                              -> BLOCKED
  dns               : direct name resolution inside the netns                              -> BLOCKED
  add_route         : `ip route add ...` (attempt to escape by reconfiguring the netns)    -> DENIED
  flush_nft         : `nft flush ruleset` (attempt to tear down the firewall)             -> DENIED

The last two are AGENT-UNPRIVILEGED-IN-NETNS: the agent has an empty capability bounding set, so
these fail with EPERM. "BLOCKED/DENIED" is the secure outcome.

Usage (argv): proxy_ip proxy_port allowed_host allowed_port evil_ip evil_port offsub_ip offsub_port
"""
from __future__ import annotations

import json
import socket
import subprocess
import sys

_FAST = 2.0  # seconds; a dropped SYN with nft `drop` (not reject) hangs until this fires


def _connect_via_proxy(pip: str, pport: int, host: str, port: int,
                       payload: bytes = b"ping") -> dict:
    """Speak HTTP CONNECT to the proxy, then round-trip bytes through the tunnel. This is an
    ordinary proxy-client exchange — no Signet code involved."""
    try:
        s = socket.create_connection((pip, pport), timeout=_FAST + 2)
    except OSError as e:
        return {"ok": False, "why": f"proxy-unreachable:{e.__class__.__name__}"}
    try:
        s.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
        reply = s.recv(256)
        if b"200" not in reply.split(b"\r\n", 1)[0]:
            return {"ok": False, "why": "refused", "reply": reply[:48].decode("latin-1", "replace")}
        s.sendall(payload)
        s.settimeout(_FAST + 2)
        echo = s.recv(256)
        return {"ok": True, "echo": echo.decode("latin-1", "replace")}
    except OSError as e:
        return {"ok": False, "why": f"tunnel-error:{e.__class__.__name__}"}
    finally:
        try:
            s.close()
        except OSError:
            pass


def _direct_blocked(ip: str, port: int) -> bool:
    """True iff a DIRECT connection to ip:port fails (no route / nft drop / refused). This is the
    inverse of egress battery #8: WITHOUT the netns this connection succeeds; WITH it, it must not."""
    try:
        s = socket.create_connection((ip, port), timeout=_FAST)
    except OSError:
        return True            # ENETUNREACH / EHOSTUNREACH / refused / timeout -> blocked (good)
    s.close()
    return False               # it connected -> the only-door leaks (bad)


def _dns_blocked(name: str) -> bool:
    """True iff direct name resolution inside the netns fails (no reachable resolver). The proxy,
    not the agent, is supposed to resolve names."""
    socket.setdefaulttimeout(_FAST)
    try:
        socket.getaddrinfo(name, 80, type=socket.SOCK_STREAM)
    except OSError:
        return True
    return False


def _cmd_denied(args: list) -> bool:
    """True iff running `args` is DENIED (non-zero exit, or the tool isn't even present). Used to
    prove the unprivileged agent cannot reconfigure its own netns."""
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=5)
        return r.returncode != 0
    except (OSError, subprocess.SubprocessError):
        return True


def main(argv: list) -> int:
    (pip, pport, ahost, aport, eip, eport, oip, oport) = argv[1:9]
    out = {
        "honest": _connect_via_proxy(pip, int(pport), ahost, int(aport)),
        "direct_evil_blocked": _direct_blocked(eip, int(eport)),
        "direct_offsubnet_blocked": _direct_blocked(oip, int(oport)),
        "dns_blocked": _dns_blocked(ahost),
        # AGENT-UNPRIVILEGED-IN-NETNS: both must be DENIED.
        "add_route_denied": _cmd_denied(["ip", "route", "add", "10.66.0.0/30", "via", pip]),
        "flush_nft_denied": _cmd_denied(["nft", "flush", "ruleset"]),
    }
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
