"""The agent sandbox — the OS only-door that turns EGRESS-SOLE-PATH from declared to enforced.

The egress rail (signet/broker/proxy.py) is a *boundary* only if the agent has no path to the
network except the proxy. Until then it is ADVISORY: a direct connection bypasses it (egress
battery #8). This package supplies that missing OS interposition: a network namespace the agent
runs inside, whose only route out is the broker proxy.

The load-bearing security property is NOT the netns plumbing — it is that the agent runs
UNPRIVILEGED inside the netns (AGENT-UNPRIVILEGED-IN-NETNS). A privileged CONTROLLER (a separate
principal, the BROKER-SEPARATE-PRINCIPAL line extended) creates and configures the namespace; the
agent gets no CAP_NET_ADMIN, so it cannot add a route, flush nftables, or raise a new interface to
escape. See signet/sandbox/netns.py.

Linux-only. Everything here imports cleanly on any platform (the platform/privilege gate is at
runtime, in `preflight()`), so the deterministic suite skips — never breaks — off Linux.
"""
from .netns import NetnsConfig, NetnsController, NetnsUnavailable, preflight

__all__ = ["NetnsConfig", "NetnsController", "NetnsUnavailable", "preflight"]
