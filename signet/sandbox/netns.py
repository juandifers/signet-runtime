"""The EGRESS-SOLE-PATH only-door: a network namespace whose only route out is the broker proxy.

This is the OS interposition the egress note (DESIGN.md P9) declared and the egress rail deferred.
The proxy decides WHERE the agent may connect; the netns makes the proxy the agent's ONLY path to
the network, so that decision is enforced rather than advisory.

Topology (rootful v0, Fork A default):

    host netns                         agent netns ("signet-agent")
    ┌───────────────────────┐         ┌──────────────────────────┐
    │ broker proxy           │         │  agent (UNPRIVILEGED)     │
    │   binds 10.77.0.1:PORT │◀━veth━━▶│  default route via        │
    │   real egress upstream │ 10.77.  │    10.77.0.1              │
    │                        │ 0.1/0.2 │  nft: drop OUTPUT except  │
    │                        │         │    10.77.0.1 tcp PORT     │
    └───────────────────────┘         │  no resolver reachable    │
                                       └──────────────────────────┘

Defense in depth (Fork B default — BOTH):
  * NO NAT / NO ip_forward from the agent netns to real interfaces — packets to the internet die
    at the host even though the agent has a default route (the route points only at the proxy peer).
  * nftables in the agent netns default-drops OUTPUT, allowing ONLY 10.77.0.1:PORT — so even a raw
    socket to an arbitrary address is dropped, not merely unrouted.

No DNS (Fork D default): the agent netns has no reachable resolver (53 is dropped, and the host's
resolv.conf is not inherited into the netns), so ALL name resolution must go through the proxy,
which already does trusted resolution. This closes agent-side DNS evasion.

THE SUBTLETY THAT VOIDS EVERYTHING (CLAUDE.md AGENT-UNPRIVILEGED-IN-NETNS): a netns isolates the
agent's network only if the agent cannot reconfigure it. So the CONTROLLER (this class, privileged,
a separate principal) creates and configures the namespace, and then execs the agent with
`setpriv --reuid/--regid --clear-groups --bounding-set -all --no-new-privs`: the agent's
capability bounding set is empty, so it can never acquire CAP_NET_ADMIN — `ip route add`,
`nft flush`, `ip link set up` all fail with EPERM from inside. The netns plumbing is the easy part;
this privilege drop is the actual security boundary.

HONEST SCOPE (P8): this makes the EGRESS rail a boundary. It does NOT sandbox the agent in any
other dimension — filesystem, IPC, PID/mount namespaces, subprocesses — those need their own rails.
"We sandboxed the network" is not "we sandboxed the agent." Out-of-perimeter egress items are
unchanged: exfil-via-allowlisted-host (the binding is WHERE, not WHAT) and the link-preview
third-party-fetch variant remain out of scope; DNS exfil is *reduced* (no agent resolver) but
label-tunneling through the proxy's resolution of allowlisted-ish names is still a theoretical
channel.

Linux-only; rootful (Fork A). Rootless (userns + slirp4netns) is a declared follow-on, OUT OF SCOPE
here. The class imports on any platform; `preflight()` is the runtime gate.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import List, Optional, Sequence


class NetnsUnavailable(RuntimeError):
    """Raised when an operation needs Linux + CAP_NET_ADMIN + the ip/nft/setpriv tools and the
    current environment cannot provide them. Callers (tests, the launcher) check `preflight()`
    first and skip; this is the fail-closed backstop if they don't."""


# The required privileged tooling. nftables (not iptables) per Fork B.
_REQUIRED_TOOLS = ("ip", "nft", "setpriv")


def preflight() -> Optional[str]:
    """Return None if a netns sandbox can be created here, else a human-readable reason it cannot.

    The single gate used by both the launcher and the privilege-gated test. Off Linux, without
    root, or with the tooling absent, this returns a reason and nothing is attempted — so the
    deterministic suite SKIPS cleanly rather than erroring."""
    if sys.platform != "linux":
        return f"requires Linux network namespaces (this platform is {sys.platform!r})"
    if os.geteuid() != 0:
        return "requires root / CAP_NET_ADMIN to create and configure a network namespace"
    for tool in _REQUIRED_TOOLS:
        if shutil.which(tool) is None:
            return f"missing required tool {tool!r} (need: {', '.join(_REQUIRED_TOOLS)})"
    return None


def _default_unprivileged_ids() -> "tuple[int, int]":
    """Pick the uid/gid the agent runs as. Prefer the invoking sudo user (so the agent runs as the
    human, not root); fall back to `nobody`. NEVER 0 — that would void AGENT-UNPRIVILEGED-IN-NETNS."""
    uid = os.environ.get("SUDO_UID")
    gid = os.environ.get("SUDO_GID")
    if uid and gid and int(uid) != 0:
        return int(uid), int(gid)
    return 65534, 65534  # nobody:nogroup


@dataclass
class NetnsConfig:
    ns: str = "signet-agent"
    veth_host: str = "sgnt-h"          # host-side veth (<= 15 chars, IFNAMSIZ)
    veth_agent: str = "sgnt-a"         # agent-side veth, moved into the netns
    host_ip: str = "10.77.0.1"         # proxy binds here; the agent's only reachable peer
    agent_ip: str = "10.77.0.2"
    prefixlen: int = 30                # /30 point-to-point: exactly these two addresses
    agent_uid: Optional[int] = None    # None -> _default_unprivileged_ids()
    agent_gid: Optional[int] = None

    def resolved_ids(self) -> "tuple[int, int]":
        if self.agent_uid is not None and self.agent_gid is not None:
            return self.agent_uid, self.agent_gid
        return _default_unprivileged_ids()


class NetnsController:
    """Privileged controller: create -> configure -> (caller binds proxy) -> restrict -> exec agent
    unprivileged -> teardown. Use as a context manager; teardown is idempotent and leaks nothing
    even if the agent crashed.

        with NetnsController(cfg) as c:           # netns + veth + route are up; host_ip is bound-able
            proxy = EgressProxy(broker, host=cfg.host_ip, port=0).start()
            c.restrict_to_proxy(proxy.port)       # nft drop-OUTPUT-except-proxy goes in now
            out = c.exec_agent([sys.executable, "-m", "signet.sandbox._agent_probe", ...])
    """

    def __init__(self, cfg: Optional[NetnsConfig] = None):
        self.cfg = cfg or NetnsConfig()
        self._setup_done = False
        self._proxy_port: Optional[int] = None

    # -- subprocess helpers -------------------------------------------------------------------
    def _run(self, args: Sequence[str], *, check: bool = True,
             capture: bool = False) -> subprocess.CompletedProcess:
        return subprocess.run(list(args), check=check,
                              capture_output=capture, text=True, timeout=20)

    def _ns(self, *args: str) -> List[str]:
        """Wrap a command so it runs inside the agent netns (privileged: configuration)."""
        return ["ip", "netns", "exec", self.cfg.ns, *args]

    # -- lifecycle ----------------------------------------------------------------------------
    def setup(self) -> "NetnsController":
        """Create the netns, the veth pair, the point-to-point addressing and the default route.
        Does NOT install the firewall yet — the proxy must bind host_ip first to claim its port;
        call restrict_to_proxy(port) afterwards. Fail-closed: any error tears down and re-raises."""
        reason = preflight()
        if reason is not None:
            raise NetnsUnavailable(reason)
        c = self.cfg
        # Start from a clean slate (a prior crash may have leaked names); ignore absence.
        self._teardown_quiet()
        try:
            self._run(["ip", "netns", "add", c.ns])
            # veth pair; move the agent end into the netns.
            self._run(["ip", "link", "add", c.veth_host, "type", "veth",
                       "peer", "name", c.veth_agent])
            self._run(["ip", "link", "set", c.veth_agent, "netns", c.ns])
            # host side up + addressed (the proxy will bind c.host_ip).
            self._run(["ip", "addr", "add", f"{c.host_ip}/{c.prefixlen}", "dev", c.veth_host])
            self._run(["ip", "link", "set", c.veth_host, "up"])
            # agent side up + addressed, loopback up, default route via the host peer ONLY.
            self._run(self._ns("ip", "addr", "add", f"{c.agent_ip}/{c.prefixlen}",
                               "dev", c.veth_agent))
            self._run(self._ns("ip", "link", "set", c.veth_agent, "up"))
            self._run(self._ns("ip", "link", "set", "lo", "up"))
            self._run(self._ns("ip", "route", "add", "default", "via", c.host_ip))
            # Deliberately NO ip_forward, NO NAT/masquerade on the host: the agent's default route
            # leads to the proxy peer and nowhere else. (Fork B: no-NAT/no-forward half.)
            self._setup_done = True
            return self
        except Exception:
            self._teardown_quiet()
            raise

    def restrict_to_proxy(self, proxy_port: int) -> None:
        """Install the nftables OUTPUT policy in the agent netns: default DROP, allow only loopback,
        established return traffic, and NEW tcp to host_ip:proxy_port. After this the proxy endpoint
        is the agent's sole reachable destination; 53 (DNS) and every other address are dropped.
        (Fork B: the nft drop-except-proxy half — defense in depth atop no-route.)"""
        if not self._setup_done:
            raise NetnsUnavailable("restrict_to_proxy() called before setup()")
        c = self.cfg
        self._proxy_port = int(proxy_port)
        self._run(self._ns("nft", "add", "table", "inet", "signet"))
        self._run(self._ns("nft", "add", "chain", "inet", "signet", "output",
                           "{", "type", "filter", "hook", "output", "priority", "0", ";",
                           "policy", "drop", ";", "}"))
        self._run(self._ns("nft", "add", "rule", "inet", "signet", "output", "oif", "lo", "accept"))
        self._run(self._ns("nft", "add", "rule", "inet", "signet", "output",
                           "ct", "state", "established,related", "accept"))
        self._run(self._ns("nft", "add", "rule", "inet", "signet", "output",
                           "ip", "daddr", c.host_ip, "tcp", "dport", str(self._proxy_port),
                           "accept"))
        # No final accept: the chain policy is drop. Everything else (incl. udp/53) dies here.

    def exec_agent(self, cmd: Sequence[str], *, capture: bool = True,
                   timeout: int = 60) -> subprocess.CompletedProcess:
        """Exec the agent UNPRIVILEGED inside the netns. setpriv drops to the configured uid/gid,
        clears supplementary groups, EMPTIES the capability bounding set and sets no_new_privs — so
        the agent can never (re)acquire CAP_NET_ADMIN, even via a file-capability binary. This is
        AGENT-UNPRIVILEGED-IN-NETNS made structural, not a runtime check."""
        if not self._setup_done:
            raise NetnsUnavailable("exec_agent() called before setup()")
        uid, gid = self.cfg.resolved_ids()
        wrapped = self._ns(
            "setpriv", "--reuid", str(uid), "--regid", str(gid), "--clear-groups",
            "--bounding-set", "-all", "--no-new-privs", "--", *cmd)
        return subprocess.run(list(wrapped), check=False,
                              capture_output=capture, text=True, timeout=timeout)

    def agent_launch_argv(self, cmd: Sequence[str]) -> List[str]:
        """The exact privilege-dropping argv exec_agent() would run — exposed so the launcher/docs
        can show the unprivileged launch model without running it."""
        uid, gid = self.cfg.resolved_ids()
        return self._ns("setpriv", "--reuid", str(uid), "--regid", str(gid), "--clear-groups",
                        "--bounding-set", "-all", "--no-new-privs", "--", *cmd)

    def teardown(self) -> None:
        """Idempotent: delete the netns (which removes the agent-side veth and the nft table with
        it) and the host-side veth. Safe to call when nothing was created."""
        self._teardown_quiet()
        self._setup_done = False

    def _teardown_quiet(self) -> None:
        c = self.cfg
        # Deleting the netns removes interfaces inside it and its nft tables; the host-side veth
        # peer is auto-removed with its peer, but we delete it explicitly too (idempotent).
        for args in (["ip", "netns", "del", c.ns],
                     ["ip", "link", "del", c.veth_host]):
            try:
                self._run(args, check=False, capture=True)
            except (OSError, subprocess.SubprocessError):
                pass

    def __enter__(self) -> "NetnsController":
        return self.setup()

    def __exit__(self, *exc) -> None:
        self.teardown()
