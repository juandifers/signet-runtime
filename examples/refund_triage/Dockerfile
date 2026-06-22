# Tier-1 structural harness for the refund-triage demo (spec §5).
#
# Establishes REAL OS uid separation on Linux: uid_broker owns the ES256 signing key at a
# container-local 0600 path (NOT a bind-mount, so ownership is genuine Linux ownership, not a
# mount artifact); uid_agent runs the LangGraph graph and can reach the broker ONLY over the Unix
# socket, where SO_PEERCRED enforces identity. This is OS uid separation — it needs NO
# CAP_NET_ADMIN and nothing like the egress netns.
#
#   build+run:  bash examples/refund_triage/run_tier1_container.sh
#   manual:     docker build -f examples/refund_triage/Dockerfile -t signet-refund-tier1 .
#               docker run --rm signet-refund-tier1 test       # the structural triad + verdicts
#               docker run --rm signet-refund-tier1 showcase   # the trace panels (tier=1 structural)
FROM python:3.11-slim

# git: the kernel-unchanged test reads `git show main:...`. util-linux: runuser (drop privilege).
RUN apt-get update && apt-get install -y --no-install-recommends git util-linux \
    && rm -rf /var/lib/apt/lists/*
# the repo is copied as root; let any uid run git against it (read-only history check)
RUN git config --system --add safe.directory '*'

# two unprivileged principals: a broker and an agent, with DISTINCT uids
RUN useradd -m -u 1100 broker && useradd -m -u 1200 agent

WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir -e ".[refund-demo,dev,supabase]"

# broker runtime dir: owned by broker, world-traversable so the agent can reach the socket file
RUN mkdir -p /run/signet && chown broker:broker /run/signet && chmod 755 /run/signet \
    && mkdir -p /home/agent/.signet /home/broker/.signet \
    && chown agent:agent /home/agent/.signet && chown broker:broker /home/broker/.signet

ENTRYPOINT ["bash", "/app/examples/refund_triage/tier1_entrypoint.sh"]
CMD ["test"]
