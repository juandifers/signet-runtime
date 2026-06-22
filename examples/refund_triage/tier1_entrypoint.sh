#!/usr/bin/env bash
# Tier-1 container entrypoint. Runs the broker as uid_broker and the agent work as uid_agent.
#   $1 = "test"     -> the structural triad + four-verdict-at-Tier-1 pytest (default)
#        "showcase" -> the trace panels (clean + a1 + a2 + a3) labeled tier=1 (structural)
# Each `docker run` is a FRESH broker session, so each distinct effect is requested once
# (consume-once is real: the same effect twice is a replay BLOCK by design).
set -euo pipefail
MODE="${1:-test}"

export SIGNET_BROKER_SOCK=/run/signet/broker.sock
export SIGNET_BROKER_KEY=/run/signet/broker.key
export SIGNET_BROKER_JWKS=/run/signet/jwks.json
AGENT_UID="$(id -u agent)"
BROKER_UID="$(id -u broker)"

echo "== launching broker as uid_broker (${BROKER_UID}) =="
HOME=/home/broker runuser -u broker -- env \
  SIGNET_BROKER_SOCK="$SIGNET_BROKER_SOCK" SIGNET_BROKER_KEY="$SIGNET_BROKER_KEY" \
  SIGNET_BROKER_JWKS="$SIGNET_BROKER_JWKS" SIGNET_AGENT_UID="$AGENT_UID" \
  SIGNET_HOME=/home/broker/.signet \
  python3 -m examples.refund_triage.tier1_broker &
BROKER_PID=$!
trap 'kill "$BROKER_PID" 2>/dev/null || true' EXIT

# wait for the socket to appear
for _ in $(seq 1 100); do [ -S "$SIGNET_BROKER_SOCK" ] && break; sleep 0.1; done
[ -S "$SIGNET_BROKER_SOCK" ] || { echo "FATAL: broker socket never appeared"; exit 1; }

echo "== OS separation =="
echo "   socket owner uid : $(stat -c %u "$SIGNET_BROKER_SOCK")  (broker)"
echo "   key  owner uid   : $(stat -c %u "$SIGNET_BROKER_KEY")  mode $(stat -c %a "$SIGNET_BROKER_KEY")"
echo "   agent uid        : ${AGENT_UID}"

AGENT_ENV=(env SIGNET_TIER1_STRUCTURAL=1 \
  SIGNET_BROKER_SOCK="$SIGNET_BROKER_SOCK" SIGNET_BROKER_KEY="$SIGNET_BROKER_KEY" \
  SIGNET_BROKER_JWKS="$SIGNET_BROKER_JWKS" SIGNET_HOME=/home/agent/.signet)

if [ "$MODE" = "showcase" ]; then
  for spec in "--scenario clean" "--scenario injected --attack a1" \
              "--scenario injected --attack a2" "--scenario injected --attack a3"; do
    echo
    # shellcheck disable=SC2086
    HOME=/home/agent runuser -u agent -- "${AGENT_ENV[@]}" \
      python3 -m examples.refund_triage.run $spec --tier 1
  done
else
  echo "== running structural triad + verdicts as uid_agent (${AGENT_UID}) =="
  HOME=/home/agent runuser -u agent -- "${AGENT_ENV[@]}" \
    python3 -m pytest tests/test_refund_triage_demo.py -v
fi
