#!/bin/bash
# AidotVpn dev wg-data-node reconcile loop.
#
# Polls the controller every $INTERVAL seconds for the current list of
# active devices, then ensures the wg-data-node container's wg0
# interface has exactly those peers (no more, no less).
#
# This script runs as a sidecar to the wg-data-node container and
# shares its network namespace via `network_mode: service:wg-data-node`,
# so the local `wg` commands target wg-data-node's wg0.
#
# Why a poll loop and not a push: the proper push channel is the
# Connect-RPC SyncPeers stream, which is gated on Phase 2c
# (`buf generate`). This script is the dev workaround until that lands.

# We deliberately use `-eo pipefail` but NOT `-u`. With `-u`, alpine's
# bash 5.x raises "unbound variable" on empty associative-array
# parameter expansion (`${have[$key]:-}`) even though the `:-` form
# specifies a default — this is a known portability papercut. Since
# this script's inputs are well-bounded (pubkey strings, IPv4 strings)
# the strict-mode protection is not worth the false-positive crash.
set -eo pipefail

CONTROLLER_URL="${CONTROLLER_URL:-http://controller:10030}"
INTERVAL="${INTERVAL:-15}"

log() { echo "[reconcile] $*"; }

# wait until controller is up — first reconcile would otherwise log a
# noisy curl failure and quit thanks to set -e.
log "waiting for controller at $CONTROLLER_URL ..."
for i in $(seq 1 120); do
    if curl -fsS "$CONTROLLER_URL/healthz" > /dev/null 2>&1; then
        log "controller reachable"
        break
    fi
    sleep 1
done

reconcile_once() {
    local resp
    # Capture both stdout and stderr; print stderr to our log on failure
    # so we can see which step actually broke (curl auth/network vs jq
    # parse vs wg command).
    if ! resp="$(curl -fsS "$CONTROLLER_URL/admin/dev/peers" 2>&1)"; then
        log "controller poll failed (curl): $resp"
        return 0
    fi

    # Build the desired set: pubkey → "ipv4/32"
    declare -A want
    local jq_err
    if ! jq_err="$(echo "$resp" | jq -r '.peers // [] | .[] | "\(.public_key)\t\(.ipv4 // "")"' 2>&1)"; then
        log "jq parse failed: $jq_err"
        log "  raw response: $resp"
        return 0
    fi
    while IFS=$'\t' read -r pub ipv4; do
        [ -n "$pub" ] || continue
        if [ -n "$ipv4" ] && [ "$ipv4" != "null" ]; then
            want["$pub"]="$ipv4/32"
        fi
    done <<< "$jq_err"

    # What does wg currently have?
    declare -A have
    while read -r pub; do
        [ -n "$pub" ] || continue
        have["$pub"]=1
    done < <(wg show wg0 peers 2>/dev/null || true)

    # Add missing peers.
    local added=0 removed=0
    for pub in "${!want[@]}"; do
        if [ -z "${have[$pub]:-}" ]; then
            log "adding peer ${pub:0:12}... allowed-ips ${want[$pub]}"
            if ! wg set wg0 peer "$pub" allowed-ips "${want[$pub]}" 2>&1; then
                log "  wg set FAILED for ${pub:0:12}"
            else
                added=$((added+1))
            fi
        fi
    done

    # Remove stale peers that the controller no longer lists.
    for pub in "${!have[@]}"; do
        if [ -z "${want[$pub]:-}" ]; then
            log "removing peer ${pub:0:12}..."
            wg set wg0 peer "$pub" remove 2>&1 || log "  wg remove FAILED"
            removed=$((removed+1))
        fi
    done

    # Once-per-cycle summary so the log shows progress (or stagnation).
    log "reconcile cycle done — desired:${#want[@]} have:${#have[@]} added:$added removed:$removed"
}

log "starting reconcile loop (interval ${INTERVAL}s, controller $CONTROLLER_URL)"
while true; do
    reconcile_once || log "reconcile_once failed (continuing)"
    sleep "$INTERVAL"
done
