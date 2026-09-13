#!/usr/bin/env bash
#
# Bring the tunnel up, say which implementation carried it, and start
# the responder the reachability test needs.
#
# Rewritten from scratch in 1.7.24. The previous file had been edited
# three times by insertion and never once read back whole: it started
# the responder three times — once with an abandoned `nc` loop, twice
# with the Python file — so the second Python instance died on "Address
# in use" at every boot. My verification ran the Python module by
# itself and passed. It never ran this file.
set -uo pipefail

echo "==> starting WireGuard"

# Which paths exist. wg-quick falls back to wireguard-go silently, so
# without this the only way to learn the fallback is missing is a
# failure that names RTNETLINK rather than the cause.
if [ -e /sys/module/wireguard ]; then
    echo "    kernel module: present"
    echo "kernel" > /run/wg-backend
else
    echo "    kernel module: absent"
    echo "userspace" > /run/wg-backend
    if command -v wireguard-go >/dev/null 2>&1; then
        echo "    wireguard-go:  present — will fall back to userspace"
    else
        echo "    wireguard-go:  absent"
        echo
        echo "!!  Neither path is available."
        echo "    The host kernel has no WireGuard module and this image has"
        echo "    no userspace fallback. On Docker Desktop the kernel is"
        echo "    WSL2's — a newer Docker Desktop usually has it."
        echo
    fi
fi

if ! wg-quick up wg0; then
    echo
    echo "!!  wg-quick failed. In the order worth checking:"
    echo "    1. No kernel module and no /dev/net/tun (userspace needs the device)."
    echo "    2. Missing NET_ADMIN."
    echo "    3. A malformed /etc/wireguard/wg0.conf."
    # Stay up so the logs are readable. Exiting restarts the container
    # and scrolls this away.
    exec tail -f /dev/null
fi

if wg show wg0 >/dev/null 2>&1; then
    if [ -e /sys/module/wireguard ]; then
        echo "==> up on the kernel module"
    else
        echo "==> up on wireguard-go (userspace) — slower, fully functional"
    fi
    wg show wg0
else
    echo "!!  wg-quick reported success but wg0 is not there."
fi

# The responder. Exactly once.
#
# Serves two ports on the tunnel address: 8080, a target that answers
# so 도달성 시험 has proof of arrival; and 10030, a proxy to the real
# controller for policies that route the control channel through the
# tunnel. See reachability-target.py.
if command -v python3 >/dev/null 2>&1; then
    python3 /usr/local/bin/reachability-target.py &
    echo "==> responder on http://10.78.0.1:8080 (probe) and :10030 (controller proxy)"
else
    echo "!!  python3 not present — no responder. 도달성 시험의 '허용된 서버' 는 응답이 없습니다."
fi

exec tail -f /dev/null
