"""Two services on the gateway's tunnel address.

## Why this exists

The app needs to reach the controller after registering — to refresh its
policy, and to learn it has been revoked. Until now it did that with a
compiled-in address:

    BuildConfig.CONTROLLER_URL = http://192.168.0.9:10030

Anyone who unpacks the APK reads the hospital's internal address off it.

The classic OpenVPN pattern avoids that: bootstrap on a public endpoint,
then speak to internal services over the tunnel using internal addresses
only. This is the gateway half of that — the controller becomes
reachable at 10.78.0.1, which means nothing outside the tunnel.

## What can and cannot be hidden

The **tunnel endpoint** cannot. WireGuard has to know where to send a
handshake, so that address is in the client by necessity — as
`remote` is in every .ovpn file. It is the gateway's address, usually
public, and not the thing worth hiding.

The **controller address** can, for everything after registration.
Registration itself has to happen before a tunnel exists, so it still
needs a reachable address; that one stays.

## Two ports

    8080   a reachability target — 도달성 시험 needs something that
           answers, and the tutorial pointed at 10030 where nothing did
    10030  a proxy to the real controller

10030 matches the controller's port elsewhere on purpose here: the app
should be able to swap host and change nothing else.
"""

import http.client
import http.server
import os
import socketserver
import threading

TUNNEL_ADDR = "10.78.0.1"
PROBE_PORT = 8080
PROXY_PORT = 10030

# Where the real controller is. The gateway already needs this for the
# agent, so it is not a new secret to keep.
UPSTREAM = os.environ.get("CONTROLLER_UPSTREAM", "host.docker.internal:10030")

# Only the endpoints a registered device uses.
#
# A blanket proxy would put the admin API on the tunnel, where any
# enrolled handset could reach it. These are the two a device calls for
# itself, and both are already unauthenticated by design.
ALLOWED_PREFIXES = ("/devices/", "/enrollment-requests")


class ProbeHandler(http.server.BaseHTTPRequestHandler):
    """Answers anything, so the probe has proof it arrived."""

    def do_GET(self):
        body = b"aidotvpn gateway reachable\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass  # one line per probe would drown the startup log


class ProxyHandler(http.server.BaseHTTPRequestHandler):
    """Forwards device-facing calls to the controller."""

    protocol_version = "HTTP/1.1"

    def _forward(self):
        if not self.path.startswith(ALLOWED_PREFIXES):
            # Refused rather than silently dropped: a device calling
            # something it should not needs to see why, and an operator
            # reading a timeout would look for a network fault.
            self.send_error(403, "not exposed on the tunnel")
            return

        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None

        try:
            conn = http.client.HTTPConnection(UPSTREAM, timeout=10)
            headers = {
                k: v for k, v in self.headers.items()
                # Hop-by-hop; re-set by the client below.
                if k.lower() not in ("host", "connection", "content-length")
            }
            conn.request(self.command, self.path, body=body, headers=headers)
            resp = conn.getresponse()
            payload = resp.read()
        except Exception as exc:  # noqa: BLE001 - reported, not swallowed
            # Say the upstream failed. A gateway that answers 502 is
            # distinguishable from one that is not there at all, which a
            # timeout is not.
            self.send_error(502, f"controller unreachable: {exc}")
            return

        self.send_response(resp.status)
        for key, value in resp.getheaders():
            if key.lower() in ("transfer-encoding", "connection", "content-length"):
                continue
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = _forward
    do_POST = _forward
    do_PUT = _forward
    do_DELETE = _forward

    def log_message(self, *_args):
        pass


def serve(port, handler):
    socketserver.TCPServer.allow_reuse_address = True
    server = socketserver.ThreadingTCPServer((TUNNEL_ADDR, port), handler)
    server.serve_forever()


if __name__ == "__main__":
    threading.Thread(target=serve, args=(PROBE_PORT, ProbeHandler), daemon=True).start()
    # Bind the proxy port before announcing readiness, so the file means
    # both ports are actually held — not merely that the process started.
    socketserver.TCPServer.allow_reuse_address = True
    proxy = socketserver.ThreadingTCPServer((TUNNEL_ADDR, PROXY_PORT), ProxyHandler)
    with open("/run/responder-ready", "w") as f:
        f.write(f"{TUNNEL_ADDR} {PROBE_PORT} {PROXY_PORT}\n")
    proxy.serve_forever()
