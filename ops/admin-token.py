#!/usr/bin/env python3
"""Obtain an ecosystem admin access token via OAuth2 authorization code + PKCE.

Usage:
    python ops/admin-token.py                # against prod (auth.sebastiancardona.dev)
    python ops/admin-token.py --test         # against the test env
    python ops/admin-token.py --issuer http://localhost:8080   # local dev

Opens your browser for login; a loopback listener on 127.0.0.1:8484 catches the
redirect (RFC 8252) and exchanges the code. Prints an `export AUTH_ADMIN_TOKEN=...`
line ready for the curl examples in the README. Tokens live 10 minutes by design —
rerun when it expires.
"""

import argparse
import base64
import hashlib
import http.server
import json
import secrets
import sys
import threading
import urllib.parse
import urllib.request
import webbrowser

# Cloudflare (orange-cloud) 403s the default Python-urllib user agent
_opener = urllib.request.build_opener()
_opener.addheaders = [("User-Agent", "Mozilla/5.0 (admin-token.py; ecosystem ops)")]
urllib.request.install_opener(_opener)

CLIENT_ID = "admin-cli"
REDIRECT = "http://127.0.0.1:8484/callback"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--issuer", default="https://auth.sebastiancardona.dev")
    parser.add_argument("--test", action="store_true", help="use auth-test.sebastiancardona.dev")
    args = parser.parse_args()
    issuer = "https://auth-test.sebastiancardona.dev" if args.test else args.issuer.rstrip("/")

    with urllib.request.urlopen(f"{issuer}/.well-known/openid-configuration") as r:
        discovery = json.load(r)

    verifier = b64url(secrets.token_bytes(48))
    challenge = b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    state = b64url(secrets.token_bytes(16))

    authorize_url = discovery["authorization_endpoint"] + "?" + urllib.parse.urlencode({
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT,
        "scope": "openid profile",
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    })

    result: dict = {}
    done = threading.Event()

    class Callback(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 (stdlib naming)
            query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            result["code"] = query.get("code", [None])[0]
            result["state"] = query.get("state", [None])[0]
            result["error"] = query.get("error", [None])[0]
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write("<h2>Listo — vuelve a la terminal.</h2>".encode())
            done.set()

        def log_message(self, *_):  # keep the terminal clean
            pass

    server = http.server.HTTPServer(("127.0.0.1", 8484), Callback)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    print(f"Opening browser for login at {issuer} …", file=sys.stderr)
    if not webbrowser.open(authorize_url):
        print(f"Open this URL manually:\n{authorize_url}", file=sys.stderr)

    if not done.wait(timeout=300):
        print("Timed out waiting for the login redirect.", file=sys.stderr)
        return 1
    server.shutdown()

    if result.get("error") or not result.get("code"):
        print(f"Authorization failed: {result.get('error')}", file=sys.stderr)
        return 1
    if result.get("state") != state:
        print("State mismatch — aborting (possible CSRF).", file=sys.stderr)
        return 1

    token_request = urllib.parse.urlencode({
        "grant_type": "authorization_code",
        "code": result["code"],
        "redirect_uri": REDIRECT,
        "client_id": CLIENT_ID,
        "code_verifier": verifier,
    }).encode()
    with urllib.request.urlopen(urllib.request.Request(
            discovery["token_endpoint"], data=token_request,
            headers={"Content-Type": "application/x-www-form-urlencoded"})) as r:
        tokens = json.load(r)

    print(f"# expires in {tokens.get('expires_in')}s — rerun this script to refresh",
          file=sys.stderr)
    print(f"export AUTH_ADMIN_TOKEN={tokens['access_token']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
