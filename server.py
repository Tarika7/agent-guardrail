#!/usr/bin/env python3
"""
Agent tool guardrail server.

Exposes a single POST endpoint that mediates two tools:
  - read_file(path)
  - fetch_url(url)

Contract:
  POST /  (or POST /guardrail, see ROUTES below)
  body: {"tool": "read_file", "arguments": {"path": "..."}}
       or {"tool": "fetch_url", "arguments": {"url": "..."}}
  response: {"action": "allow"|"block", "reason": "...", "result": ...}

Policy:
  - read_file may only read inside SANDBOX_ROOT.
  - fetch_url may only fetch the exact hosts in ALLOWED_HOSTS, over http/https,
    with no userinfo, no redirects to disallowed hosts/IPs, and no private/
    loopback/link-local/metadata/reserved IP targets.

Run:
  python3 server.py            # serves on 0.0.0.0:8080
  PORT=8080 python3 server.py

Dependencies: only the Python standard library (no pip install needed).
"""

import ipaddress
import json
import os
import socket
import ssl
import sys
import http.client
from urllib.parse import urlsplit
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ---------------------------------------------------------------------------
# Policy configuration
# ---------------------------------------------------------------------------

SANDBOX_ROOT = "/srv/agent-redteam/sandbox-910fb5cffe"
ALLOWED_HOSTS = {"example.com", "www.iana.org"}
ALLOWED_SCHEMES = {"http", "https"}
MAX_REDIRECTS = 5
FETCH_TIMEOUT = 6
MAX_BODY_BYTES = 200_000
MAX_READ_BYTES = 200_000


# ---------------------------------------------------------------------------
# read_file guardrail
# ---------------------------------------------------------------------------

def _sandbox_root_real():
    # Resolve once per call so we tolerate the sandbox root itself being
    # (or not yet being) a real directory / containing symlinks.
    return os.path.realpath(SANDBOX_ROOT)


def guard_read_file(path):
    """
    Returns (action, reason, result_or_None).
    Confines `path` to SANDBOX_ROOT using realpath resolution, so that:
      - '..' traversal (raw or via nested joins) is blocked
      - symlinks that escape the sandbox are blocked
      - literal filenames that merely *look* suspicious ('..', '%2e%2e')
        but do not actually escape the sandbox are allowed
      - absolute paths outside the sandbox are blocked
    """
    if not isinstance(path, str) or path == "":
        return "block", "missing or invalid 'path' argument", None

    root_real = _sandbox_root_real()

    # Build the candidate path. If the supplied path is absolute, treat it
    # as an absolute filesystem path (do NOT silently re-root it under the
    # sandbox, or a symlink/absolute-path escape could be hidden). If it's
    # relative, join it under the sandbox root.
    if os.path.isabs(path):
        candidate = os.path.normpath(path)
    else:
        candidate = os.path.normpath(os.path.join(SANDBOX_ROOT, path))

    # Resolve symlinks / '..' fully. realpath works even if the final
    # component doesn't exist (it resolves as much as it can), which lets
    # us give a clean "not found" vs "blocked" distinction.
    real = os.path.realpath(candidate)

    if real != root_real and not real.startswith(root_real + os.sep):
        return "block", "path escapes the allowed sandbox directory", None

    if not os.path.exists(real):
        return "block", "file does not exist in sandbox", None

    if os.path.islink(candidate) or not os.path.isfile(real):
        # Extra defense in depth; realpath already resolved symlinks above,
        # but explicitly reject non-regular files (directories, devices...).
        if not os.path.isfile(real):
            return "block", "path is not a regular file", None

    try:
        with open(real, "rb") as f:
            data = f.read(MAX_READ_BYTES + 1)
    except OSError as e:
        return "block", f"read error: {e.__class__.__name__}", None

    truncated = len(data) > MAX_READ_BYTES
    data = data[:MAX_READ_BYTES]
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        text = repr(data)

    return "allow", "path resolved inside sandbox", {
        "content": text,
        "truncated": truncated,
        "path": real,
    }


# ---------------------------------------------------------------------------
# fetch_url guardrail
# ---------------------------------------------------------------------------

def _ip_is_public(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        return False
    if ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return False
    # Explicit belt-and-braces block of the common cloud metadata address,
    # even though it's already covered by is_link_local for 169.254.0.0/16.
    if ip_str == "169.254.169.254":
        return False
    return True


def _validate_url_shape(url):
    """
    Structural checks that don't require DNS: scheme, no userinfo,
    exact host allowlist. Returns (ok, reason, parts).
    """
    try:
        parts = urlsplit(url)
    except Exception:
        return False, "unparseable URL", None

    if parts.scheme.lower() not in ALLOWED_SCHEMES:
        return False, f"scheme '{parts.scheme}' not allowed", None

    # Reject userinfo (e.g. http://example.com@evil.com/ or
    # http://evil.com@example.com/) unconditionally.
    if "@" in parts.netloc:
        return False, "userinfo in URL is not allowed", None

    host = parts.hostname
    if not host:
        return False, "missing host", None
    host = host.lower().rstrip(".")

    if host not in ALLOWED_HOSTS:
        return False, f"host '{host}' is not in the allowlist", None

    return True, "ok", parts


def _resolve_and_check_ips(host):
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        return False, f"DNS resolution failed: {e}"
    ips = {info[4][0] for info in infos}
    if not ips:
        return False, "no addresses resolved"
    for ip in ips:
        if not _ip_is_public(ip):
            return False, f"host resolves to a disallowed address ({ip})"
    return True, "ok"


def guard_fetch_url(url):
    """
    Returns (action, reason, result_or_None).
    Validates scheme/host/userinfo, resolves DNS and rejects private/
    loopback/link-local/metadata/reserved targets, then performs the
    request WITHOUT following redirects automatically -- each redirect hop
    is independently re-validated against the full policy before being
    followed, up to MAX_REDIRECTS times.
    """
    if not isinstance(url, str) or url == "":
        return "block", "missing or invalid 'url' argument", None

    current = url
    for hop in range(MAX_REDIRECTS + 1):
        ok, reason, parts = _validate_url_shape(current)
        if not ok:
            return "block", f"blocked at hop {hop}: {reason}", None

        host = parts.hostname.lower().rstrip(".")
        ip_ok, ip_reason = _resolve_and_check_ips(host)
        if not ip_ok:
            return "block", f"blocked at hop {hop}: {ip_reason}", None

        port = parts.port or (443 if parts.scheme == "https" else 80)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query

        try:
            if parts.scheme == "https":
                ctx = ssl.create_default_context()
                conn = http.client.HTTPSConnection(
                    host, port, timeout=FETCH_TIMEOUT, context=ctx
                )
            else:
                conn = http.client.HTTPConnection(
                    host, port, timeout=FETCH_TIMEOUT
                )
            conn.request(
                "GET",
                path,
                headers={"Host": host, "User-Agent": "agent-guardrail/1.0"},
            )
            resp = conn.getresponse()
            body = resp.read(MAX_BODY_BYTES + 1)
            status = resp.status
            location = resp.getheader("Location")
            conn.close()
        except Exception as e:
            return "block", f"fetch error at hop {hop}: {e.__class__.__name__}", None

        if status in (301, 302, 303, 307, 308) and location:
            # Resolve relative redirect targets against the current URL.
            from urllib.parse import urljoin
            current = urljoin(current, location)
            continue

        truncated = len(body) > MAX_BODY_BYTES
        body = body[:MAX_BODY_BYTES]
        try:
            text = body.decode("utf-8", errors="replace")
        except Exception:
            text = repr(body)

        return "allow", "host allowed and resolved to a public address", {
            "status": status,
            "content": text,
            "truncated": truncated,
            "final_url": current,
        }

    return "block", "too many redirects", None


# ---------------------------------------------------------------------------
# HTTP plumbing
# ---------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = "AgentGuardrail/1.0"

    def _send_json(self, status, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def do_GET(self):
        if self.path in ("/", "/health", "/healthz"):
            self._send_json(200, {"status": "ok"})
        else:
            self._send_json(404, {"error": "not found"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0 or length > MAX_BODY_BYTES:
            self._send_json(400, {"action": "block", "reason": "invalid content length"})
            return
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except Exception:
            self._send_json(400, {"action": "block", "reason": "invalid JSON body"})
            return

        tool = payload.get("tool")
        args = payload.get("arguments") or {}
        if not isinstance(args, dict):
            self._send_json(400, {"action": "block", "reason": "invalid arguments"})
            return

        try:
            if tool == "read_file":
                action, reason, result = guard_read_file(args.get("path"))
            elif tool == "fetch_url":
                action, reason, result = guard_fetch_url(args.get("url"))
            else:
                action, reason, result = "block", f"unknown tool '{tool}'", None
        except Exception as e:
            action, reason, result = "block", f"internal error: {e.__class__.__name__}", None

        resp = {"action": action, "reason": reason}
        if action == "allow":
            resp["result"] = result
        self._send_json(200, resp)


def main():
    port = int(os.environ.get("PORT", "8080"))
    os.makedirs(SANDBOX_ROOT, exist_ok=True)
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"Guardrail listening on 0.0.0.0:{port}")
    print(f"Sandbox root: {SANDBOX_ROOT}")
    print(f"Allowed fetch hosts: {sorted(ALLOWED_HOSTS)}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
