#!/usr/bin/env python3
"""Serve CW Digest locally with refresh/archive API endpoints."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import subprocess  # nosec B404
import sys
import threading
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse


SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
FETCH_SCRIPT = SCRIPT_DIR / "fetch_gmail_digest.py"
ARCHIVE_FILE = PROJECT_ROOT / "data" / "archive_weeks.json"
ALLOWED_SOURCES = {"all", "politico", "substack", "stephen_bush", "newsletters"}
MAX_REFRESH_BODY_BYTES = 16 * 1024
REFRESH_TIMEOUT_SECONDS = 300
REFRESH_REQUEST_HEADER = "X-CW-Digest-Request"
REFRESH_REQUEST_HEADER_VALUE = "refresh"
_REFRESH_LOCK = threading.Lock()


def _json_response(handler: SimpleHTTPRequestHandler, status: int, payload: dict) -> None:
    body = json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(body)


def _is_loopback_client(handler: SimpleHTTPRequestHandler) -> bool:
    host = ""
    if getattr(handler, "client_address", None):
        host = str(handler.client_address[0] or "")
    host = host.strip()
    if not host:
        return False
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host == "localhost"


def _sanitize_command_output(value: str | None, *, limit: int = 4000) -> str:
    text = (value or "").strip()
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + " ... [truncated]"


def _normalize_source(source_raw: object) -> str:
    source = str(source_raw or "all").strip().lower()
    if source in ALLOWED_SOURCES:
        return source
    return "all"


def _normalize_model_name(model_raw: object) -> str:
    model = str(model_raw or "gpt-4o-mini").strip()
    if re.fullmatch(r"[A-Za-z0-9._:-]{1,80}", model):
        return model
    return "gpt-4o-mini"


def _run_refresh(max_results: int, source: str, ai_summaries: bool, ai_model: str) -> tuple[int, dict]:
    safe_source = _normalize_source(source)
    safe_model = _normalize_model_name(ai_model)
    cmd = [
        sys.executable,
        str(FETCH_SCRIPT),
        "--sync-html",
        "--source",
        safe_source,
        "--max-results",
        str(max_results),
    ]
    if ai_summaries:
        cmd.extend(["--ai-summaries", "--ai-model", safe_model])

    try:
        completed = subprocess.run(  # nosec B603
            cmd,
            cwd=str(PROJECT_ROOT),
            capture_output=True,
            text=True,
            timeout=REFRESH_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        return (
            HTTPStatus.GATEWAY_TIMEOUT,
            {
                "error": f"Refresh command timed out after {REFRESH_TIMEOUT_SECONDS} seconds.",
                "stderr": _sanitize_command_output(exc.stderr),
                "stdout": _sanitize_command_output(exc.stdout),
            },
        )

    if completed.returncode != 0:
        return (
            HTTPStatus.INTERNAL_SERVER_ERROR,
            {
                "error": "Refresh command failed.",
                "stderr": _sanitize_command_output(completed.stderr),
                "stdout": _sanitize_command_output(completed.stdout),
            },
        )

    output = completed.stdout.strip()
    try:
        parsed = json.loads(output) if output else {}
    except ValueError:
        parsed = {"raw_output": output}

    return HTTPStatus.OK, parsed


class DigestHandler(SimpleHTTPRequestHandler):
    """Simple static server with digest APIs."""

    def __init__(
        self,
        *args,
        directory: str | None = None,
        allow_remote_api: bool = False,
        **kwargs,
    ) -> None:
        self._allow_remote_api = allow_remote_api
        super().__init__(*args, directory=directory, **kwargs)

    def _require_local_api_client(self) -> bool:
        if self._allow_remote_api or _is_loopback_client(self):
            return True
        _json_response(
            self,
            HTTPStatus.FORBIDDEN,
            {
                "error": "API access is restricted to localhost. "
                "Restart with --allow-remote-api to permit remote API requests.",
            },
        )
        return False

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/api/archive":
            if not self._require_local_api_client():
                return
            payload = {"version": 1, "weeks": []}
            if ARCHIVE_FILE.exists():
                try:
                    loaded = json.loads(ARCHIVE_FILE.read_text(encoding="utf-8"))
                    if isinstance(loaded, dict):
                        payload = loaded
                except ValueError:
                    payload = {"version": 1, "weeks": []}
            _json_response(self, HTTPStatus.OK, payload)
            return

        if parsed.path == "/api/health":
            _json_response(self, HTTPStatus.OK, {"ok": True})
            return

        super().do_GET()

    def end_headers(self) -> None:
        """Add baseline security and cache-control headers."""
        path = getattr(self, "path", "")
        parsed = urlparse(path).path if path else ""
        if parsed.endswith(".html") or parsed.startswith("/api/"):
            self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        super().end_headers()

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path != "/api/refresh":
            _json_response(self, HTTPStatus.NOT_FOUND, {"error": "Unknown endpoint."})
            return

        if not self._require_local_api_client():
            return

        request_marker = str(self.headers.get(REFRESH_REQUEST_HEADER, "")).strip().lower()
        if request_marker != REFRESH_REQUEST_HEADER_VALUE:
            _json_response(
                self,
                HTTPStatus.FORBIDDEN,
                {"error": "Missing or invalid refresh request header."},
            )
            return

        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            _json_response(self, HTTPStatus.BAD_REQUEST, {"error": "Invalid Content-Length header."})
            return
        if length < 0:
            _json_response(self, HTTPStatus.BAD_REQUEST, {"error": "Invalid request body length."})
            return
        if length > MAX_REFRESH_BODY_BYTES:
            _json_response(
                self,
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                {"error": f"Request body too large (max {MAX_REFRESH_BODY_BYTES} bytes)."},
            )
            return

        body = self.rfile.read(length) if length > 0 else b"{}"
        try:
            payload = json.loads(body.decode("utf-8"))
        except ValueError:
            _json_response(self, HTTPStatus.BAD_REQUEST, {"error": "Request body must be valid JSON."})
            return
        if not isinstance(payload, dict):
            _json_response(self, HTTPStatus.BAD_REQUEST, {"error": "Request JSON must be an object."})
            return

        source = _normalize_source(payload.get("source"))
        max_results_raw = payload.get("max_results", 25)
        ai_summaries = bool(payload.get("ai_summaries", False))
        ai_model = _normalize_model_name(payload.get("ai_model"))

        try:
            max_results = int(max_results_raw)
        except (TypeError, ValueError):
            max_results = 25
        if max_results < 1:
            max_results = 1
        if max_results > 150:
            max_results = 150

        if not _REFRESH_LOCK.acquire(blocking=False):
            _json_response(
                self,
                HTTPStatus.TOO_MANY_REQUESTS,
                {"error": "Refresh already in progress. Please wait and retry."},
            )
            return
        try:
            status, result = _run_refresh(
                max_results=max_results,
                source=source,
                ai_summaries=ai_summaries,
                ai_model=ai_model,
            )
        finally:
            _REFRESH_LOCK.release()
        _json_response(self, status, result)


def main() -> None:
    parser = argparse.ArgumentParser(description="Serve CW Digest with refresh API")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8765, help="Port to bind (default: 8765)")
    parser.add_argument(
        "--allow-remote-api",
        action="store_true",
        help="Allow API requests from non-loopback clients.",
    )
    args = parser.parse_args()

    server = ThreadingHTTPServer(
        (args.host, args.port),
        lambda *handler_args, **handler_kwargs: DigestHandler(
            *handler_args,
            directory=str(PROJECT_ROOT),
            allow_remote_api=args.allow_remote_api,
            **handler_kwargs,
        ),
    )
    print(f"Serving CW Digest at http://{args.host}:{args.port}/newsletter-digest.html")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
