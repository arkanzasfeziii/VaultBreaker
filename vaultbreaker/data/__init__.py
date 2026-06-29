"""Static data and utility helpers for VaultBreaker modules."""
from __future__ import annotations

import re
import socket
import urllib.parse
from typing import Any, Dict, Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─────────────────────────────────────────────────────────────
# Tool metadata
# ─────────────────────────────────────────────────────────────

TOOL_NAME = "VaultBreaker Framework"
COMMAND = "vaultbreaker"
VERSION = "1.0.0"

# ─────────────────────────────────────────────────────────────
# Network helpers
# ─────────────────────────────────────────────────────────────


def tcp_connect(host: str, port: int, timeout: int = 5) -> Optional[socket.socket]:
    """Attempt a TCP connection and return the socket, or None on failure."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        return s
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def send_recv(sock: socket.socket, data: bytes, timeout: int = 5) -> bytes:
    """Send *data* over *sock* and return the response (up to 4096 bytes)."""
    try:
        sock.settimeout(timeout)
        sock.sendall(data)
        return sock.recv(4096)
    except (socket.timeout, ConnectionResetError, OSError):
        return b""


def http_request(
    url: str,
    method: str = "GET",
    data: Any = None,
    headers: Optional[Dict] = None,
    timeout: int = 10,
    json_body: Any = None,
) -> Optional[requests.Response]:
    """Fire an HTTP request with sane defaults and return the response."""
    try:
        kwargs: Dict[str, Any] = {
            "timeout": timeout,
            "verify": False,
            "allow_redirects": True,
        }
        if headers:
            kwargs["headers"] = headers
        if method.upper() == "GET":
            return requests.get(url, params=data, **kwargs)
        elif method.upper() == "POST":
            if json_body is not None:
                kwargs["json"] = json_body
            elif data is not None:
                kwargs["data"] = data
            return requests.post(url, **kwargs)
        return None
    except requests.RequestException:
        return None
