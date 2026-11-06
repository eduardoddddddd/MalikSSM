"""
MalikSSM Python SDK (Zero-Dependency Client)
============================================
Automatically authenticates using AWS-style credential chain:
  1. Explicit `token` passed to `MalikClient(token="...")`
  2. Environment variable `MALIK_TOKEN` (for 24/7 bots, Docker containers, or servers)
  3. Local Windows DPAPI session (`session.bin` via `malik session-token`) created by `malik login`
"""

from __future__ import annotations
import json
import os
import shutil
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional


class MalikError(Exception):
    """Raised when MalikSSM returns an API or authentication error."""


class MalikClient:
    def __init__(
        self,
        server_url: Optional[str] = None,
        token: Optional[str] = None,
        agent_name: str = "python-sdk",
        timeout: int = 10,
    ) -> None:
        self.server_url = (
            server_url
            or os.environ.get("MALIK_SERVER")
            or "http://127.0.0.1:8443"
        ).rstrip("/")
        self.token = token or os.environ.get("MALIK_TOKEN") or self._load_dpapi_session_token()
        self.agent_name = agent_name
        self.timeout = timeout

    @staticmethod
    def _load_dpapi_session_token() -> str:
        """Resolves the active workstation session token from Windows DPAPI via malik.exe."""
        candidates = [
            shutil.which("malik"),
            shutil.which("malik.exe"),
            os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "bin", "malik.exe")),
            os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "malik.exe")),
        ]
        for exe in candidates:
            if exe and os.path.isfile(exe):
                try:
                    res = subprocess.run(
                        [exe, "session-token"],
                        capture_output=True,
                        text=True,
                        timeout=3,
                        check=False,
                    )
                    if res.returncode == 0 and res.stdout.strip():
                        return res.stdout.strip()
                except Exception:
                    pass
        return ""

    def _request(
        self,
        method: str,
        path: str,
        body: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        url = f"{self.server_url}{path}"
        headers = {
            "X-Malik-Agent": self.agent_name,
            "Accept": "application/json",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        data: Optional[bytes] = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode("utf-8")

        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8")
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="replace")
            try:
                msg = json.loads(err_body).get("error", err_body)
            except Exception:
                msg = err_body
            raise MalikError(f"MalikSSM HTTP {exc.code}: {msg}") from exc
        except urllib.error.URLError as exc:
            raise MalikError(f"Cannot reach MalikSSM server at {self.server_url}: {exc}") from exc

    def search(self, query: str = "", tags: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Semantic search across paths, tags, descriptions, and schema_keys."""
        params: Dict[str, str] = {}
        if query:
            params["q"] = query
        if tags:
            params["tags"] = ",".join(tags)
        qs = f"?{urllib.parse.urlencode(params)}" if params else ""
        return self._request("GET", f"/v1/search{qs}").get("results", [])

    def get(
        self,
        path: str,
        field: Optional[str] = None,
        stage: str = "AWSCURRENT",
    ) -> Any:
        """
        Retrieve a decrypted secret.
        - If `field` is specified, returns that single string value.
        - If the secret is a key-value map (`kv`), returns the `dict` of fields.
        - Otherwise returns the plain string `value`.
        """
        norm_path = path.strip("/")
        params: Dict[str, str] = {"stage": stage}
        if field:
            params["field"] = field
        qs = urllib.parse.urlencode(params)
        res = self._request("GET", f"/v1/secrets/{norm_path}?{qs}")
        if field:
            return res.get("value")
        if res.get("type") in ("kv", "env") and isinstance(res.get("data"), dict):
            return res["data"]
        return res.get("value")

    def set(
        self,
        path: str,
        data: Optional[Dict[str, str]] = None,
        value: str = "",
        description: str = "",
        tags: Optional[List[str]] = None,
        secret_type: str = "kv",
    ) -> Dict[str, Any]:
        """Create or update (rotate) a secret in MalikSSM."""
        return self._request(
            "POST",
            "/v1/secrets",
            body={
                "path": path.strip("/"),
                "type": secret_type,
                "description": description,
                "tags": tags or [],
                "data": data or {},
                "value": value,
            },
        )

    def totp(self, path: str) -> str:
        """Return the current 6-digit 2FA TOTP code for `path`."""
        norm_path = path.strip("/")
        return self._request("GET", f"/v1/totp/{norm_path}")["code"]

    def boto3_client(self):
        """Return a drop-in AWS `boto3.client('secretsmanager')` pre-configured for MalikSSM."""
        import boto3  # type: ignore

        return boto3.client(
            "secretsmanager",
            endpoint_url=self.server_url,
            aws_access_key_id=self.token or "mlk_anonymous",
            aws_secret_access_key="malik-ssm-local",
            region_name="local",
        )
