"""LIVE GitHub rail — a real GitHubRail that talks to api.github.com.

Outbound only (no inbound webhook server): authenticates as a GitHub App, exchanges a
short-lived installation token, reads a PR's changed files + head_sha + base, and posts a
real Check Run named "signet/enforced" bound to the head_sha.

It is a drop-in for `signet.authorizers.github_railbridge.GitHubRail` (implements
open_check/conclude) AND adds the L3-runner conveniences read_pr/post_check/list_open_prs.
The DECISION logic is unchanged and lives elsewhere (enforce_merge); this only turns a
decision into a real Check Run.

Credentials come from the environment, NEVER hardcoded:
    SIGNET_GH_APP_ID, SIGNET_GH_PRIVATE_KEY_PATH, SIGNET_GH_INSTALLATION_ID, SIGNET_GH_REPO

FAIL CLOSED: any auth/fetch/post error raises (the runner then posts conclusion=failure or
posts nothing) -- never a neutral/success on error. `jwt`/`requests` are imported lazily so
importing this module never breaks the offline test suite; install with
`pip install -e ".[l3-github]"`.
"""
from __future__ import annotations

import os
import time
from typing import Optional

from signet.authorizers.github_railbridge import GitHubRail

API = "https://api.github.com"
CHECK_NAME = "signet/enforced"
_ENV = ("SIGNET_GH_APP_ID", "SIGNET_GH_PRIVATE_KEY_PATH",
        "SIGNET_GH_INSTALLATION_ID", "SIGNET_GH_REPO")


def _require_deps():
    try:
        import jwt        # noqa: F401  (PyJWT, needs the [crypto] extra for RS256)
        import requests   # noqa: F401
    except Exception as e:  # pragma: no cover - exercised only in a live env
        raise RuntimeError(
            "The live GitHub rail needs PyJWT + requests. "
            "Install with: pip install -e \".[l3-github]\"") from e


class LiveGitHubRail(GitHubRail):
    """Real Check Run rail over the GitHub App API. Fail closed on every error."""

    CHECK_NAME = CHECK_NAME

    def __init__(self, app_id: str, private_key_pem: str, installation_id: str,
                 repo: str, session=None):
        _require_deps()
        import requests
        if "/" not in repo:
            raise ValueError(f"SIGNET_GH_REPO must be 'owner/repo', got {repo!r}")
        self._app_id = str(app_id)
        self._key = private_key_pem
        self._installation_id = str(installation_id)
        self.repo = repo
        self._owner, self._name = repo.split("/", 1)
        self._session = session or requests.Session()
        self._inst_token: Optional[str] = None
        self._inst_exp: float = 0.0

    # -- construction from the operator's environment (the ONLY source of secrets) --
    @classmethod
    def from_env(cls) -> "LiveGitHubRail":
        missing = [k for k in _ENV if not os.environ.get(k)]
        if missing:
            raise RuntimeError("Missing required env var(s): " + ", ".join(missing))
        key_path = os.environ["SIGNET_GH_PRIVATE_KEY_PATH"]
        try:
            with open(key_path, "r") as fh:
                pem = fh.read()
        except OSError as e:
            raise RuntimeError(f"Cannot read SIGNET_GH_PRIVATE_KEY_PATH ({key_path}): {e}")
        if "PRIVATE KEY" not in pem:
            raise RuntimeError(f"{key_path} does not look like a PEM private key")
        return cls(os.environ["SIGNET_GH_APP_ID"], pem,
                   os.environ["SIGNET_GH_INSTALLATION_ID"], os.environ["SIGNET_GH_REPO"])

    # -- auth: App JWT -> short-lived installation token (refreshed on expiry) --
    def _app_jwt(self) -> str:
        import jwt
        now = int(time.time())
        payload = {"iat": now - 60, "exp": now + 540, "iss": self._app_id}  # <=10 min
        return jwt.encode(payload, self._key, algorithm="RS256")

    def _installation_token(self) -> str:
        # refresh ~2 min before expiry (installation tokens last ~1h).
        if self._inst_token and time.time() < self._inst_exp - 120:
            return self._inst_token
        import requests
        url = f"{API}/app/installations/{self._installation_id}/access_tokens"
        r = self._session.post(url, headers={
            "Authorization": f"Bearer {self._app_jwt()}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }, timeout=30)
        if r.status_code not in (200, 201):
            raise RuntimeError(f"installation token exchange failed: {r.status_code} {r.text[:200]}")
        data = r.json()
        self._inst_token = data["token"]
        # expires_at like "2026-06-03T12:00:00Z"
        self._inst_exp = _parse_iso_to_epoch(data.get("expires_at")) or (time.time() + 3000)
        return self._inst_token

    def _headers(self) -> dict:
        return {
            "Authorization": f"token {self._installation_token()}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def _get(self, path: str):
        import requests
        r = self._session.get(f"{API}{path}", headers=self._headers(), timeout=30)
        if r.status_code != 200:
            raise RuntimeError(f"GET {path} failed: {r.status_code} {r.text[:200]}")
        return r.json()

    # -- repo reads --
    def list_open_prs(self) -> list:
        out, page = [], 1
        while True:
            batch = self._get(f"/repos/{self.repo}/pulls?state=open&per_page=100&page={page}")
            out.extend(int(p["number"]) for p in batch)
            if len(batch) < 100:
                break
            page += 1
        return out

    def read_pr(self, pr: int):
        """Return (changed_file_paths: tuple, head_sha: str, base: str)."""
        meta = self._get(f"/repos/{self.repo}/pulls/{pr}")
        head_sha = meta["head"]["sha"]
        base = meta["base"]["ref"]
        files, page = [], 1
        while True:
            batch = self._get(f"/repos/{self.repo}/pulls/{pr}/files?per_page=100&page={page}")
            files.extend(f["filename"] for f in batch)
            if len(batch) < 100:
                break
            page += 1
        return tuple(files), head_sha, base

    # -- the single-step poster the L3 runner uses --
    def post_check(self, head_sha: str, conclusion: str, summary: str) -> str:
        """Create a COMPLETED Check Run bound to head_sha. conclusion in {success,failure,...}."""
        return self._create_check(head_sha, status="completed", conclusion=conclusion,
                                   summary=summary)

    # -- GitHubRail ABC (two-step, for use through GitHubRailBridge.authorize) --
    def open_check(self, chain_hash: str, head_sha: str) -> str:
        return self._create_check(head_sha, status="in_progress", external_id=chain_hash,
                                  summary="Signet enforcement in progress.")

    def conclude(self, check_run_id: str, chain_hash: str, conclusion: str) -> str:
        import requests
        url = f"{API}/repos/{self.repo}/check-runs/{check_run_id}"
        body = {"status": "completed", "conclusion": conclusion,
                "external_id": chain_hash,
                "output": {"title": "Signet enforcement",
                           "summary": f"chain_hash={chain_hash} -> {conclusion}"}}
        r = self._session.patch(url, headers=self._headers(), json=body, timeout=30)
        if r.status_code not in (200, 201):
            raise RuntimeError(f"conclude check failed: {r.status_code} {r.text[:200]}")
        return str(r.json()["id"])

    def _create_check(self, head_sha: str, *, status: str, conclusion: Optional[str] = None,
                      external_id: Optional[str] = None, summary: str = "") -> str:
        import requests
        body = {"name": CHECK_NAME, "head_sha": head_sha, "status": status,
                "output": {"title": "Signet enforcement", "summary": summary or status}}
        if conclusion is not None:
            body["conclusion"] = conclusion
        if external_id is not None:
            body["external_id"] = external_id
        r = self._session.post(f"{API}/repos/{self.repo}/check-runs",
                               headers=self._headers(), json=body, timeout=30)
        if r.status_code not in (200, 201):
            raise RuntimeError(f"create check failed: {r.status_code} {r.text[:200]}")
        return str(r.json()["id"])


def _parse_iso_to_epoch(s: Optional[str]) -> Optional[float]:
    if not s:
        return None
    try:
        from datetime import datetime, timezone
        return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc).timestamp()
    except Exception:
        return None
