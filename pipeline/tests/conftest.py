from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from zdc_kev.models import FetchRecord

FIXTURES = Path(__file__).parent / "fixtures"
REPO_ROOT = Path(__file__).resolve().parents[2]


def requires_repo_files(*paths: str):
    """Skip where pipeline/ is checked out on its own (the public pipelines mirror)."""
    missing = [p for p in paths if not (REPO_ROOT / p).exists()]
    return pytest.mark.skipif(bool(missing), reason=f"needs {', '.join(missing)} from the full repository")


def load_bytes(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def load_json(name: str) -> dict:
    return json.loads(load_bytes(name))


def make_fetch(source_id: str, body: bytes, *, url: str = "https://example.test/feed",
               mode: str = "full", ok: bool = True, status: int = 200,
               error: str | None = None, not_modified: bool = False) -> FetchRecord:
    record = FetchRecord(source_id=source_id, url=url, request_mode=mode)
    record.http_status = status
    record.ok = ok
    record.not_modified = not_modified
    record.error = error
    if body is not None:
        record.body = body
        record.bytes_downloaded = len(body)
        record.content_hash = hashlib.sha256(body).hexdigest()
    record.finished_at = datetime.now(timezone.utc)
    record.duration_ms = 1
    return record


class StubClient:
    """Replays canned FetchRecords in order, so adapters are tested with zero network.

    Records every call so tests can assert on request shape — which parameters were
    sent, and whether conditional headers were used.
    """

    def __init__(self, responses: list[FetchRecord]):
        self._responses = list(responses)
        self.calls: list[dict] = []

    def get(self, url, *, request_mode="full", etag=None, last_modified=None,
            params=None, headers=None, expect_json=True, no_auth=False) -> FetchRecord:
        self.calls.append(
            {"url": url, "request_mode": request_mode, "etag": etag,
             "last_modified": last_modified, "params": params or {}, "no_auth": no_auth}
        )
        if not self._responses:
            raise AssertionError(f"StubClient exhausted; unexpected request to {url}")
        response = self._responses.pop(0)
        response.url = url
        response.request_mode = request_mode
        return response

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.fixture
def cisa_body() -> bytes:
    return load_bytes("cisa_kev.json")


@pytest.fixture
def euvd_page() -> dict:
    return load_json("euvd_exploited_page.json")


@pytest.fixture
def circl_body() -> bytes:
    return load_bytes("circl_kev_entries.ndjson")


@pytest.fixture
def vulncheck_body() -> bytes:
    return load_bytes("vulncheck_kev.json")
