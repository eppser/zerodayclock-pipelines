"""CVE-source adapter contract."""

from __future__ import annotations

import abc
from dataclasses import dataclass
from datetime import date, datetime

from zdc_kev.http import PoliteClient

from ..models import CveCollectResult, CveRecord


@dataclass
class CveSourceState:
    last_success_at: datetime | None = None
    last_full_sync_at: datetime | None = None
    #: Highest release tag / window boundary already consumed, so a run resumes
    #: exactly where the last one stopped instead of guessing from the clock.
    cursor: str | None = None


class CveSource(abc.ABC):
    source_id: str
    rate_per_minute: int = 30
    requires_credential: bool = False
    credential_env: str | None = None

    @abc.abstractmethod
    def collect(self, client: PoliteClient, state: CveSourceState, mode: str,
                *, today: date | None = None) -> CveCollectResult: ...

    def make_client(self) -> PoliteClient:
        return PoliteClient(self.source_id, per_minute=self.rate_per_minute,
                            headers=self.headers(), timeout=300.0)

    def headers(self) -> dict[str, str]:
        return {}


_REGISTRY: dict[str, type[CveSource]] = {}


def register(cls: type[CveSource]) -> type[CveSource]:
    if not getattr(cls, "source_id", None):
        raise ValueError(f"{cls.__name__} must define source_id")
    if cls.source_id in _REGISTRY:
        raise ValueError(f"duplicate source_id {cls.source_id!r}")
    _REGISTRY[cls.source_id] = cls
    return cls


def get_source(source_id: str) -> CveSource:
    try:
        return _REGISTRY[source_id]()
    except KeyError:
        raise KeyError(f"no adapter for {source_id!r}; known: {sorted(_REGISTRY)}") from None


def registered_ids() -> list[str]:
    return sorted(_REGISTRY)


__all__ = ["CveSource", "CveSourceState", "CveCollectResult", "CveRecord",
           "register", "get_source", "registered_ids"]
