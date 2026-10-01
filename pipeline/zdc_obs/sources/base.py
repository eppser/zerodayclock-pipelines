"""Observation source adapter contract.

Same two-step onboarding as the KEV pipeline: a row in
``obs_core.observation_sources`` and a module here. Nothing else changes.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass
from datetime import date, datetime

from zdc_kev.http import PoliteClient

from ..models import ExploitationObservation, ObsCollectResult, classify_vuln_id


@dataclass
class ObsSourceState:
    last_etag: str | None = None
    last_modified: str | None = None
    last_content_hash: str | None = None
    last_success_at: datetime | None = None
    last_full_sync_at: datetime | None = None


class ObservationSource(abc.ABC):
    source_id: str
    observation_type: str
    rate_per_minute: int = 30
    requires_credential: bool = False
    credential_env: str | None = None
    full_sync_interval_days: int = 7

    @abc.abstractmethod
    def collect(self, client: PoliteClient, state: ObsSourceState, mode: str,
                *, today: date | None = None) -> ObsCollectResult:
        """Fetch and normalise. Never raise for an expected upstream failure — return
        a result carrying the error so one dead source cannot take the others down."""

    def make_client(self) -> PoliteClient:
        return PoliteClient(self.source_id, per_minute=self.rate_per_minute,
                            headers=self.headers())

    def headers(self) -> dict[str, str]:
        return {}

    @staticmethod
    def primary_id(cve_id: str | None, native_id: str) -> tuple[str, str]:
        if cve_id:
            return cve_id, "cve"
        return native_id, classify_vuln_id(native_id)


_REGISTRY: dict[str, type[ObservationSource]] = {}


def register(cls: type[ObservationSource]) -> type[ObservationSource]:
    if not getattr(cls, "source_id", None):
        raise ValueError(f"{cls.__name__} must define source_id")
    if cls.source_id in _REGISTRY:
        raise ValueError(f"duplicate source_id {cls.source_id!r}")
    _REGISTRY[cls.source_id] = cls
    return cls


def get_source(source_id: str) -> ObservationSource:
    try:
        return _REGISTRY[source_id]()
    except KeyError:
        raise KeyError(f"no adapter for {source_id!r}; known: {sorted(_REGISTRY)}") from None


def registered_ids() -> list[str]:
    return sorted(_REGISTRY)


__all__ = ["ObservationSource", "ObsSourceState", "ObsCollectResult",
           "ExploitationObservation", "register", "get_source", "registered_ids"]
