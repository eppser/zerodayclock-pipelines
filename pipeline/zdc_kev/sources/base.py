"""Source adapter contract and registry.

Onboarding a new KEV source is deliberately two steps and nothing else:

1. Add a row to ``core.kev_sources`` (a migration).
2. Add a module here that subclasses :class:`KevSource` and calls ``@register``.

Nothing in the orchestrator, schema, or consolidation logic changes. That is the
"make sure we can onboard other sources going forward" requirement, enforced by
structure rather than by intention.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass
from datetime import date, datetime

from ..http import PoliteClient
from ..models import CollectResult, KevObservation, classify_vuln_id


@dataclass
class SourceState:
    """What the last successful run of this source left behind.

    Read from ``raw.source_fetches`` so incremental logic survives a fresh checkout —
    no local state files, nothing that a CI runner would lose between jobs.
    """

    last_etag: str | None = None
    last_modified: str | None = None
    last_content_hash: str | None = None
    last_success_at: datetime | None = None
    last_full_sync_at: datetime | None = None


class KevSource(abc.ABC):
    source_id: str
    rate_per_minute: int = 30
    requires_credential: bool = False
    credential_env: str | None = None
    #: Force a complete re-pull at least this often, even in incremental mode, so a
    #: missed delta cannot silently persist. "Priority is the most comprehensive dataset."
    full_sync_interval_days: int = 7

    @abc.abstractmethod
    def collect(
        self,
        client: PoliteClient,
        state: SourceState,
        mode: str,
        *,
        today: date | None = None,
    ) -> CollectResult:
        """Fetch and normalise. Must never raise for an expected upstream failure —
        return a CollectResult carrying the error instead, so one dead source cannot
        take the other three down with it."""

    def make_client(self) -> PoliteClient:
        return PoliteClient(self.source_id, per_minute=self.rate_per_minute, headers=self.headers())

    def headers(self) -> dict[str, str]:
        return {}

    # -- helpers shared by adapters -------------------------------------------------

    @staticmethod
    def primary_id(cve_id: str | None, native_id: str) -> tuple[str, str]:
        """Group on the CVE when one exists, else on the source's native id.

        This is what makes rows from four sources land on the same
        ``derived.kev_consolidated`` row. EUVD's native id is EUVD-*, CIRCL's is a
        uuid; without this every source would form its own island.
        """
        if cve_id:
            return cve_id, "cve"
        return native_id, classify_vuln_id(native_id)


_REGISTRY: dict[str, type[KevSource]] = {}


def register(cls: type[KevSource]) -> type[KevSource]:
    if not getattr(cls, "source_id", None):
        raise ValueError(f"{cls.__name__} must define source_id")
    if cls.source_id in _REGISTRY:
        raise ValueError(f"duplicate source_id {cls.source_id!r}")
    _REGISTRY[cls.source_id] = cls
    return cls


def get_source(source_id: str) -> KevSource:
    try:
        return _REGISTRY[source_id]()
    except KeyError:
        raise KeyError(
            f"no adapter registered for {source_id!r}; known: {sorted(_REGISTRY)}"
        ) from None


def registered_ids() -> list[str]:
    return sorted(_REGISTRY)


__all__ = [
    "KevSource",
    "SourceState",
    "CollectResult",
    "KevObservation",
    "register",
    "get_source",
    "registered_ids",
]
