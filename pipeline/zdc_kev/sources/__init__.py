"""KEV source adapters.

Importing this package registers every adapter. Adding a source means adding a module
here and one row in ``core.kev_sources`` — nothing in the orchestrator changes.
"""

from . import circl, cisa, euvd, vulncheck  # noqa: F401  (import registers the adapter)
from .base import KevSource, SourceState, get_source, register, registered_ids

__all__ = ["KevSource", "SourceState", "get_source", "register", "registered_ids"]
