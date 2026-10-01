"""Observation source adapters. Importing this package registers them."""

from . import msrc, shadowserver, vulncheck_canary  # noqa: F401
from .base import (ObservationSource, ObsSourceState, get_source, register,
                   registered_ids)

__all__ = ["ObservationSource", "ObsSourceState", "get_source", "register", "registered_ids"]
