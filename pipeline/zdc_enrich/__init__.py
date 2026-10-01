"""Per-CVE enrichment and the detail rollup.

Two jobs, in order, once the harvesters have run:

1. Fetch EPSS — the only external source this pipeline owns.
2. Rebuild ``derived.cve_detail`` — one row per CVE, joining the CVE registry, KEV
   catalogues, exploitation observations, EPSS and first-party patch dates.

The rebuild is a pure SQL function (migration 0015) and takes its censoring date as a
parameter, so it is deterministic and replayable. This module only decides *when* to
call it and *what to assert* about the result.
"""
