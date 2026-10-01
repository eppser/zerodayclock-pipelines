# Zero Day Clock — data pipelines

The ingestion pipelines behind [zerodayclock.com](https://zerodayclock.com). Each one pulls a
public or licensed source, validates it, and writes it to the site's Postgres database. The
site itself is not in this repository.

This repository is a **read-only mirror**: it is regenerated from the main (private)
repository, so pull requests here cannot be merged. Please open an issue instead.

## Pipelines

| Workflow | Package | What it ingests |
|---|---|---|
| `cve-pipeline.yml` | `zdc_cve` | Every CVE record: CVE Project deltas and NVD |
| `kev-pipeline.yml` | `zdc_kev` | Known-exploited catalogues: CISA KEV, VulnCheck KEV, CIRCL, EUVD |
| `obs-pipeline.yml` | `zdc_obs` | Exploitation observations, including Shadowserver's public honeypot dashboard |
| `enrich-pipeline.yml` | `zdc_enrich` | Derived tables, FIRST EPSS scores, and the eval gate over them |
| `patch-pipeline.yml` | `zdc_patch` | Vendor patch-release dates from first-party advisories |
| `watchdog.yml` | `tools/watchdog.py` | Alerts when any pipeline stops completing on schedule |

`zdc_honeypot`, `zdc_crowdsec` and `zdc_export` are included as code but run from the private
repository, because their inputs are licensed feeds.

Every run executes the unit tests first and records an evaluation report; a failed check
blocks the write.

## Running locally

```sh
cd pipeline
python -m venv .venv && .venv/bin/pip install --require-hashes -r requirements-ci.txt
.venv/bin/python -m pytest -q
DATABASE_URL=postgresql://... .venv/bin/python -m zdc_kev.run --mode incremental --report kev-report.json
```

Optional credentials: `NVD_API_KEY` (higher NVD rate limit), `VULNCHECK_API_TOKEN`.

## Security

Workflows run with a read-only token, pin every action to a commit SHA, install
dependencies by hash, and receive secrets only on `main`. To report a vulnerability, open a
private advisory under the repository's **Security** tab.

## License

Apache License 2.0. See [`LICENSE`](LICENSE). Data retrieved by these pipelines remains
subject to each source's own terms.
