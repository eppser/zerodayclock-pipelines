"""Public data export.

The contract this serves says a reviewer must be able to check the arithmetic
without database access. Two properties make that true rather than nominal: the
export is byte-identical for an unchanged database (so a diff means the numbers
moved, not that the file was rewritten), and the manifest describes exactly what
was written (so the thing a reviewer trusts is the thing on disk).
"""

from __future__ import annotations

import gzip
import hashlib
import json

import pytest

from zdc_export import run as export_run


class _Cursor:
    def __init__(self, conn):
        self.conn = conn

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        self.conn.last_sql = sql
        if "count(distinct" in sql:
            self._row = self.conn.counts
        elif "method_registry" in sql:
            self._rows = list(self.conn.registry.items())
        elif "censored_at" in sql:
            self._row = ("2026-09-01",)
        else:
            self._row = (0,)

    def fetchone(self):
        return self._row

    def fetchall(self):
        return self._rows

    def copy(self, sql):
        payload = self.conn.csv
        class _CM:
            def __enter__(self_inner):
                return [payload]
            def __exit__(self_inner, *a):
                return False
        return _CM()


class FakeConn:
    def __init__(self, csv=b"a,b\n1,2\n", counts=(1, 1), registry=None):
        self.csv = csv
        self.counts = counts
        self.registry = registry or {"cve_detail": "v3"}

    def cursor(self):
        return _Cursor(self)


class TestDeterminism:
    def test_gzip_is_byte_identical_across_calls(self):
        # gzip stores the source mtime by default, so the same bytes compress to
        # different files each run and every export looks changed. mtime=0 pins it.
        a = export_run._gzip(b"hello world")
        b = export_run._gzip(b"hello world")
        assert a == b

    def test_gzip_roundtrips(self):
        assert gzip.decompress(export_run._gzip(b"x,y\n1,2\n")) == b"x,y\n1,2\n"

    def test_the_check_can_fail_different_input_differs(self):
        assert export_run._gzip(b"a") != export_run._gzip(b"b")


class TestSortKeyIsVerified:
    def test_accepts_a_unique_key(self):
        conn = FakeConn(counts=(100, 100))
        export_run._assert_key_is_unique(conn, "cve_detail", "cve_id")   # no raise

    def test_REJECTS_a_key_with_ties(self):
        # The real case: scan_pressure's key was (vuln_id, window_days), which has
        # 6,307 duplicates across 7,379 rows. Ties make the row order arbitrary.
        conn = FakeConn(counts=(7379, 1072))
        with pytest.raises(SystemExit) as e:
            export_run._assert_key_is_unique(conn, "scan_pressure", "vuln_id, window_days")
        assert "6307 duplicate" in str(e.value)


class TestManifest:
    def test_manifest_matches_the_files_on_disk(self, tmp_path):
        conn = FakeConn(csv=b"cve_id,x\nCVE-2026-1,1\n", counts=(1, 1))
        m = export_run.export(conn, tmp_path, only=["cve_detail"])
        assert len(m["files"]) == 1
        f = m["files"][0]
        blob = (tmp_path / f["file"]).read_bytes()
        assert hashlib.sha256(blob).hexdigest() == f["sha256"]
        assert f["rows"] == 1                       # header excluded
        assert m["censoring_date"] == "2026-09-01"
        assert m["method_versions"] == {"cve_detail": "v3"}

    def test_manifest_is_valid_json_on_disk(self, tmp_path):
        conn = FakeConn(counts=(1, 1))
        export_run.export(conn, tmp_path, only=["cve_detail"])
        json.loads((tmp_path / "manifest.json").read_text())

    def test_unknown_view_is_refused(self, tmp_path):
        with pytest.raises(SystemExit):
            export_run.export(FakeConn(), tmp_path, only=["not_a_view"])

    def test_every_declared_export_has_a_sort_key(self):
        for view, key in export_run.EXPORTS:
            assert key and key.strip(), f"{view} has no sort key"
