"""Tests for the two defects the first live run exposed."""

from __future__ import annotations

from zdc_kev.http import redact_url


class TestRedactUrl:
    """A presigned S3 URL carries live AWS credentials in its query string.

    Recording it verbatim would write them into raw.source_fetches and print them to
    the CI log on every run.
    """

    def test_strips_aws_presigned_credentials(self):
        url = (
            "https://bucket.s3.amazonaws.com/kev.zip"
            "?X-Amz-Algorithm=AWS4-ECDSA-P256-SHA256"
            "&X-Amz-Credential=ASIAIOSFODNN7EXAMPLE%2F20260827%2Fs3"
            "&X-Amz-Security-Token=EXAMPLE-SESSION-TOKEN"
            "&X-Amz-Signature=0000example0signature0000"
            "&x-id=GetObject"
        )
        redacted = redact_url(url)
        for secret in ("ASIAIOSFODNN7EXAMPLE", "EXAMPLE-SESSION", "example0signature"):
            assert secret not in redacted
        # Non-secret parameters survive, so the record still identifies the request.
        assert "x-id=GetObject" in redacted
        assert redacted.startswith("https://bucket.s3.amazonaws.com/kev.zip")

    def test_strips_bare_token_and_key_params(self):
        assert "s3cr3t" not in redact_url("https://api.test/v1?token=s3cr3t&page=2")
        assert "abc123" not in redact_url("https://api.test/v1?apiKey=abc123")
        assert "page=2" in redact_url("https://api.test/v1?token=s3cr3t&page=2")

    def test_leaves_ordinary_urls_untouched(self):
        url = "https://euvdservices.enisa.europa.eu/api/search?exploited=true&page=0"
        assert redact_url(url) == url

    def test_handles_url_without_query(self):
        url = "https://www.cisa.gov/feeds/known_exploited_vulnerabilities.json"
        assert redact_url(url) == url


class TestPresignedFetchDropsAuth:
    def test_archive_request_sets_no_auth(self):
        """S3 returns HTTP 400 if a bearer token accompanies a presigned URL:
        "Only one auth mechanism allowed". Caught only by a live run."""
        import io
        import json
        import zipfile

        from conftest import StubClient, make_fetch
        from zdc_kev.sources.base import SourceState
        from zdc_kev.sources.vulncheck import VulnCheckKev

        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("kev.json", json.dumps([{"cve": ["CVE-2024-0001"]}]))

        client = StubClient(
            [
                make_fetch("vulncheck", json.dumps({"data": [{"url": "https://signed.test/kev.zip"}]}).encode()),
                make_fetch("vulncheck", buffer.getvalue()),
            ]
        )
        VulnCheckKev(token="t").collect(client, SourceState(), "full")

        assert client.calls[0]["no_auth"] is False   # the API call keeps the bearer token
        assert client.calls[1]["no_auth"] is True    # the presigned download must not
