import io
import json
import urllib.error

import pytest

from malview import vt_client

SHA = "a" * 64


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.fixture
def captured(monkeypatch):
    """Replace urlopen; record requests so tests can assert what was sent."""
    calls = []

    def install(handler):
        def fake_urlopen(req, timeout=None):
            calls.append(req)
            return handler(req)
        monkeypatch.setattr(vt_client.urllib.request, "urlopen", fake_urlopen)
        return calls
    return install


def test_missing_key_makes_no_request(captured):
    calls = captured(lambda req: pytest.fail("should not be called"))
    result = vt_client.fetch_vt_report(SHA)
    assert result.status == "missing_key"
    assert calls == []


@pytest.mark.parametrize("bad", ["", "abc", "g" * 64, SHA + "/../../users/me", "a" * 63])
def test_rejects_non_sha256(monkeypatch, captured, bad):
    monkeypatch.setenv("VT_API_KEY", "secret-key")
    calls = captured(lambda req: pytest.fail("should not be called"))
    result = vt_client.fetch_vt_report(bad)
    assert result.status == "error"
    assert calls == []


def test_not_found(monkeypatch, captured):
    monkeypatch.setenv("VT_API_KEY", "secret-key")

    def handler(req):
        raise urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, None)
    captured(handler)
    assert vt_client.fetch_vt_report(SHA).status == "not_found"


def test_ok_is_a_hash_lookup_only(monkeypatch, captured):
    monkeypatch.setenv("VT_API_KEY", "secret-key")
    body = {"data": {"attributes": {
        "last_analysis_stats": {"malicious": 5, "suspicious": 1, "harmless": 2, "undetected": 60},
        "reputation": -12,
        "tags": ["peexe"],
    }}}
    calls = captured(lambda req: _Resp(json.dumps(body).encode()))

    result = vt_client.fetch_vt_report(SHA.upper())
    assert result.status == "ok"
    assert (result.report.malicious, result.report.undetected) == (5, 60)
    assert result.report.reputation == -12
    assert result.report.tags == ["peexe"]

    (req,) = calls
    assert req.get_method() == "GET"          # never an upload
    assert req.data is None
    assert req.full_url == f"https://www.virustotal.com/api/v3/files/{SHA}"
    assert req.get_header("X-apikey") == "secret-key"


def test_errors_do_not_echo_key(monkeypatch, captured):
    monkeypatch.setenv("VT_API_KEY", "secret-key")

    def handler(req):
        raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", {}, None)
    captured(handler)
    result = vt_client.fetch_vt_report(SHA)
    assert result.status == "error"
    assert "secret-key" not in (result.message or "")
