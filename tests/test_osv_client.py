"""The shared OSV client: answers, pagination, and failures that are never empty."""

import io
import json
import urllib.error

import pytest

from traust_engine.osv import OsvClient, Query, base_score, normalize_base_url


class FakeOpener:
    """Routes requests to canned responses: a dict, an HTTP status, or an exception."""

    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def __call__(self, req, timeout=None):
        body = json.loads(req.data) if req.data else None
        self.calls.append((req.full_url, body))
        handler = self.routes[req.full_url.rsplit("/v1/", 1)[1].split("/")[0]]
        reply = handler(body, req.full_url) if callable(handler) else handler
        if isinstance(reply, Exception):
            raise reply
        if isinstance(reply, int):
            raise urllib.error.HTTPError(req.full_url, reply, "err", {}, None)
        return io.BytesIO(json.dumps(reply).encode())


def client(routes, **kw):
    return OsvClient("https://osv.test/v1", opener=FakeOpener(routes), sleep=lambda s: None, **kw)


Q1 = Query("PyPI", "requests", "2.19.0")
Q2 = Query("npm", "lodash", "4.17.15")


def test_normalize_base_url():
    assert normalize_base_url("https://api.osv.dev/v1/query") == "https://api.osv.dev/v1"
    assert normalize_base_url("https://api.osv.dev/v1/querybatch/") == "https://api.osv.dev/v1"
    assert normalize_base_url(None) == "https://api.osv.dev/v1"


def test_batch_ids_align_with_queries():
    c = client({"querybatch": {"results": [{"vulns": [{"id": "GHSA-1"}]}, {}]}})
    out = c.query_batch([Q1, Q2])
    assert out.ids == [["GHSA-1"], []]
    assert out.complete


def test_pages_are_followed():
    pages = {"querybatch": {"results": [{"vulns": [{"id": "A"}], "next_page_token": "t1"}]}}
    pages["query"] = lambda body, url: (
        {"vulns": [{"id": "B"}], "next_page_token": "t2"}
        if body["page_token"] == "t1"
        else {"vulns": [{"id": "C"}]}
    )
    assert client(pages).query_batch([Q1]).ids == [["A", "B", "C"]]


@pytest.mark.parametrize(
    ("reply", "status"),
    [
        (429, "quota-deferred"),
        (503, "unreachable"),
        (urllib.error.URLError("down"), "unreachable"),
        (TimeoutError(), "unreachable"),
        (400, "error"),
        ({"results": []}, "error"),  # wrong number of results
    ],
)
def test_a_failed_batch_is_none_and_counted_never_empty(reply, status):
    out = client({"querybatch": reply}).query_batch([Q1, Q2])
    assert out.ids == [None, None]
    assert out.issues == {status: 2}
    assert not out.complete


def test_retries_before_giving_up():
    attempts = []
    c = client({"querybatch": lambda b, u: attempts.append(1) or 503}, retries=3)
    c.query_batch([Q1])
    assert len(attempts) == 3


def test_a_client_error_is_not_retried():
    attempts = []
    client({"querybatch": lambda b, u: attempts.append(1) or 404}, retries=3).query_batch([Q1])
    assert len(attempts) == 1


def test_a_failed_page_leaves_that_query_unanswered():
    routes = {
        "querybatch": {"results": [{"vulns": [{"id": "A"}], "next_page_token": "t"}, {}]},
        "query": 503,
    }
    out = client(routes).query_batch([Q1, Q2])
    assert out.ids == [None, []]
    assert out.issues == {"unreachable": 1}


def test_get_vulns_counts_failures():
    routes = {"vulns": lambda b, url: {"id": "OK"} if url.endswith("/OK") else 503}
    found, issues = client(routes).get_vulns(["OK", "BAD", "OK"])
    assert list(found) == ["OK"]
    assert issues == {"unreachable": 1}


@pytest.mark.parametrize(
    ("vector", "score"),
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        ("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", None),
        ("AV:N/AC:L/Au:N/C:P/I:P/A:P", None),
        ("CVSS:3.1/AV:X", None),
    ],
)
def test_cvss_v3_base_score(vector, score):
    assert base_score(vector) == score


def test_probe_reports_why_the_api_cannot_be_used():
    assert client({"query": {}}).probe(Q1) is None
    status, detail = client({"query": urllib.error.URLError("down")}).probe(Q1)
    assert status == "unreachable" and "osv.test" in detail
    assert client({"query": 429}).probe(Q1)[0] == "quota-deferred"
