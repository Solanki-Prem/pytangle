# SPDX-License-Identifier: MIT
"""Shared test fixtures: a fake session that mimics SafeSession's surface."""

from __future__ import annotations

import pytest


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


class FakeSession:
    """Routes GET/POST by URL substring to canned payloads.

    routes: list of (predicate_or_substring, FakeResponse).
    """

    def __init__(self, get_routes=None, post_routes=None):
        self.get_routes = get_routes or []
        self.post_routes = post_routes or []
        self.closed = False

    def _match(self, routes, url):
        for matcher, resp in routes:
            if callable(matcher) and matcher(url):
                return resp
            if isinstance(matcher, str) and matcher in url:
                return resp
        return FakeResponse(None, status_code=404)

    def get(self, url, **kwargs):
        return self._match(self.get_routes, url)

    def post_json(self, url, payload, **kwargs):
        for matcher, resp in self.post_routes:
            if matcher in url:
                return resp
        return FakeResponse(None, status_code=404)

    def close(self):
        self.closed = True


@pytest.fixture
def fake_response():
    return FakeResponse
