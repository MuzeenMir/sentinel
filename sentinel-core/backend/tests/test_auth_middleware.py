"""Tests for the shared Flask auth middleware token extraction (SEC-09)."""

from flask import Flask

import auth_middleware

app = Flask(__name__)


def test_extract_token_reads_authorization_header():
    with app.test_request_context(headers={"Authorization": "Bearer abc123"}):
        assert auth_middleware._extract_token() == "abc123"


def test_extract_token_ignores_query_param():
    # SEC-09: a JWT in ?token= leaks via access logs, Referer, and proxy
    # caches. The Authorization header is the only accepted source.
    with app.test_request_context("/?token=leaky-jwt"):
        assert auth_middleware._extract_token() is None


def test_extract_token_returns_none_without_credentials():
    with app.test_request_context("/"):
        assert auth_middleware._extract_token() is None
