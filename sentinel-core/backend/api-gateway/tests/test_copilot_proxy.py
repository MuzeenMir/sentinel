"""The copilot proxy must expose the read-only approval queue over GET.

POST copilot actions (summarize/ask/propose/confirm) already proxy to the
llm-gateway. The auto-triage worker's proposals are listed via GET
/copilot/proposals; the gateway must forward that too, with the same verified
internal identity, so the admin console can render the approval queue.
"""

from types import SimpleNamespace
from unittest.mock import patch

from fastapi.testclient import TestClient


def _client():
    import asgi_app

    return asgi_app, TestClient(asgi_app.asgi)


def test_get_proposals_forwards_to_llm_gateway():
    asgi_app, client = _client()
    upstream = SimpleNamespace(
        status_code=200,
        content=b'{"proposals": [{"alert_id": 7}]}',
        json=lambda: {"proposals": [{"alert_id": 7}]},
    )
    with (
        patch.object(
            asgi_app,
            "require_current_user",
            lambda request: {"id": 1, "tenant_id": 1},
        ),
        patch.object(asgi_app.core, "get_internal_service_token", lambda: "svc-tok"),
        patch.object(asgi_app.requests, "get", return_value=upstream) as mock_get,
    ):
        rv = client.get("/api/v1/copilot/proposals?limit=25")

    assert rv.status_code == 200
    assert rv.json()["proposals"][0]["alert_id"] == 7
    called_url = mock_get.call_args.args[0]
    assert called_url.endswith("/copilot/proposals")
    # verified internal identity is forwarded, never trusted from the client
    headers = mock_get.call_args.kwargs["headers"]
    assert headers["X-Internal-Service-Token"] == "svc-tok"
    assert headers["X-Actor"] == "user:1"


def test_get_proposals_requires_authentication():
    from fastapi.responses import JSONResponse

    asgi_app, client = _client()
    with patch.object(
        asgi_app,
        "require_current_user",
        lambda request: JSONResponse({"error": "unauthorized"}, status_code=401),
    ):
        rv = client.get("/api/v1/copilot/proposals")
    assert rv.status_code == 401


def test_unknown_copilot_get_path_is_404():
    asgi_app, client = _client()
    with patch.object(
        asgi_app, "require_current_user", lambda request: {"id": 1, "tenant_id": 1}
    ):
        rv = client.get("/api/v1/copilot/does-not-exist")
    assert rv.status_code == 404
