import importlib


def _load_net(monkeypatch):
    monkeypatch.delenv("SENTINEL_BIND_HOST", raising=False)
    monkeypatch.delenv("SENTINEL_BIND_PUBLIC", raising=False)
    import _lib.net as net

    return importlib.reload(net)


def test_bind_host_defaults_to_loopback(monkeypatch):
    net = _load_net(monkeypatch)

    assert net.bind_host() == "127.0.0.1"


def test_bind_host_public_override_binds_all_interfaces(monkeypatch):
    net = _load_net(monkeypatch)
    monkeypatch.setenv("SENTINEL_BIND_PUBLIC", "1")

    assert net.bind_host() == "0.0.0.0"


def test_bind_host_env_override(monkeypatch):
    net = _load_net(monkeypatch)
    monkeypatch.setenv("SENTINEL_BIND_HOST", "10.0.0.5")

    assert net.bind_host() == "10.0.0.5"
