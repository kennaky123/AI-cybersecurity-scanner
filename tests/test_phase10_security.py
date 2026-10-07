import socket

import pytest

from backend.app.services.html_analyzer import HTMLAnalyzer, HTMLFetchError, _resolve_public


@pytest.mark.parametrize("hostname", ["localhost", "metadata.google.internal", "instance-data.ec2.internal"])
def test_ssrf_policy_blocks_local_and_cloud_metadata_hostnames(hostname: str) -> None:
    with pytest.raises(HTMLFetchError, match="blocked"):
        _resolve_public(hostname, 80)


def test_ssrf_policy_blocks_private_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.8", 80))])

    with pytest.raises(HTMLFetchError, match="private"):
        _resolve_public("internal.example", 80)


def test_dns_rebinding_is_rejected_when_resolution_changes(monkeypatch: pytest.MonkeyPatch) -> None:
    results = iter([
        [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))],
        [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.8", 80))],
    ])
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: next(results))

    with pytest.raises(HTMLFetchError, match="private"):
        HTMLAnalyzer.fetch("http://example.test")
