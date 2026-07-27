"""Security contracts for controller-side untrusted HTTP ingestion."""

from __future__ import annotations

import httpx
import pytest

from cognithor.learning.knowledge_ingest import _is_youtube_url
from cognithor.security.network_guard import (
    NetworkAccessDenied,
    ResponseTooLarge,
    fetch_public_http,
    redact_url_for_log,
    validate_public_http_url,
)


def _resolver(*addresses: str):
    async def resolve(_host: str, _port: int) -> list[str]:
        return list(addresses)

    return resolve


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "gopher://127.0.0.1/",
        "http://user:secret@example.com/",
        "http://localhost/admin",
        "http://service.local/",
        "http://router.home.arpa/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://127.0.0.1/",
        "http://10.0.0.1/",
        "http://172.16.0.1/",
        "http://192.168.50.226:8006/",
        "http://169.254.169.254/latest/meta-data/",
        "http://100.64.0.1/",
        "http://[::1]/",
        "http://[fc00::1]/",
        "http://[fe80::1%25en0]/",
        "http://[::ffff:10.0.0.1]/",
    ],
)
async def test_private_and_non_http_destinations_fail_closed(url: str) -> None:
    with pytest.raises(NetworkAccessDenied):
        await validate_public_http_url(url)


@pytest.mark.asyncio
async def test_hostname_resolving_to_any_private_address_fails_closed() -> None:
    with pytest.raises(NetworkAccessDenied, match="non-public"):
        await validate_public_http_url(
            "https://public-looking.example/data",
            resolver=_resolver("93.184.216.34", "192.168.50.226"),
        )


@pytest.mark.asyncio
async def test_public_destination_and_domain_constraint_pass() -> None:
    url = "https://www.youtube.com/watch?v=dQw4w9WgXcQ"
    assert (
        await validate_public_http_url(
            url,
            allowed_domains={"youtube.com"},
            resolver=_resolver("142.250.191.110"),
        )
        == url
    )


@pytest.mark.asyncio
async def test_domain_constraint_rejects_suffix_confusion() -> None:
    with pytest.raises(NetworkAccessDenied, match="domain set"):
        await validate_public_http_url(
            "https://youtube.com.attacker.example/watch",
            allowed_domains={"youtube.com"},
            resolver=_resolver("93.184.216.34"),
        )


@pytest.mark.asyncio
async def test_private_redirect_is_rejected_before_second_request() -> None:
    requested: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requested.append(str(request.url))
        return httpx.Response(302, headers={"location": "http://192.168.50.226:8006/"})

    with pytest.raises(NetworkAccessDenied):
        await fetch_public_http(
            "https://example.com/start",
            resolver=_resolver("93.184.216.34"),
            transport=httpx.MockTransport(handler),
        )
    assert requested == ["https://example.com/start"]


@pytest.mark.asyncio
async def test_every_public_redirect_is_revalidated() -> None:
    resolutions: list[str] = []

    async def resolver(host: str, _port: int) -> list[str]:
        resolutions.append(host)
        return ["93.184.216.34"]

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/start":
            return httpx.Response(302, headers={"location": "https://cdn.example.net/final"})
        return httpx.Response(200, content=b"safe", headers={"content-type": "text/plain"})

    response = await fetch_public_http(
        "https://example.com/start",
        resolver=resolver,
        transport=httpx.MockTransport(handler),
    )
    assert response.body == b"safe"
    assert response.final_url == "https://cdn.example.net/final"
    assert resolutions == ["example.com", "cdn.example.net"]


@pytest.mark.asyncio
async def test_response_size_is_bounded_by_header_and_stream() -> None:
    async def declared_handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"x", headers={"content-length": "1000"})

    with pytest.raises(ResponseTooLarge):
        await fetch_public_http(
            "https://example.com/",
            max_bytes=10,
            resolver=_resolver("93.184.216.34"),
            transport=httpx.MockTransport(declared_handler),
        )

    async def streamed_handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"x" * 11)

    with pytest.raises(ResponseTooLarge):
        await fetch_public_http(
            "https://example.com/",
            max_bytes=10,
            resolver=_resolver("93.184.216.34"),
            transport=httpx.MockTransport(streamed_handler),
        )


def test_url_logging_redacts_credentials_query_and_fragment() -> None:
    assert (
        redact_url_for_log("https://user:secret@example.com/path?token=secret#fragment")
        == "https://example.com/path"
    )


def test_url_logging_handles_malformed_port_without_leaking_query() -> None:
    assert redact_url_for_log("https://example.com:not-a-port/path?token=secret") == "<invalid-url>"


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://youtube.com/watch?v=123", True),
        ("https://www.youtube.com/watch?v=123", True),
        ("https://youtu.be/dQw4w9WgXcQ", True),
        ("https://youtube.com.attacker.example/watch?v=123", False),
        ("https://attacker.example/?next=youtube.com", False),
        ("file://youtube.com/etc/passwd", False),
    ],
)
def test_youtube_detection_uses_parsed_hostname(url: str, expected: bool) -> None:
    assert _is_youtube_url(url) is expected
