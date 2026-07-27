"""Fail-closed HTTP egress validation for controller-side fetches.

Generated-code sandboxes have their own network policy.  This module protects
trusted controller processes that fetch *untrusted* user or model supplied
URLs, such as the knowledge-ingestion service.  It intentionally permits only
public HTTP(S) destinations, resolves every hostname before every request, and
requires every redirect target to pass the same validation.

Application validation is one layer of defence.  Home-lab deployments must
also keep generated-code networking disabled until an egress firewall/proxy
that denies private and management networks has been verified.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

import httpx

_MAX_URL_LENGTH = 4096
_REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})
_BLOCKED_HOSTS = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "metadata",
        "metadata.google.internal",
        "instance-data",
        "instance-data.ec2.internal",
    }
)

Resolver = Callable[[str, int], Awaitable[list[str]]]


class NetworkAccessDenied(ValueError):
    """Raised when an HTTP destination violates the public-egress policy."""


class ResponseTooLarge(NetworkAccessDenied):
    """Raised before an untrusted response can exceed the configured bound."""


@dataclass(frozen=True, slots=True)
class PublicHTTPResponse:
    """Bounded public HTTP response used by ingestion and retrieval code."""

    body: bytes
    final_url: str
    content_type: str
    status_code: int


def _canonical_hostname(hostname: str) -> str:
    """Return a lower-case IDNA hostname without a trailing root dot."""
    try:
        return hostname.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise NetworkAccessDenied("URL hostname is not valid IDNA") from exc


def _is_public_ip(value: str) -> bool:
    """Return whether *value* is a globally routable address.

    ``is_global`` rejects RFC1918, loopback, link-local, CGNAT, documentation,
    multicast, reserved, unspecified, and IPv4-mapped private IPv6 addresses.
    """
    try:
        address = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return False
    return bool(address.is_global)


def _hostname_allowed(hostname: str, allowed_domains: frozenset[str] | None) -> bool:
    if allowed_domains is None:
        return True
    return any(hostname == domain or hostname.endswith(f".{domain}") for domain in allowed_domains)


async def _system_resolver(hostname: str, port: int) -> list[str]:
    loop = asyncio.get_running_loop()
    try:
        records = await loop.run_in_executor(
            None,
            lambda: socket.getaddrinfo(
                hostname,
                port,
                socket.AF_UNSPEC,
                socket.SOCK_STREAM,
            ),
        )
    except socket.gaierror as exc:
        raise NetworkAccessDenied(f"DNS resolution failed for {hostname}") from exc

    addresses = {
        sockaddr[0]
        for _family, _socktype, _proto, _canonname, sockaddr in records
        if sockaddr and isinstance(sockaddr[0], str)
    }
    return sorted(addresses)


async def validate_public_http_url(
    url: str,
    *,
    allowed_domains: set[str] | frozenset[str] | None = None,
    resolver: Resolver | None = None,
) -> str:
    """Validate a public HTTP(S) URL and all of its current DNS answers.

    The function deliberately has no allow-private escape hatch.  Named
    integrations that require home-lab access must use their own bounded
    connector rather than passing through this generic fetch path.
    """
    if not isinstance(url, str) or not url or len(url) > _MAX_URL_LENGTH:
        raise NetworkAccessDenied("URL is empty or exceeds the maximum length")
    if any(ord(character) < 32 or ord(character) == 127 for character in url):
        raise NetworkAccessDenied("URL contains control characters")

    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise NetworkAccessDenied("URL is malformed") from exc

    if parsed.scheme.lower() not in {"http", "https"}:
        raise NetworkAccessDenied("Only HTTP and HTTPS URLs are permitted")
    if parsed.username is not None or parsed.password is not None:
        raise NetworkAccessDenied("Credentials in URLs are forbidden")
    if not parsed.hostname:
        raise NetworkAccessDenied("URL must contain a hostname")

    hostname = _canonical_hostname(parsed.hostname)
    if (
        hostname in _BLOCKED_HOSTS
        or hostname.endswith(".localhost")
        or hostname.endswith(".local")
        or hostname.endswith(".internal")
        or hostname.endswith(".home.arpa")
    ):
        raise NetworkAccessDenied(f"Host is blocked by public-egress policy: {hostname}")

    domains = (
        frozenset(_canonical_hostname(domain) for domain in allowed_domains)
        if allowed_domains is not None
        else None
    )
    if not _hostname_allowed(hostname, domains):
        raise NetworkAccessDenied(f"Host is outside the permitted domain set: {hostname}")

    try:
        literal = ipaddress.ip_address(hostname.split("%", 1)[0])
    except ValueError:
        literal = None

    if literal is not None:
        if not literal.is_global:
            raise NetworkAccessDenied(f"Non-public address is forbidden: {hostname}")
        addresses = [str(literal)]
    else:
        resolve = resolver or _system_resolver
        addresses = await resolve(hostname, port or (443 if parsed.scheme == "https" else 80))
        if not addresses:
            raise NetworkAccessDenied(f"DNS returned no addresses for {hostname}")

    blocked = [address for address in addresses if not _is_public_ip(address)]
    if blocked:
        raise NetworkAccessDenied(f"DNS for {hostname} returned non-public address: {blocked[0]}")
    return url


async def fetch_public_http(
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    timeout_seconds: float = 30.0,
    max_bytes: int = 2_000_000,
    max_redirects: int = 5,
    allowed_domains: set[str] | frozenset[str] | None = None,
    resolver: Resolver | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> PublicHTTPResponse:
    """Fetch a bounded public URL while validating every redirect hop."""
    if max_bytes < 1:
        raise ValueError("max_bytes must be positive")
    if max_redirects < 0 or max_redirects > 10:
        raise ValueError("max_redirects must be between 0 and 10")

    current = url
    visited: set[str] = set()
    async with httpx.AsyncClient(
        timeout=timeout_seconds,
        follow_redirects=False,
        transport=transport,
    ) as client:
        for redirect_count in range(max_redirects + 1):
            await validate_public_http_url(
                current,
                allowed_domains=allowed_domains,
                resolver=resolver,
            )
            if current in visited:
                raise NetworkAccessDenied("Redirect loop detected")
            visited.add(current)

            async with client.stream("GET", current, headers=dict(headers or {})) as response:
                if response.status_code in _REDIRECT_CODES:
                    location = response.headers.get("location")
                    if not location:
                        raise NetworkAccessDenied("Redirect response omitted Location")
                    if redirect_count >= max_redirects:
                        raise NetworkAccessDenied("Maximum redirect count exceeded")
                    current = urljoin(current, location)
                    continue

                response.raise_for_status()
                content_length = response.headers.get("content-length")
                if content_length:
                    try:
                        declared_size = int(content_length)
                    except ValueError:
                        declared_size = 0
                    if declared_size > max_bytes:
                        raise ResponseTooLarge(
                            f"Response declares {declared_size} bytes; limit is {max_bytes}"
                        )

                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > max_bytes:
                        raise ResponseTooLarge(f"Response exceeded {max_bytes} bytes")

                return PublicHTTPResponse(
                    body=bytes(body),
                    final_url=str(response.url),
                    content_type=response.headers.get("content-type", ""),
                    status_code=response.status_code,
                )

    raise NetworkAccessDenied("HTTP fetch ended without a response")


def redact_url_for_log(url: str) -> str:
    """Return a URL safe for structured logs (no query, fragment, credentials)."""
    try:
        parsed = urlsplit(url)
        parsed_port = parsed.port
    except ValueError:
        return "<invalid-url>"
    hostname = parsed.hostname or "<missing-host>"
    port = f":{parsed_port}" if parsed_port is not None else ""
    return f"{parsed.scheme}://{hostname}{port}{parsed.path}"
