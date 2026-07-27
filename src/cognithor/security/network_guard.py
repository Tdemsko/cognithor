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
import inspect
import ipaddress
import socket
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx

from cognithor.utils.logging import get_logger

log = get_logger(__name__)

_MAX_URL_LENGTH = 4096
_REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})
_ALLOWED_HTTP_METHODS = frozenset({"DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"})
_FORBIDDEN_REQUEST_HEADERS = frozenset(
    {
        "connection",
        "content-length",
        "forwarded",
        "host",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-proto",
        "x-real-ip",
    }
)
_CROSS_ORIGIN_SECRET_HEADERS = frozenset(
    {
        "authorization",
        "cookie",
        "proxy-authenticate",
        "www-authenticate",
    }
)
_LOCAL_BROWSER_SCHEMES = frozenset({"about", "blob", "data"})
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


def _hostname_blocked(hostname: str, blocked_domains: frozenset[str] | None) -> bool:
    if blocked_domains is None:
        return False
    return any(hostname == domain or hostname.endswith(f".{domain}") for domain in blocked_domains)


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
    blocked_domains: set[str] | frozenset[str] | None = None,
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
    denied_domains = (
        frozenset(_canonical_hostname(domain) for domain in blocked_domains)
        if blocked_domains is not None
        else None
    )
    if _hostname_blocked(hostname, denied_domains):
        raise NetworkAccessDenied(f"Host is denied by the domain policy: {hostname}")

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

    blocked_addresses = [address for address in addresses if not _is_public_ip(address)]
    if blocked_addresses:
        raise NetworkAccessDenied(
            f"DNS for {hostname} returned non-public address: {blocked_addresses[0]}"
        )
    return url


def _origin(url: str) -> tuple[str, str, int]:
    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()
    hostname = _canonical_hostname(parsed.hostname or "")
    return scheme, hostname, parsed.port or (443 if scheme == "https" else 80)


def _validated_request_headers(headers: Mapping[str, str] | None) -> dict[str, str]:
    """Reject request-smuggling and virtual-host override headers."""
    clean: dict[str, str] = {}
    for raw_name, raw_value in (headers or {}).items():
        name = str(raw_name).strip()
        value = str(raw_value)
        lower_name = name.lower()
        if not name or lower_name in _FORBIDDEN_REQUEST_HEADERS:
            raise NetworkAccessDenied(f"Request header is forbidden: {name or '<empty>'}")
        if any(ord(character) < 32 and character != "\t" for character in name + value):
            raise NetworkAccessDenied("Request headers contain control characters")
        if "\r" in value or "\n" in value:
            raise NetworkAccessDenied("Request headers contain a line break")
        clean[name] = value
    return clean


def _strip_cross_origin_secrets(headers: Mapping[str, str]) -> dict[str, str]:
    return {
        name: value
        for name, value in headers.items()
        if name.lower() not in _CROSS_ORIGIN_SECRET_HEADERS
    }


async def request_public_http(
    url: str,
    *,
    method: str = "GET",
    headers: Mapping[str, str] | None = None,
    body: str | bytes | None = None,
    timeout_seconds: float = 30.0,
    max_bytes: int = 2_000_000,
    max_redirects: int = 5,
    raise_for_status: bool = True,
    allowed_domains: set[str] | frozenset[str] | None = None,
    blocked_domains: set[str] | frozenset[str] | None = None,
    resolver: Resolver | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> PublicHTTPResponse:
    """Issue a bounded public HTTP request and validate every redirect hop.

    Redirects are handled here instead of by the HTTP library so a public URL
    cannot redirect to a router, NAS, metadata service, or control-plane host.
    Cross-origin redirects cannot carry authorization or cookie headers.
    """
    if max_bytes < 1:
        raise ValueError("max_bytes must be positive")
    if max_redirects < 0 or max_redirects > 10:
        raise ValueError("max_redirects must be between 0 and 10")

    current_method = method.upper()
    if current_method not in _ALLOWED_HTTP_METHODS:
        raise NetworkAccessDenied("HTTP method is not permitted")
    current_headers = _validated_request_headers(headers)
    current_body = body
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
                blocked_domains=blocked_domains,
                resolver=resolver,
            )
            if current in visited:
                raise NetworkAccessDenied("Redirect loop detected")
            visited.add(current)

            async with client.stream(
                current_method,
                current,
                headers=current_headers,
                content=current_body,
            ) as response:
                if response.status_code in _REDIRECT_CODES:
                    location = response.headers.get("location")
                    if not location:
                        raise NetworkAccessDenied("Redirect response omitted Location")
                    if redirect_count >= max_redirects:
                        raise NetworkAccessDenied("Maximum redirect count exceeded")
                    next_url = urljoin(current, location)
                    current_origin = _origin(current)
                    next_origin = _origin(next_url)
                    if current_origin[0] == "https" and next_origin[0] != "https":
                        raise NetworkAccessDenied("HTTPS redirects may not downgrade transport")
                    if next_origin != current_origin:
                        if current_body is not None or current_method not in {"GET", "HEAD"}:
                            raise NetworkAccessDenied(
                                "Cross-origin redirects may not replay a request body or "
                                "side-effecting method"
                            )
                        current_headers = _strip_cross_origin_secrets(current_headers)
                    if response.status_code == 303 or (
                        response.status_code in {301, 302} and current_method not in {"GET", "HEAD"}
                    ):
                        current_method = "GET"
                        current_body = None
                    current = next_url
                    continue

                if raise_for_status:
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

                response_body = bytearray()
                async for chunk in response.aiter_bytes():
                    response_body.extend(chunk)
                    if len(response_body) > max_bytes:
                        raise ResponseTooLarge(f"Response exceeded {max_bytes} bytes")

                return PublicHTTPResponse(
                    body=bytes(response_body),
                    final_url=str(response.url),
                    content_type=response.headers.get("content-type", ""),
                    status_code=response.status_code,
                )

    raise NetworkAccessDenied("HTTP fetch ended without a response")


async def fetch_public_http(
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    timeout_seconds: float = 30.0,
    max_bytes: int = 2_000_000,
    max_redirects: int = 5,
    allowed_domains: set[str] | frozenset[str] | None = None,
    blocked_domains: set[str] | frozenset[str] | None = None,
    resolver: Resolver | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> PublicHTTPResponse:
    """Fetch a bounded public URL while validating every redirect hop."""
    return await request_public_http(
        url,
        headers=headers,
        timeout_seconds=timeout_seconds,
        max_bytes=max_bytes,
        max_redirects=max_redirects,
        allowed_domains=allowed_domains,
        blocked_domains=blocked_domains,
        resolver=resolver,
        transport=transport,
    )


async def validate_browser_network_url(
    url: str,
    *,
    resolver: Resolver | None = None,
) -> str:
    """Validate an HTTP(S)/WebSocket browser request.

    WebSocket URLs use the same destination rules as HTTP. Local browser-only
    schemes are allowed for document internals; filesystem, extension, FTP,
    and custom protocols are rejected.
    """
    try:
        parsed = urlsplit(url)
    except ValueError as exc:
        raise NetworkAccessDenied("Browser URL is malformed") from exc
    scheme = parsed.scheme.lower()
    if scheme in _LOCAL_BROWSER_SCHEMES:
        return url
    if scheme in {"ws", "wss"}:
        equivalent = parsed._replace(scheme="https" if scheme == "wss" else "http").geturl()
        await validate_public_http_url(equivalent, resolver=resolver)
        return url
    return await validate_public_http_url(url, resolver=resolver)


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


async def install_playwright_public_egress_guard(
    context: Any,
    *,
    resolver: Resolver | None = None,
) -> None:
    """Install fail-closed HTTP and WebSocket interception on a context.

    The caller must create the context with ``service_workers="block"``.
    Playwright before 1.48 cannot intercept WebSockets, so it is rejected
    rather than silently leaving a private-network bypass.
    """
    route = getattr(context, "route", None)
    route_web_socket = getattr(context, "route_web_socket", None)
    if not callable(route) or not callable(route_web_socket):
        raise NetworkAccessDenied("Playwright >=1.48 request and WebSocket routing are required")

    async def guard_http(playwright_route: Any, request: Any) -> None:
        request_url = str(getattr(request, "url", "") or "")
        try:
            await validate_browser_network_url(request_url, resolver=resolver)
        except Exception as exc:
            log.warning(
                "browser_public_egress_blocked",
                url=redact_url_for_log(request_url),
                reason=type(exc).__name__,
            )
            await _maybe_await(playwright_route.abort("blockedbyclient"))
            return
        await _maybe_await(playwright_route.continue_())

    async def guard_web_socket(web_socket_route: Any) -> None:
        socket_url = str(getattr(web_socket_route, "url", "") or "")
        try:
            await validate_browser_network_url(socket_url, resolver=resolver)
        except Exception as exc:
            log.warning(
                "browser_websocket_egress_blocked",
                url=redact_url_for_log(socket_url),
                reason=type(exc).__name__,
            )
            await _maybe_await(
                web_socket_route.close(code=1008, reason="Public egress policy denied destination")
            )
            return
        await _maybe_await(web_socket_route.connect_to_server())

    await _maybe_await(route("**/*", guard_http))
    await _maybe_await(route_web_socket("**/*", guard_web_socket))


def redact_url_for_log(url: str) -> str:
    """Return a URL safe for structured logs (no query, fragment, credentials)."""
    try:
        parsed = urlsplit(url)
        parsed_port = parsed.port
    except ValueError:
        return "<invalid-url>"
    hostname = parsed.hostname or "<missing-host>"
    port = f":{parsed_port}" if parsed_port is not None else ""
    # Paths can contain opaque credentials and reset tokens. The origin is
    # sufficient to diagnose a denied destination without retaining them.
    return f"{parsed.scheme}://{hostname}{port}"
