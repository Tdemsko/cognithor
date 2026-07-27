"""Thomas AI generic web/browser public-egress security contracts."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from cognithor.browser.agent import BrowserAgent
from cognithor.mcp.browser import BrowserTool
from cognithor.mcp.web import WebError, WebTools
from cognithor.models import PlannedAction
from cognithor.security.home_lab import ActionRiskClass, action_risk_class, safe_mode_allows
from cognithor.security.network_guard import (
    NetworkAccessDenied,
    ResponseTooLarge,
    install_playwright_public_egress_guard,
    redact_url_for_log,
    request_public_http,
)

pytestmark = pytest.mark.security_contract

_PUBLIC_IP = "93.184.216.34"


async def _public_resolver(_hostname: str, _port: int) -> list[str]:
    return [_PUBLIC_IP]


async def _mixed_resolver(hostname: str, _port: int) -> list[str]:
    if hostname in {"private.test", "metadata.test"}:
        return ["192.168.50.1"]
    return [_PUBLIC_IP]


@pytest.mark.asyncio
async def test_public_redirect_to_private_is_blocked_before_second_request() -> None:
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(str(request.url))
        return httpx.Response(302, headers={"location": "https://private.test/admin"})

    with pytest.raises(NetworkAccessDenied, match="non-public"):
        await request_public_http(
            "https://public.test/start",
            resolver=_mixed_resolver,
            transport=httpx.MockTransport(handler),
        )

    assert requested == ["https://public.test/start"]


@pytest.mark.asyncio
async def test_cross_origin_redirect_drops_authorization_and_cookie() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.host == "one.test":
            return httpx.Response(302, headers={"location": "https://two.test/final"})
        return httpx.Response(200, content=b"ok")

    response = await request_public_http(
        "https://one.test/start",
        headers={
            "Authorization": "Bearer do-not-forward",
            "Cookie": "session=do-not-forward",
            "X-Trace": "safe",
        },
        resolver=_public_resolver,
        transport=httpx.MockTransport(handler),
    )

    assert response.body == b"ok"
    assert len(requests) == 2
    assert requests[0].headers["authorization"] == "Bearer do-not-forward"
    assert "authorization" not in requests[1].headers
    assert "cookie" not in requests[1].headers
    assert requests[1].headers["x-trace"] == "safe"


@pytest.mark.asyncio
async def test_cross_origin_redirect_cannot_replay_body_or_side_effect() -> None:
    requested: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(request)
        return httpx.Response(307, headers={"location": "https://other.test/collect"})

    with pytest.raises(NetworkAccessDenied, match="Cross-origin"):
        await request_public_http(
            "https://public.test/submit",
            method="POST",
            body="secret-bearing-payload",
            resolver=_public_resolver,
            transport=httpx.MockTransport(handler),
        )

    assert len(requested) == 1


@pytest.mark.asyncio
async def test_https_redirect_cannot_downgrade_transport() -> None:
    transport = httpx.MockTransport(
        lambda _request: httpx.Response(
            302,
            headers={"location": "http://public.test/plaintext"},
        )
    )
    with pytest.raises(NetworkAccessDenied, match="downgrade"):
        await request_public_http(
            "https://public.test/start",
            resolver=_public_resolver,
            transport=transport,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["CONNECT", "TRACE", "INVALID-METHOD"])
async def test_proxy_and_diagnostic_http_methods_are_rejected(method: str) -> None:
    with pytest.raises(NetworkAccessDenied, match="method"):
        await request_public_http(
            "https://public.test/",
            method=method,
            resolver=_public_resolver,
            transport=httpx.MockTransport(lambda _request: httpx.Response(200)),
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "headers",
    [
        {"Host": "router.home"},
        {"X-Forwarded-Host": "nas.home"},
        {"Connection": "upgrade"},
        {"X-Test": "safe\r\nHost: router.home"},
    ],
)
async def test_virtual_host_and_header_smuggling_are_rejected(
    headers: dict[str, str],
) -> None:
    with pytest.raises(NetworkAccessDenied):
        await request_public_http(
            "https://public.test/",
            headers=headers,
            resolver=_public_resolver,
            transport=httpx.MockTransport(lambda _request: httpx.Response(200)),
        )


@pytest.mark.asyncio
async def test_redirect_method_semantics_do_not_replay_post_on_302() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if len(requests) == 1:
            return httpx.Response(302, headers={"location": "/done"})
        return httpx.Response(200, content=b"ok")

    await request_public_http(
        "https://public.test/start",
        method="POST",
        body="side-effect",
        resolver=_public_resolver,
        transport=httpx.MockTransport(handler),
    )

    assert [request.method for request in requests] == ["POST", "GET"]
    assert requests[1].content == b""


@pytest.mark.asyncio
async def test_bounded_public_request_rejects_declared_and_streamed_oversize() -> None:
    declared = httpx.MockTransport(
        lambda _request: httpx.Response(
            200,
            headers={"content-length": "5000"},
            content=b"x",
        )
    )
    with pytest.raises(ResponseTooLarge):
        await request_public_http(
            "https://public.test/",
            max_bytes=100,
            resolver=_public_resolver,
            transport=declared,
        )

    streamed = httpx.MockTransport(lambda _request: httpx.Response(200, content=b"x" * 101))
    with pytest.raises(ResponseTooLarge):
        await request_public_http(
            "https://public.test/",
            max_bytes=100,
            resolver=_public_resolver,
            transport=streamed,
        )


@pytest.mark.asyncio
async def test_web_fetch_redirect_to_private_fails_closed() -> None:
    web = WebTools()
    web._dns_cache.set("public.test", [_PUBLIC_IP])
    web._network_resolver = _mixed_resolver
    web._network_transport = httpx.MockTransport(
        lambda _request: httpx.Response(
            302,
            headers={"location": "http://private.test/router"},
        )
    )

    with pytest.raises(WebError, match="Fetch fehlgeschlagen"):
        await web.web_fetch(
            "https://public.test/start",
            reader_mode="trafilatura",
        )


@pytest.mark.asyncio
async def test_http_request_response_is_bounded_before_model_rendering() -> None:
    web = WebTools()
    web._dns_cache.set("public.test", [_PUBLIC_IP])
    web._network_resolver = _public_resolver
    web._network_transport = httpx.MockTransport(
        lambda _request: httpx.Response(200, content=b"x" * 1025)
    )
    web._http_request_max_body = 1024
    web._http_request_rate_limit = 0

    with pytest.raises(WebError, match="Request fehlgeschlagen"):
        await web.http_request("https://public.test/data")


class _FakeRoute:
    def __init__(self) -> None:
        self.aborted = False
        self.continued = False

    async def abort(self, _reason: str) -> None:
        self.aborted = True

    async def continue_(self) -> None:
        self.continued = True


class _FakeRequest:
    def __init__(self, url: str) -> None:
        self.url = url


class _FakeWebSocketRoute:
    def __init__(self, url: str) -> None:
        self.url = url
        self.closed = False
        self.connected = False

    async def close(self, **_kwargs: Any) -> None:
        self.closed = True

    def connect_to_server(self) -> object:
        self.connected = True
        return object()


class _FakeContext:
    def __init__(self) -> None:
        self.http_handler: Any = None
        self.web_socket_handler: Any = None

    async def route(self, pattern: str, handler: Any) -> None:
        assert pattern == "**/*"
        self.http_handler = handler

    async def route_web_socket(self, pattern: str, handler: Any) -> None:
        assert pattern == "**/*"
        self.web_socket_handler = handler


@pytest.mark.asyncio
async def test_playwright_guard_blocks_private_http_and_websocket() -> None:
    context = _FakeContext()
    await install_playwright_public_egress_guard(
        context,
        resolver=_mixed_resolver,
    )

    public_route = _FakeRoute()
    await context.http_handler(public_route, _FakeRequest("https://public.test/app.js"))
    assert public_route.continued and not public_route.aborted

    private_route = _FakeRoute()
    await context.http_handler(private_route, _FakeRequest("http://private.test/api"))
    assert private_route.aborted and not private_route.continued

    public_socket = _FakeWebSocketRoute("wss://public.test/events")
    await context.web_socket_handler(public_socket)
    assert public_socket.connected and not public_socket.closed

    private_socket = _FakeWebSocketRoute("ws://private.test/events")
    await context.web_socket_handler(private_socket)
    assert private_socket.closed and not private_socket.connected


@pytest.mark.asyncio
async def test_playwright_guard_requires_websocket_interception() -> None:
    context = MagicMock(spec=["route"])
    context.route = AsyncMock()
    with pytest.raises(NetworkAccessDenied, match="WebSocket"):
        await install_playwright_public_egress_guard(context)


@pytest.mark.asyncio
async def test_basic_browser_installs_guard_before_first_page(tmp_path: Any) -> None:
    tool = BrowserTool(workspace_dir=tmp_path)
    context = AsyncMock()
    context.route = AsyncMock()
    context.route_web_socket = AsyncMock()
    context.new_page = AsyncMock(return_value=AsyncMock())
    browser = AsyncMock()
    browser.new_context = AsyncMock(return_value=context)
    playwright = AsyncMock()
    playwright.chromium.launch = AsyncMock(return_value=browser)

    tool._playwright_factory = MagicMock(
        return_value=MagicMock(start=AsyncMock(return_value=playwright))
    )
    assert await tool.initialize()

    context.route.assert_awaited_once()
    context.route_web_socket.assert_awaited_once()
    context.new_page.assert_awaited_once()
    assert browser.new_context.await_args.kwargs["service_workers"] == "block"


@pytest.mark.asyncio
async def test_v17_browser_installs_guard_before_first_page() -> None:
    agent = BrowserAgent()
    context = AsyncMock()
    context.route = AsyncMock()
    context.route_web_socket = AsyncMock()
    context.new_page = AsyncMock(return_value=AsyncMock())
    browser = AsyncMock()
    browser.new_context = AsyncMock(return_value=context)
    playwright = AsyncMock()
    playwright.chromium.launch = AsyncMock(return_value=browser)

    with (
        patch("cognithor.browser.agent._HAS_PLAYWRIGHT", True),
        patch(
            "cognithor.browser.agent.async_playwright",
            return_value=MagicMock(start=AsyncMock(return_value=playwright)),
            create=True,
        ),
    ):
        assert await agent.start()

    context.route.assert_awaited_once()
    context.route_web_socket.assert_awaited_once()
    context.new_page.assert_awaited_once()
    assert browser.new_context.await_args.kwargs["service_workers"] == "block"


def test_network_logs_never_include_query_credentials_or_fragments() -> None:
    safe = redact_url_for_log("https://user:password@example.com/path?token=secret#private")
    assert safe == "https://example.com"
    assert "password" not in safe
    assert "secret" not in safe
    assert "path" not in safe


@pytest.mark.parametrize(
    "tool_name",
    [
        "browser_click",
        "browser_fill",
        "browser_fill_form",
        "browser_execute_js",
        "browser_key",
        "browser_tab",
        "browser_workflow",
        "browser_vision_find",
    ],
)
def test_v17_browser_mutations_are_explicit_r4_and_safe_mode_denied(
    tool_name: str,
    tmp_path: Any,
) -> None:
    action = PlannedAction(tool=tool_name, params={})
    assert action_risk_class(action, tmp_path) == ActionRiskClass.R4_PRODUCTION_EXTERNAL
    assert safe_mode_allows(tool_name) is False
