from __future__ import annotations

import asyncio
import ssl
from dataclasses import dataclass, field

from aiohttp import web
from langchain_core.messages import HumanMessage

from deceive.runtime import (
    DeceiveRuntime,
    ProtocolInstanceConfig,
    SessionSummaryState,
    encode_details,
    merge_log_extra,
    new_session_id,
)


class TransportInfoSource:
    def __init__(self, transport):
        self.transport = transport

    def get_extra_info(self, name, default=None):
        if self.transport is None:
            return default
        return self.transport.get_extra_info(name, default)


@dataclass
class HTTPSession:
    summary_state: SessionSummaryState = field(default_factory=SessionSummaryState)
    username: str = "-"
    log_extra: dict | None = None


class HTTPInstanceState:
    def __init__(
        self,
        runtime: DeceiveRuntime,
        instance: ProtocolInstanceConfig,
        scheme: str,
    ):
        self.runtime = runtime
        self.instance = instance
        self.scheme = scheme
        self.sessions: dict[str, HTTPSession] = {}

    async def handle_request(self, request: web.Request) -> web.Response:
        cookie_name = self.instance.get("session_cookie_name", "deceive_session")
        session_id = request.cookies.get(cookie_name) or new_session_id()
        is_new_session = session_id not in self.sessions
        session = self.sessions.setdefault(session_id, HTTPSession())

        task = asyncio.current_task()
        if task is not None:
            task.set_name(session_id)

        source = TransportInfoSource(request.transport)
        log_extra = self.runtime.get_session_log_extra(
            source, self.instance, session_id
        )
        session.log_extra = log_extra
        session.username = request.remote or "-"

        body = await request.read()
        request_text = self._format_request(request, body)
        host = request.headers.get("Host", "-")
        user_agent = request.headers.get("User-Agent", "-")

        self.runtime.logger.info(
            "User input",
            extra=merge_log_extra(
                log_extra,
                details=encode_details(request_text),
                interactive=False,
                http_method=request.method,
                http_path=request.path,
                http_query=request.query_string,
                http_host=host,
                user_agent=user_agent,
            ),
        )

        llm_response = await self.runtime.invoke_llm(
            self.instance,
            session_id,
            {
                "messages": [HumanMessage(content=request_text)],
                "username": session.username,
                "interactive": False,
                "protocol": self.scheme,
                "protocol_instance": self.instance.full_name,
                "http_method": request.method,
                "http_path": request.path,
                "http_query": request.query_string,
                "http_host": host,
                "user_agent": user_agent,
            },
        )

        status = self.instance.getint("default_status", 200)
        response = web.Response(
            text=llm_response.content,
            status=status,
            content_type=self.instance.get("content_type", "text/html"),
        )
        if is_new_session:
            response.set_cookie(cookie_name, session_id, httponly=True, samesite="Lax")

        self.runtime.logger.info(
            "LLM response",
            extra=merge_log_extra(
                log_extra,
                details=encode_details(llm_response.content),
                interactive=False,
                http_method=request.method,
                http_path=request.path,
                http_status=status,
                http_host=host,
                user_agent=user_agent,
            ),
        )
        return response

    def _format_request(self, request: web.Request, body: bytes) -> str:
        version = f"{request.version.major}.{request.version.minor}"
        lines = [f"{request.method} {request.raw_path} HTTP/{version}"]
        for key, value in request.headers.items():
            lines.append(f"{key}: {value}")
        if body:
            lines.append("")
            lines.append(body.decode("utf-8", errors="replace"))
        return "\n".join(lines)

    async def summarize_open_sessions(self):
        for session_id, session in list(self.sessions.items()):
            await self.runtime.summarize_session(
                session.summary_state,
                self.instance,
                session_id,
                username=session.username,
                interactive=False,
                log_extra=session.log_extra,
            )


class HTTPRunningServer:
    def __init__(self, runner: web.AppRunner, site: web.TCPSite, state: HTTPInstanceState):
        self.runner = runner
        self.site = site
        self.state = state
        self._closing = False

    def close(self):
        self._closing = True

    async def wait_closed(self):
        await self.state.summarize_open_sessions()
        await self.runner.cleanup()

    def get_port(self):
        server = getattr(self.site, "_server", None)
        if server is None or not server.sockets:
            return None
        return server.sockets[0].getsockname()[1]


class HTTPProtocolAdapter:
    def __init__(self, scheme: str):
        self.name = scheme
        self.scheme = scheme

    async def start_instance(
        self, runtime: DeceiveRuntime, instance: ProtocolInstanceConfig
    ):
        state = HTTPInstanceState(runtime, instance, self.scheme)
        app = web.Application()
        app.router.add_route("*", "/{tail:.*}", state.handle_request)

        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(
            runner,
            host=instance.get("listen_host", ""),
            port=instance.getint("port", 8443 if self.scheme == "https" else 8080),
            ssl_context=self._ssl_context(runtime, instance),
        )
        await site.start()
        return HTTPRunningServer(runner, site, state)

    def _ssl_context(
        self, runtime: DeceiveRuntime, instance: ProtocolInstanceConfig
    ) -> ssl.SSLContext | None:
        if self.scheme != "https":
            return None

        cert_file = instance.get("cert_file")
        key_file = instance.get("key_file")
        if not cert_file or not key_file:
            raise ValueError(
                f"HTTPS protocol instance {instance.full_name} requires cert_file and key_file."
            )

        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(
            runtime.resolve_runtime_path(cert_file),
            runtime.resolve_runtime_path(key_file),
        )
        return context
