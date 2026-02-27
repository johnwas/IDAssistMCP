"""
FastMCP server implementation for IDAssistMCP

This module provides the main MCP server with SSE/Streamable HTTP transport
and IDA Pro integration for the single-binary context.
"""

import warnings
from contextlib import asynccontextmanager
from threading import Event, Thread
from typing import AsyncIterator, Optional

import asyncio
from hypercorn.config import Config as HypercornConfig
from hypercorn.asyncio import serve
from mcp.server.fastmcp import Context, FastMCP
from mcp.server.transport_security import TransportSecuritySettings

# Suppress ResourceWarnings for memory streams
warnings.filterwarnings("ignore", category=ResourceWarning)

from .config import IDAssistMCPConfig, TransportType
from .context import IDAContextManager
from .logging import log
from .tasks import TaskManager, TaskStatus, get_task_manager


class ResourceManagedASGIApp:
    """ASGI app wrapper that ensures proper resource cleanup"""

    def __init__(self, app):
        self.app = app
        self._response_started = {}

    async def __call__(self, scope, receive, send):
        scope_id = id(scope)
        self._response_started[scope_id] = False

        async def wrapped_send(message):
            if message["type"] == "http.response.start":
                self._response_started[scope_id] = True
            elif message["type"] == "http.response.body":
                if not self._response_started.get(scope_id):
                    log.log_debug("Attempted to send response body before response start")
                    return
            try:
                await send(message)
            except Exception as e:
                error_msg = str(e)
                if ("connection" in error_msg.lower() or
                    "closed" in error_msg.lower() or
                    "ASGIHTTPState" in error_msg or
                    "response already" in error_msg.lower() or
                    "Unexpected message type" in error_msg):
                    log.log_debug(f"Client disconnected or ASGI state error (expected): {e}")
                else:
                    log.log_warn(f"Error sending ASGI message: {e}")

        try:
            await self.app(scope, receive, wrapped_send)
        except BaseException as e:
            import sys
            import traceback

            if sys.version_info >= (3, 11) and isinstance(e, BaseExceptionGroup):
                log.log_debug(f"ASGI exception group during request: {e}")
                for exc in e.exceptions:
                    error_msg = str(exc)
                    if ("ASGIHTTPState" in error_msg or
                        "connection" in error_msg.lower() or
                        "closed" in error_msg.lower() or
                        "response already" in error_msg.lower() or
                        "Unexpected message type" in error_msg or
                        "cancelled" in error_msg.lower() or
                        isinstance(exc, asyncio.CancelledError)):
                        log.log_debug(f"Client disconnect or ASGI state error (expected): {exc}")
                    else:
                        log.log_warn(f"Unexpected exception in request group: {exc}")
                        log.log_debug(f"Traceback: {''.join(traceback.format_exception(type(exc), exc, exc.__traceback__))}")
                return

            error_msg = str(e)
            if ("ASGIHTTPState" in error_msg or
                "connection" in error_msg.lower() or
                "closed" in error_msg.lower() or
                "response already" in error_msg.lower() or
                "Unexpected message type" in error_msg or
                "cancelled" in error_msg.lower() or
                isinstance(e, asyncio.CancelledError)):
                log.log_debug(f"Client disconnect or ASGI state error (expected): {e}")
            else:
                log.log_warn(f"Unexpected ASGI exception during request: {e}")
                log.log_debug(f"Traceback: {traceback.format_exc()}")
            return
        finally:
            self._response_started.pop(scope_id, None)


@asynccontextmanager
async def server_lifespan(server: FastMCP) -> AsyncIterator[IDAContextManager]:
    """Application lifecycle manager for the MCP server."""
    context_manager = IDAContextManager()

    # Refresh context from current IDB
    try:
        context_manager.refresh()
    except Exception as e:
        log.log_error(f"Failed to refresh IDA context on startup: {e}")

    log.log_info("IDAssistMCP server started")

    try:
        yield context_manager
    except asyncio.CancelledError:
        log.log_debug("Server lifespan received CancelledError (graceful shutdown)")
        raise
    except KeyboardInterrupt:
        log.log_info("Server lifespan received KeyboardInterrupt")
        raise
    except BaseException as e:
        import sys
        import traceback

        if sys.version_info >= (3, 11) and isinstance(e, BaseExceptionGroup):
            log.log_warn(f"Server lifespan TaskGroup error: {e}")
            all_connection_errors = True
            for exc in e.exceptions:
                error_msg = str(exc).lower()
                is_connection_error = (
                    "connection" in error_msg or
                    "closed" in error_msg or
                    "cancelled" in error_msg or
                    "ASGIHTTPState" in str(exc) or
                    isinstance(exc, asyncio.CancelledError)
                )
                if not is_connection_error:
                    log.log_error(f"Lifespan sub-exception: {exc}")
                    all_connection_errors = False

            if not all_connection_errors:
                raise
        else:
            error_msg = str(e).lower()
            is_connection_error = (
                "connection" in error_msg or
                "closed" in error_msg or
                "cancelled" in error_msg
            )
            if not is_connection_error:
                log.log_error(f"Server lifespan error: {e}")
                raise
    finally:
        try:
            log.log_info("Shutting down server, clearing IDA context")
            context_manager.clear()
            await asyncio.sleep(0.5)
            log.log_info("Server lifespan cleanup completed")
        except Exception as e:
            log.log_error(f"Error during server shutdown: {e}")


class SSEServerThread(Thread):
    """Thread for running the MCP server with Hypercorn"""

    def __init__(self, asgi_app, config: IDAssistMCPConfig):
        super().__init__(name="IDAssistMCP-Server", daemon=True)
        self.asgi_app = asgi_app
        self.config = config
        self.shutdown_signal = Event()
        self.hypercorn_config = HypercornConfig()
        self.hypercorn_config.bind = [f"{config.server.host}:{config.server.port}"]

        self.hypercorn_config.keep_alive_timeout = 5
        self.hypercorn_config.graceful_timeout = 10

        # Disable hypercorn's logging
        self.hypercorn_config.access_log_format = ""
        self.hypercorn_config.error_logger = None
        self.hypercorn_config.access_logger = None

        import logging
        logging.getLogger('hypercorn').disabled = True
        logging.getLogger('hypercorn.error').disabled = True
        logging.getLogger('hypercorn.access').disabled = True

        warnings.filterwarnings("ignore", category=ResourceWarning)

    def run(self):
        try:
            log.log_info(f"Starting MCP server on {self.config.server.host}:{self.config.server.port}")

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            try:
                loop.run_until_complete(self._run_server())
            finally:
                loop.close()

        except Exception as e:
            log.log_error(f"MCP server error: {e}")
            import traceback
            log.log_error(f"MCP server traceback: {traceback.format_exc()}")

    async def _run_server(self):
        import sys
        import traceback

        while not self.shutdown_signal.is_set():
            try:
                await serve(
                    self.asgi_app,
                    self.hypercorn_config,
                    shutdown_trigger=self._shutdown_trigger
                )
                break
            except BaseException as e:
                if self.shutdown_signal.is_set():
                    break

                is_recoverable = False

                if sys.version_info >= (3, 11) and isinstance(e, BaseExceptionGroup):
                    all_recoverable = True
                    for exc in e.exceptions:
                        if not self._is_recoverable_exception(exc, str(exc)):
                            all_recoverable = False
                            log.log_error(f"Unrecoverable sub-exception: {exc}")
                    is_recoverable = all_recoverable
                else:
                    is_recoverable = self._is_recoverable_exception(e, str(e))

                if is_recoverable:
                    log.log_info("Recoverable error encountered, server continuing...")
                    await asyncio.sleep(0.1)
                    continue
                else:
                    log.log_error("Unrecoverable server error, stopping server")
                    break

        try:
            await asyncio.sleep(1.0)
        except Exception:
            pass

    def _is_recoverable_exception(self, exc: BaseException, error_msg: str) -> bool:
        if isinstance(exc, asyncio.CancelledError):
            return True

        recoverable_patterns = [
            "connection", "closed", "ASGIHTTPState", "response already",
            "Unexpected message type", "client disconnect", "broken pipe",
            "reset by peer", "stream",
        ]

        error_msg_lower = error_msg.lower()
        for pattern in recoverable_patterns:
            if pattern.lower() in error_msg_lower:
                return True

        return False

    async def _shutdown_trigger(self):
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self.shutdown_signal.wait)
        log.log_info("Shutdown signal received")
        await asyncio.sleep(0.5)

    def stop(self):
        log.log_info("Stopping MCP server")
        self.shutdown_signal.set()

        if self.is_alive():
            self.join(timeout=5.0)
            if self.is_alive():
                log.log_warn("MCP server thread did not shut down cleanly within 5 seconds")
            else:
                log.log_info("MCP server thread shutdown completed")


class IDAssistMCPServer:
    """Main IDAssistMCP server class"""

    def __init__(self, config: Optional[IDAssistMCPConfig] = None):
        self.config = config or IDAssistMCPConfig()
        self.mcp_server: Optional[FastMCP] = None
        self._server_thread: Optional[SSEServerThread] = None
        self._running = False

        log.log_info(f"Initialized IDAssistMCP server")

    def create_mcp_server(self) -> FastMCP:
        """Create and configure the FastMCP server instance"""
        try:
            log.log_info("Creating FastMCP instance...")
            mcp = FastMCP(
                name="IDAssistMCP",
                lifespan=server_lifespan,
                transport_security=TransportSecuritySettings(
                    enable_dns_rebinding_protection=False
                )
            )
            log.log_info("FastMCP instance created")

            # Store configuration for lifespan access
            mcp._config = self.config

            log.log_info("Registering tools...")
            self._register_tools(mcp)
            log.log_info("Tools registered successfully")

            log.log_info("Registering resources...")
            self._register_resources(mcp)
            log.log_info("Resources registered successfully")

            log.log_info("Registering prompts...")
            self._register_prompts(mcp)
            log.log_info("Prompts registered successfully")

            return mcp

        except Exception as e:
            log.log_error(f"Failed to create MCP server: {e}")
            import traceback
            log.log_error(f"MCP server creation traceback: {traceback.format_exc()}")
            raise

    def _register_tools(self, mcp: FastMCP):
        """Register all MCP tools"""
        from .tools import register_tools
        disabled = set(self.config.disabled_tools)
        register_tools(mcp, disabled_tools=disabled)

    def _register_resources(self, mcp: FastMCP):
        """Register all MCP resources"""
        from .resources import register_resources
        register_resources(mcp)

    def _register_prompts(self, mcp: FastMCP):
        """Register all MCP prompts"""
        from .prompts import register_prompts
        register_prompts(mcp)

    def start(self) -> bool:
        """Start the MCP server with configured transport.

        Returns:
            True if started successfully
        """
        if self._running:
            log.log_warn("Server is already running")
            return True

        try:
            log.log_info("Starting IDAssistMCP server...")

            errors = self.config.validate()
            if errors:
                log.log_error(f"Configuration errors: {errors}")
                return False

            self.mcp_server = self.create_mcp_server()

            # Start the transport server
            self._start_transport_server()

            self._running = True
            transport = self.config.server.transport.value
            log.log_info(f"IDAssistMCP server started successfully (transport: {transport})")

            if self.config.is_transport_enabled(TransportType.SSE):
                log.log_info(f"SSE endpoint: {self.config.get_sse_url()}")
            elif self.config.is_transport_enabled(TransportType.STREAMABLEHTTP):
                log.log_info(f"Streamable HTTP endpoint: {self.config.get_streamablehttp_url()}")

            return True

        except Exception as e:
            log.log_error(f"Failed to start server: {e}")
            import traceback
            log.log_error(f"Server startup traceback: {traceback.format_exc()}")
            self.stop()
            return False

    def _start_transport_server(self):
        """Start the appropriate transport server thread"""
        if not self.mcp_server:
            raise RuntimeError("MCP server not created")

        try:
            # Get ASGI app based on transport type
            if self.config.is_transport_enabled(TransportType.SSE):
                log.log_info("Creating SSE ASGI app...")
                if hasattr(self.mcp_server, 'sse_app'):
                    asgi_app = self.mcp_server.sse_app()
                else:
                    raise RuntimeError("FastMCP does not have sse_app method")
            elif self.config.is_transport_enabled(TransportType.STREAMABLEHTTP):
                log.log_info("Creating Streamable HTTP ASGI app...")
                if hasattr(self.mcp_server, 'streamable_http_app'):
                    asgi_app = self.mcp_server.streamable_http_app()
                else:
                    raise RuntimeError("FastMCP does not have streamable_http_app method")
            else:
                raise RuntimeError(f"Unknown transport type: {self.config.server.transport}")

            # Wrap with error handling
            wrapped_app = ResourceManagedASGIApp(asgi_app)

            self._server_thread = SSEServerThread(wrapped_app, self.config)
            self._server_thread.start()

            import time
            time.sleep(0.2)

            if self._server_thread.is_alive():
                log.log_info("MCP server thread is running")
            else:
                self._server_thread = None
                raise RuntimeError("MCP server thread failed to start")

        except Exception as e:
            log.log_error(f"Failed to start transport server: {e}")
            if self._server_thread:
                try:
                    self._server_thread.stop()
                except Exception:
                    pass
                self._server_thread = None
            raise

    def stop(self):
        """Stop the MCP server"""
        if not self._running:
            return

        log.log_info("Stopping IDAssistMCP server")

        try:
            if self._server_thread:
                try:
                    self._server_thread.stop()
                    if self._server_thread.is_alive():
                        self._server_thread.join(timeout=10.0)
                except Exception as e:
                    log.log_error(f"Error stopping server thread: {e}")
                finally:
                    self._server_thread = None

            if self.mcp_server:
                self.mcp_server = None

        except Exception as e:
            log.log_error(f"Error during server shutdown: {e}")
        finally:
            self._running = False
            log.log_info("IDAssistMCP server stopped")

    def is_running(self) -> bool:
        """Check if the server is running"""
        return self._running

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
