"""
IDAssistMCP - IDA Pro Plugin Entry Point

This is the IDA plugin_t that manages the IDAssistMCP MCP server lifecycle.
Place this file (or a symlink to it) in your IDA Pro plugins/ directory.

The plugin starts/stops a standalone MCP server that exposes IDA Pro's
analysis capabilities (36+ tools, 8 resources, 7 prompts) via the Model
Context Protocol over SSE or Streamable HTTP transport.

Usage:
    - The plugin loads automatically when IDA starts.
    - Press Ctrl+Shift+M (or use Edit > Plugins > IDAssistMCP) to toggle
      the MCP server on/off.
    - The server endpoint URL is printed to IDA's output window on start.
    - Configure via environment variables with IDASSISTMCP_ prefix:
        IDASSISTMCP_SERVER__HOST=0.0.0.0
        IDASSISTMCP_SERVER__PORT=9080
        IDASSISTMCP_SERVER__TRANSPORT=streamablehttp   (or sse)
"""

import os
import sys

import idaapi
import ida_kernwin


# --------------------------------------------------------------------------- #
# Ensure the plugin package is importable
# --------------------------------------------------------------------------- #

_PLUGIN_DIR = os.path.dirname(os.path.realpath(__file__))
_SRC_DIR = os.path.join(_PLUGIN_DIR, "src")
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)


# --------------------------------------------------------------------------- #
# Plugin class
# --------------------------------------------------------------------------- #

class IDAssistMCPPlugin(idaapi.plugin_t):
    """IDA plugin that manages the IDAssistMCP MCP server."""

    flags = idaapi.PLUGIN_KEEP
    comment = "IDAssistMCP - MCP server for LLM-powered reverse engineering"
    help = "Toggle MCP server with Ctrl+Shift+M"
    wanted_name = "IDAssistMCP"
    wanted_hotkey = "Ctrl-Shift-M"

    def init(self):
        """Called when the plugin is loaded by IDA."""
        self._server = None
        self._config = None

        ida_kernwin.msg("[IDAssistMCP] Plugin loaded. Press Ctrl+Shift+M to start/stop the MCP server.\n")

        # Register menu action
        self._register_menu_action()

        return idaapi.PLUGIN_KEEP

    def run(self, arg=0):
        """Called when the user activates the plugin (hotkey or menu)."""
        if self._server and self._server.is_running():
            self._stop_server()
        else:
            self._start_server()

    def term(self):
        """Called when IDA is shutting down."""
        if self._server and self._server.is_running():
            ida_kernwin.msg("[IDAssistMCP] Shutting down MCP server...\n")
            self._server.stop()
            self._server = None

        self._unregister_menu_action()
        ida_kernwin.msg("[IDAssistMCP] Plugin unloaded.\n")

    # --------------------------------------------------------------------- #
    # Server lifecycle
    # --------------------------------------------------------------------- #

    def _start_server(self):
        """Start the MCP server."""
        try:
            from idassist_mcp.config import IDAssistMCPConfig, TransportType
            from idassist_mcp.server import IDAssistMCPServer
            from idassist_mcp.logging import disable_external_logging

            # Suppress noisy external loggers
            disable_external_logging()

            # Load configuration (reads IDASSISTMCP_ env vars)
            self._config = IDAssistMCPConfig()

            ida_kernwin.msg(f"[IDAssistMCP] Starting MCP server on "
                            f"{self._config.server.host}:{self._config.server.port} "
                            f"(transport: {self._config.server.transport.value})...\n")

            self._server = IDAssistMCPServer(self._config)

            if self._server.start():
                if self._config.is_transport_enabled(TransportType.SSE):
                    url = self._config.get_sse_url()
                else:
                    url = self._config.get_streamablehttp_url()

                ida_kernwin.msg(f"[IDAssistMCP] MCP server running at: {url}\n")
                ida_kernwin.msg(f"[IDAssistMCP] Add to Claude Desktop config:\n")
                ida_kernwin.msg(f'  "idassistmcp": {{"url": "{url}"}}\n')
            else:
                ida_kernwin.msg("[IDAssistMCP] ERROR: Server failed to start.\n")
                self._server = None

        except ImportError as e:
            ida_kernwin.msg(f"[IDAssistMCP] ERROR: Missing dependency: {e}\n")
            ida_kernwin.msg(f"[IDAssistMCP] Install requirements: pip install -r "
                            f"{os.path.join(_PLUGIN_DIR, 'requirements.txt')}\n")
        except Exception as e:
            ida_kernwin.msg(f"[IDAssistMCP] ERROR: {e}\n")
            import traceback
            ida_kernwin.msg(f"[IDAssistMCP] {traceback.format_exc()}\n")

    def _stop_server(self):
        """Stop the MCP server."""
        if self._server:
            ida_kernwin.msg("[IDAssistMCP] Stopping MCP server...\n")
            self._server.stop()
            self._server = None
            ida_kernwin.msg("[IDAssistMCP] MCP server stopped.\n")

    # --------------------------------------------------------------------- #
    # Menu integration
    # --------------------------------------------------------------------- #

    ACTION_NAME = "idassistmcp:toggle_server"
    MENU_PATH = "Edit/Plugins/"

    def _register_menu_action(self):
        """Register the toggle action in IDA's menu."""
        action_desc = idaapi.action_desc_t(
            self.ACTION_NAME,
            "IDAssistMCP: Toggle MCP Server",
            _ToggleServerHandler(self),
            self.wanted_hotkey,
            "Start or stop the IDAssistMCP MCP server",
            -1,  # icon
        )

        if idaapi.register_action(action_desc):
            idaapi.attach_action_to_menu(
                self.MENU_PATH,
                self.ACTION_NAME,
                idaapi.SETMENU_APP,
            )

    def _unregister_menu_action(self):
        """Remove the toggle action from IDA's menu."""
        idaapi.detach_action_from_menu(self.MENU_PATH, self.ACTION_NAME)
        idaapi.unregister_action(self.ACTION_NAME)


class _ToggleServerHandler(idaapi.action_handler_t):
    """Action handler that delegates to the plugin's run() method."""

    def __init__(self, plugin: IDAssistMCPPlugin):
        super().__init__()
        self._plugin = plugin

    def activate(self, ctx):
        self._plugin.run()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


# --------------------------------------------------------------------------- #
# IDA plugin entry point
# --------------------------------------------------------------------------- #

def PLUGIN_ENTRY():
    return IDAssistMCPPlugin()
