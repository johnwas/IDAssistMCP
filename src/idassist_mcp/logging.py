"""
Centralized logging utilities for IDAssistMCP using IDA Pro's output window.

Provides a logger that routes messages to ida_kernwin.msg() when running
inside IDA Pro, or falls back to print() for standalone testing.
"""

import logging
import warnings

# Suppress ResourceWarnings from anyio memory streams
warnings.filterwarnings("ignore", category=ResourceWarning, module="anyio.streams.memory")
warnings.filterwarnings("ignore", category=ResourceWarning, message=".*MemoryObjectReceiveStream.*")

try:
    import ida_kernwin
    _IN_IDA = True
except ImportError:
    _IN_IDA = False


class IDALogHandler(logging.Handler):
    """Python logging.Handler that routes to IDA's output window."""

    PREFIX = "[IDAssistMCP]"

    def emit(self, record):
        try:
            msg = self.format(record)
            output = f"{self.PREFIX} {record.levelname}: {msg}\n"
            if _IN_IDA:
                ida_kernwin.msg(output)
            else:
                print(output, end="")
        except Exception:
            self.handleError(record)


class IDALogger:
    """Logger compatible with Binary Ninja's log interface.

    Provides log_debug/log_info/log_warn/log_error methods so that code
    ported from BinAssistMCP works with minimal changes.
    """

    PREFIX = "[IDAssistMCP]"

    @staticmethod
    def log_debug(msg):
        if _IN_IDA:
            ida_kernwin.msg(f"{IDALogger.PREFIX} DEBUG: {msg}\n")
        else:
            print(f"{IDALogger.PREFIX} DEBUG: {msg}")
        if _qt_handler is not None:
            _qt_handler.emit(logging.LogRecord("idassist_mcp", logging.DEBUG, "", 0, f"DEBUG: {msg}", (), None))

    @staticmethod
    def log_info(msg):
        if _IN_IDA:
            ida_kernwin.msg(f"{IDALogger.PREFIX} INFO: {msg}\n")
        else:
            print(f"{IDALogger.PREFIX} INFO: {msg}")
        if _qt_handler is not None:
            _qt_handler.emit(logging.LogRecord("idassist_mcp", logging.INFO, "", 0, f"INFO: {msg}", (), None))

    @staticmethod
    def log_warn(msg):
        if _IN_IDA:
            ida_kernwin.msg(f"{IDALogger.PREFIX} WARN: {msg}\n")
        else:
            print(f"{IDALogger.PREFIX} WARN: {msg}")
        if _qt_handler is not None:
            _qt_handler.emit(logging.LogRecord("idassist_mcp", logging.WARNING, "", 0, f"WARN: {msg}", (), None))

    @staticmethod
    def log_error(msg):
        if _IN_IDA:
            ida_kernwin.msg(f"{IDALogger.PREFIX} ERROR: {msg}\n")
        else:
            print(f"{IDALogger.PREFIX} ERROR: {msg}")
        if _qt_handler is not None:
            _qt_handler.emit(logging.LogRecord("idassist_mcp", logging.ERROR, "", 0, f"ERROR: {msg}", (), None))


# Global logger instance
log = IDALogger()

# Qt log handler reference (set by install_qt_handler)
_qt_handler = None


def install_qt_handler(handler):
    """Install a QLogHandler to receive copies of all log messages.

    Args:
        handler: A QLogHandler instance from ui.log_tab
    """
    global _qt_handler
    _qt_handler = handler


def get_qt_handler():
    """Get the currently installed Qt handler, or None."""
    return _qt_handler


def get_logger(name: str) -> logging.Logger:
    """Get a Python logging.Logger that routes to IDA's output window.

    Args:
        name: Logger name (e.g. module __name__)

    Returns:
        Configured logging.Logger instance
    """
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = IDALogHandler()
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
    return logger


def setup_logging_filters():
    """Suppress noisy external library loggers."""
    external_loggers = [
        'hypercorn', 'hypercorn.error', 'hypercorn.access',
        'uvicorn', 'uvicorn.error', 'uvicorn.access',
        'mcp', 'mcp.client', 'mcp.server',
        'httpx', 'fastapi', 'starlette', 'anyio'
    ]
    for logger_name in external_loggers:
        ext_logger = logging.getLogger(logger_name)
        ext_logger.setLevel(logging.CRITICAL)
        ext_logger.propagate = False


def disable_external_logging():
    """Completely disable external library logging and resource warnings."""
    logging.getLogger().setLevel(logging.CRITICAL)
    warnings.filterwarnings("ignore", category=ResourceWarning)
    warnings.filterwarnings("ignore", message="unclosed.*", category=ResourceWarning)

    external_loggers = [
        'hypercorn', 'hypercorn.error', 'hypercorn.access',
        'uvicorn', 'uvicorn.error', 'uvicorn.access',
        'mcp', 'mcp.client', 'mcp.server',
        'httpx', 'fastapi', 'starlette', 'anyio'
    ]
    for logger_name in external_loggers:
        ext_logger = logging.getLogger(logger_name)
        ext_logger.disabled = True
        ext_logger.propagate = False


# Setup filters on import
setup_logging_filters()
