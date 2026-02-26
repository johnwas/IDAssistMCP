"""
Utility functions for IDAssistMCP

This module provides common utility functions used across the project,
including IDA-specific helpers for address parsing, formatting, and
main-thread execution.
"""

from pathlib import Path
from typing import Optional

from .logging import log

try:
    import idaapi
    _IN_IDA = True
except ImportError:
    _IN_IDA = False


def execute_on_main_thread(callback):
    """Execute a callback on IDA's main thread.

    IDA requires all IDB modifications to happen on the main thread.
    This wraps idaapi.execute_sync() with MFF_FAST.

    Args:
        callback: A callable (no arguments) to execute on the main thread.

    Returns:
        The return value of idaapi.execute_sync().
    """
    if not _IN_IDA:
        return callback()

    return idaapi.execute_sync(callback, idaapi.MFF_FAST)


def parse_address(address_str: str) -> Optional[int]:
    """Parse an address string to integer.

    Args:
        address_str: Address string (hex or decimal)

    Returns:
        Integer address or None if parsing fails
    """
    if not address_str:
        return None

    try:
        address_str = address_str.strip()
        if address_str.startswith('0x') or address_str.startswith('0X'):
            return int(address_str, 16)
        if address_str.isdigit():
            return int(address_str)
        # Try pure hex without prefix
        return int(address_str, 16)
    except ValueError:
        log.log_debug(f"Failed to parse address: {address_str}")
        return None


def format_address(address: int, width: Optional[int] = None) -> str:
    """Format an address as a hex string.

    Args:
        address: Integer address
        width: Optional width for zero-padding

    Returns:
        Formatted hex address string
    """
    if width:
        return f"0x{address:0{width}x}"
    else:
        return f"0x{address:x}"


def format_size(size_bytes: int) -> str:
    """Format a size in bytes to human-readable format.

    Args:
        size_bytes: Size in bytes

    Returns:
        Human-readable size string
    """
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"


def truncate_string(text: str, max_length: int = 100, suffix: str = "...") -> str:
    """Truncate a string to a maximum length.

    Args:
        text: Input text
        max_length: Maximum length
        suffix: Suffix to add when truncating

    Returns:
        Truncated string
    """
    if not text or len(text) <= max_length:
        return text
    return text[:max_length - len(suffix)] + suffix


def sanitize_identifier(name: str) -> str:
    """Sanitize a name to be safe for use as an identifier.

    Args:
        name: Input name string

    Returns:
        Sanitized name safe for use in URLs, filenames, etc.
    """
    if not name or not isinstance(name, str):
        return "unnamed"

    invalid_chars = '/\\:*?"<>| \t\n\r'
    for char in invalid_chars:
        name = name.replace(char, '_')

    name = name.strip('_.')

    if not name:
        name = "unnamed"

    if name and not (name[0].isalpha() or name[0] == '_'):
        name = f"bin_{name}"

    return name


def safe_get_attribute(obj, attr_path: str, default=None):
    """Safely get a nested attribute from an object.

    Args:
        obj: Object to get attribute from
        attr_path: Dot-separated attribute path
        default: Default value if attribute not found

    Returns:
        Attribute value or default
    """
    try:
        attrs = attr_path.split('.')
        result = obj
        for attr in attrs:
            if hasattr(result, attr):
                result = getattr(result, attr)
            else:
                return default
        return result
    except Exception:
        return default


def resolve_name_or_address(name_or_address: str) -> Optional[int]:
    """Resolve a function name or address string to an effective address.

    Tries to parse as address first, then looks up as a name in IDA.

    Args:
        name_or_address: Function name or hex address string

    Returns:
        Effective address or None if unresolvable
    """
    # Try parsing as address first
    ea = parse_address(name_or_address)
    if ea is not None:
        return ea

    # Try looking up as a name
    if _IN_IDA:
        try:
            import ida_name
            ea = ida_name.get_name_ea(idaapi.BADADDR, name_or_address)
            if ea != idaapi.BADADDR:
                return ea
        except Exception:
            pass

    return None
