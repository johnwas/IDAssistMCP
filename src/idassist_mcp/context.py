"""
Single-binary IDA context manager for IDAssistMCP

Unlike BinAssistMCP which manages multiple Binary Ninja views, IDA Pro
works with a single IDB at a time. This module provides context about
the currently loaded binary.
"""

import hashlib
import os
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .logging import log
from .utils import execute_on_main_thread

try:
    import idaapi
    import idautils
    import idc
    import ida_funcs
    import ida_nalt
    import ida_segment
    import ida_entry
    import ida_ida
    import ida_name
    _IN_IDA = True
except ImportError:
    _IN_IDA = False


@dataclass
class IDABinaryContext:
    """Information about the currently loaded IDA binary"""
    filename: str = ""
    filepath: str = ""
    md5: str = ""
    sha256: str = ""
    architecture: str = ""
    platform: str = ""
    base_address: int = 0
    entry_point: int = 0
    bitness: int = 0
    file_type: str = ""
    compiler: str = ""
    segments: List[Dict[str, Any]] = field(default_factory=list)
    analysis_complete: bool = False
    function_count: int = 0
    string_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation"""
        return {
            "filename": self.filename,
            "filepath": self.filepath,
            "md5": self.md5,
            "sha256": self.sha256,
            "architecture": self.architecture,
            "platform": self.platform,
            "base_address": hex(self.base_address) if self.base_address else "0x0",
            "entry_point": hex(self.entry_point) if self.entry_point else "0x0",
            "bitness": self.bitness,
            "file_type": self.file_type,
            "compiler": self.compiler,
            "segments": self.segments,
            "analysis_complete": self.analysis_complete,
            "function_count": self.function_count,
            "string_count": self.string_count,
        }


class IDAContextManager:
    """Context manager for the single IDA binary (current IDB).

    Provides a cached view of the binary's metadata that can be
    refreshed on demand. Thread-safe for concurrent MCP access.
    """

    def __init__(self):
        self._context: Optional[IDABinaryContext] = None
        self._lock = threading.RLock()

    def refresh(self) -> IDABinaryContext:
        """Rebuild context from the current IDB.

        All IDA API calls run on the main thread via execute_on_main_thread.

        Returns:
            Updated IDABinaryContext
        """
        if not _IN_IDA:
            log.log_warn("Not running inside IDA, returning empty context")
            ctx = IDABinaryContext()
            with self._lock:
                self._context = ctx
            return ctx

        ctx = IDABinaryContext()

        def _do_refresh():
            try:
                # File info
                ctx.filepath = ida_nalt.get_input_file_path() or ""
                ctx.filename = os.path.basename(ctx.filepath) if ctx.filepath else ""

                # Hashes
                ctx.md5 = _get_input_md5()
                ctx.sha256 = _get_input_sha256()

                # Architecture & platform (IDA 9.0+ accessor functions)
                proc_name = ida_ida.inf_get_procname()
                ctx.architecture = proc_name if proc_name else "unknown"

                if ida_ida.inf_is_64bit():
                    ctx.bitness = 64
                elif ida_ida.inf_is_32bit_exactly():
                    ctx.bitness = 32
                else:
                    ctx.bitness = 16

                ctx.base_address = ida_ida.inf_get_min_ea()
                ctx.entry_point = ida_ida.inf_get_start_ea()

                # File type
                ftype = ida_ida.inf_get_filetype()
                file_type_map = {
                    0: "unknown",
                    1: "ELF",
                    2: "OMF",
                    6: "PE",
                    13: "Mach-O",
                    25: "ELF",
                }
                ctx.file_type = file_type_map.get(ftype, f"type_{ftype}")

                # Platform heuristic
                if "ARM" in ctx.architecture.upper():
                    ctx.platform = "ARM"
                elif "MIPS" in ctx.architecture.upper():
                    ctx.platform = "MIPS"
                elif ctx.architecture in ("metapc",):
                    ctx.platform = "x86"
                else:
                    ctx.platform = ctx.architecture

                # Segments
                ctx.segments = _get_segments_list()

                # Counts
                ctx.function_count = len(list(idautils.Functions()))
                try:
                    ctx.string_count = sum(1 for _ in idautils.Strings())
                except Exception:
                    ctx.string_count = 0

                # Analysis state
                ctx.analysis_complete = not ida_ida.inf_is_auto_enabled()

            except Exception as e:
                log.log_error(f"Error refreshing IDA context: {e}")

        execute_on_main_thread(_do_refresh)

        with self._lock:
            self._context = ctx

        log.log_info(f"Context refreshed: {ctx.filename} ({ctx.architecture} {ctx.bitness}-bit, {ctx.function_count} functions)")
        return ctx

    def get_context(self) -> IDABinaryContext:
        """Get the current context, refreshing if needed.

        Returns:
            Current IDABinaryContext
        """
        with self._lock:
            if self._context is None:
                return self.refresh()
            return self._context

    def get_binary_name(self) -> str:
        """Get the current binary's filename.

        Returns:
            Binary filename or 'unknown'
        """
        ctx = self.get_context()
        return ctx.filename or "unknown"

    def invalidate(self):
        """Invalidate the cached context, forcing a refresh on next access."""
        with self._lock:
            self._context = None

    def clear(self):
        """Clear the context."""
        with self._lock:
            self._context = None
        log.log_info("IDA context cleared")


def _get_input_md5() -> str:
    """Get MD5 hash of the input file."""
    try:
        md5_bytes = ida_nalt.retrieve_input_file_md5()
        if md5_bytes:
            # ida_nalt returns bytes, convert to hex string
            if isinstance(md5_bytes, bytes):
                return md5_bytes.hex()
            return str(md5_bytes)
    except Exception:
        pass

    # Fallback: compute from file
    try:
        filepath = ida_nalt.get_input_file_path()
        if filepath and os.path.exists(filepath):
            h = hashlib.md5()
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            return h.hexdigest()
    except Exception:
        pass

    return ""


def _get_input_sha256() -> str:
    """Get SHA-256 hash of the input file."""
    try:
        sha256_bytes = ida_nalt.retrieve_input_file_sha256()
        if sha256_bytes:
            if isinstance(sha256_bytes, bytes):
                return sha256_bytes.hex()
            return str(sha256_bytes)
    except Exception:
        pass

    # Fallback: compute from file
    try:
        filepath = ida_nalt.get_input_file_path()
        if filepath and os.path.exists(filepath):
            h = hashlib.sha256()
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            return h.hexdigest()
    except Exception:
        pass

    return ""


def _get_segments_list() -> List[Dict[str, Any]]:
    """Get list of segments from the IDB."""
    segments = []
    try:
        for i in range(ida_segment.get_segm_qty()):
            seg = ida_segment.getnseg(i)
            if seg is None:
                continue

            name = ida_segment.get_segm_name(seg) or f"seg_{i}"
            seg_class = ida_segment.get_segm_class(seg) or ""

            # Determine permissions
            perms = ""
            if seg.perm & ida_segment.SFL_LOADER:
                pass  # Loader segment flag
            perms_r = bool(seg.perm & idaapi.SFL_READ) if hasattr(idaapi, 'SFL_READ') else True
            perms_w = bool(seg.perm & idaapi.SFL_WRITE) if hasattr(idaapi, 'SFL_WRITE') else False
            perms_x = bool(seg.perm & idaapi.SFL_CODE) if hasattr(idaapi, 'SFL_CODE') else False

            # Fallback: use segment type for permissions
            perm_str = ""
            perm_str += "R" if (seg.perm & 4) else "-"
            perm_str += "W" if (seg.perm & 2) else "-"
            perm_str += "X" if (seg.perm & 1) else "-"

            segments.append({
                "name": name,
                "start": hex(seg.start_ea),
                "end": hex(seg.end_ea),
                "size": seg.end_ea - seg.start_ea,
                "permissions": perm_str,
                "class": seg_class,
            })
    except Exception as e:
        log.log_error(f"Error getting segments: {e}")

    return segments
