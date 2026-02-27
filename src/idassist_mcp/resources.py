"""
MCP Resources for IDAssistMCP

This module provides browsable, cacheable data resources for MCP clients.
Resources are accessed via URI patterns like ida://{resource_name}.

Since IDA is single-binary, resources don't take a filename parameter.
"""

from typing import Any, Dict

from mcp.server.fastmcp import FastMCP

from .context import IDAContextManager
from .logging import log

try:
    import idaapi
    import idautils
    import idc
    import ida_entry
    import ida_funcs
    import ida_ida
    import ida_nalt
    import ida_name
    import ida_segment
    import ida_typeinf
    _IN_IDA = True
except ImportError:
    _IN_IDA = False


def register_resources(mcp: FastMCP):
    """Register all MCP resources on the given FastMCP instance."""

    @mcp.resource("ida://triage")
    def triage_resource() -> Dict[str, Any]:
        """Binary triage summary with high-level stats.

        Provides a quick overview of the loaded binary including
        file info, architecture, function/string/segment counts.
        """
        if not _IN_IDA:
            return {"error": "Not running in IDA"}

        try:
            filepath = ida_nalt.get_input_file_path() or ""
            import os
            filename = os.path.basename(filepath)

            func_count = sum(1 for _ in idautils.Functions())
            string_count = sum(1 for _ in idautils.Strings())
            seg_count = ida_segment.get_segm_qty()
            entry_count = ida_entry.get_entry_qty()
            import_count = ida_nalt.get_import_module_qty()

            bitness = 64 if ida_ida.inf_is_64bit() else (32 if ida_ida.inf_is_32bit_exactly() else 16)

            return {
                "filename": filename,
                "filepath": filepath,
                "architecture": ida_ida.inf_get_procname(),
                "bitness": bitness,
                "entry_point": hex(ida_ida.inf_get_start_ea()),
                "base_address": hex(ida_ida.inf_get_min_ea()),
                "analysis_complete": not ida_ida.inf_is_auto_enabled(),
                "statistics": {
                    "functions": func_count,
                    "strings": string_count,
                    "segments": seg_count,
                    "entry_points": entry_count,
                    "import_modules": import_count,
                },
            }
        except Exception as e:
            log.log_error(f"Error in triage resource: {e}")
            return {"error": str(e)}

    @mcp.resource("ida://functions")
    def functions_resource() -> Dict[str, Any]:
        """Full function list with addresses and sizes."""
        if not _IN_IDA:
            return {"error": "Not running in IDA"}

        try:
            functions = []
            for func_ea in idautils.Functions():
                func = ida_funcs.get_func(func_ea)
                name = ida_funcs.get_func_name(func_ea) or f"sub_{func_ea:x}"
                size = (func.end_ea - func.start_ea) if func else 0
                functions.append({
                    "name": name,
                    "address": hex(func_ea),
                    "size": size,
                })

            return {
                "functions": functions,
                "count": len(functions),
            }
        except Exception as e:
            log.log_error(f"Error in functions resource: {e}")
            return {"error": str(e)}

    @mcp.resource("ida://imports")
    def imports_resource() -> Dict[str, Any]:
        """Import table grouped by module with function names and ordinals."""
        if not _IN_IDA:
            return {"error": "Not running in IDA"}

        try:
            imports_by_module: Dict[str, list] = {}
            _current_module = [""]

            def imp_cb(ea, name, ordinal):
                if name:
                    imports_by_module.setdefault(_current_module[0], []).append({
                        "name": name,
                        "address": hex(ea),
                        "ordinal": ordinal,
                    })
                return True

            for i in range(ida_nalt.get_import_module_qty()):
                mod_name = ida_nalt.get_import_module_name(i)
                _current_module[0] = mod_name or f"module_{i}"
                ida_nalt.enum_import_names(i, imp_cb)

            return {
                "imports": imports_by_module,
                "module_count": len(imports_by_module),
                "total_imports": sum(len(v) for v in imports_by_module.values()),
            }
        except Exception as e:
            log.log_error(f"Error in imports resource: {e}")
            return {"error": str(e)}

    @mcp.resource("ida://exports")
    def exports_resource() -> Dict[str, Any]:
        """Export table with names, addresses, and ordinals."""
        if not _IN_IDA:
            return {"error": "Not running in IDA"}

        try:
            exports = []
            for i in range(ida_entry.get_entry_qty()):
                ordinal = ida_entry.get_entry_ordinal(i)
                ea = ida_entry.get_entry(ordinal)
                name = ida_entry.get_entry_name(ordinal) or f"export_{ordinal}"
                exports.append({
                    "name": name,
                    "address": hex(ea),
                    "ordinal": ordinal,
                })

            return {"exports": exports, "count": len(exports)}
        except Exception as e:
            log.log_error(f"Error in exports resource: {e}")
            return {"error": str(e)}

    @mcp.resource("ida://strings")
    def strings_resource() -> Dict[str, Any]:
        """String table with addresses and encoding info (first 500 strings)."""
        if not _IN_IDA:
            return {"error": "Not running in IDA"}

        try:
            strings = []
            for s in idautils.Strings():
                value = str(s)
                if len(value) >= 4:
                    strings.append({
                        "address": hex(s.ea),
                        "value": value,
                        "length": s.length,
                        "type": "ascii" if s.strtype == 0 else f"type_{s.strtype}",
                    })
                    if len(strings) >= 500:
                        break

            return {"strings": strings, "count": len(strings), "note": "First 500 strings; use get_strings tool for pagination"}
        except Exception as e:
            log.log_error(f"Error in strings resource: {e}")
            return {"error": str(e)}

    @mcp.resource("ida://info")
    def info_resource() -> Dict[str, Any]:
        """Detailed binary info including architecture, ABI, compiler, segments."""
        if not _IN_IDA:
            return {"error": "Not running in IDA"}

        try:
            filepath = ida_nalt.get_input_file_path() or ""
            import os

            bitness = 64 if ida_ida.inf_is_64bit() else (32 if ida_ida.inf_is_32bit_exactly() else 16)

            # Segments summary
            segments = []
            for i in range(ida_segment.get_segm_qty()):
                seg = ida_segment.getnseg(i)
                if seg:
                    name = ida_segment.get_segm_name(seg) or f"seg_{i}"
                    perm = ""
                    perm += "R" if (seg.perm & 4) else "-"
                    perm += "W" if (seg.perm & 2) else "-"
                    perm += "X" if (seg.perm & 1) else "-"
                    segments.append({
                        "name": name,
                        "start": hex(seg.start_ea),
                        "end": hex(seg.end_ea),
                        "size": seg.end_ea - seg.start_ea,
                        "permissions": perm,
                        "class": ida_segment.get_segm_class(seg) or "",
                    })

            return {
                "filename": os.path.basename(filepath),
                "filepath": filepath,
                "architecture": ida_ida.inf_get_procname(),
                "bitness": bitness,
                "entry_point": hex(ida_ida.inf_get_start_ea()),
                "min_address": hex(ida_ida.inf_get_min_ea()),
                "max_address": hex(ida_ida.inf_get_max_ea()),
                "file_type": ida_ida.inf_get_filetype(),
                "segments": segments,
                "segment_count": len(segments),
            }
        except Exception as e:
            log.log_error(f"Error in info resource: {e}")
            return {"error": str(e)}

    @mcp.resource("ida://segments")
    def segments_resource() -> Dict[str, Any]:
        """Segment list with names, ranges, permissions, and class."""
        if not _IN_IDA:
            return {"error": "Not running in IDA"}

        try:
            segments = []
            for i in range(ida_segment.get_segm_qty()):
                seg = ida_segment.getnseg(i)
                if seg is None:
                    continue

                name = ida_segment.get_segm_name(seg) or f"seg_{i}"
                seg_class = ida_segment.get_segm_class(seg) or ""
                perm = ""
                perm += "R" if (seg.perm & 4) else "-"
                perm += "W" if (seg.perm & 2) else "-"
                perm += "X" if (seg.perm & 1) else "-"

                segments.append({
                    "name": name,
                    "start": hex(seg.start_ea),
                    "end": hex(seg.end_ea),
                    "size": seg.end_ea - seg.start_ea,
                    "permissions": perm,
                    "class": seg_class,
                })

            return {"segments": segments, "count": len(segments)}
        except Exception as e:
            log.log_error(f"Error in segments resource: {e}")
            return {"error": str(e)}

    @mcp.resource("ida://sections")
    def sections_resource() -> Dict[str, Any]:
        """Binary sections (same as segments in IDA, which doesn't distinguish them)."""
        # IDA doesn't distinguish sections vs segments; delegate
        return segments_resource()

    log.log_info("Registered MCP resources")
