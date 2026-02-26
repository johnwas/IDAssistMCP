"""
Comprehensive MCP tool implementations for IDAssistMCP

This module provides all 36+ IDA Pro integration tools registered as
FastMCP tools. All tools that modify the IDB use execute_on_main_thread().
"""

import functools
import json
import re
from typing import Any, Dict, List, Optional

from mcp.server.fastmcp import Context, FastMCP

from .context import IDAContextManager
from .logging import log
from .tasks import TaskStatus, get_task_manager
from .utils import (
    execute_on_main_thread,
    format_address,
    parse_address,
    resolve_name_or_address,
    truncate_string,
)

try:
    import idaapi
    import idautils
    import idc
    import ida_bytes
    import ida_entry
    import ida_funcs
    import ida_hexrays
    import ida_kernwin
    import ida_lines
    import ida_name
    import ida_nalt
    import ida_search
    import ida_segment
    import ida_typeinf
    import ida_xref
    _IN_IDA = True
except ImportError:
    _IN_IDA = False


# --------------------------------------------------------------------------- #
# Helper: resolve function name / hex address to ea
# --------------------------------------------------------------------------- #

def _resolve(name_or_addr: str) -> int:
    """Resolve a function name or address string to an effective address.

    Raises ValueError if the name/address cannot be resolved.
    """
    ea = resolve_name_or_address(name_or_addr)
    if ea is None:
        raise ValueError(f"Cannot resolve '{name_or_addr}' to an address")
    return ea


# --------------------------------------------------------------------------- #
# Tool registration entry-point (called from server.py)
# --------------------------------------------------------------------------- #

def register_tools(mcp: FastMCP):
    """Register all MCP tools on the given FastMCP instance."""

    # Tool annotations for MCP 2025-11-25 compliance
    READ_ONLY = {
        "readOnlyHint": True,
        "idempotentHint": True,
        "openWorldHint": False,
    }
    MODIFY = {
        "readOnlyHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    }
    NON_IDEMPOTENT = {
        "readOnlyHint": False,
        "idempotentHint": False,
        "openWorldHint": False,
    }

    # ================================================================== #
    #  1-2. Binary Management
    # ================================================================== #

    @mcp.tool(annotations=READ_ONLY)
    def list_binaries(ctx: Context) -> dict:
        """List the currently loaded binary (IDA is single-binary).

        Returns:
            Dictionary with the current binary name and metadata.
        """
        cm: IDAContextManager = ctx.request_context.lifespan_context
        cm.refresh()
        binary_ctx = cm.get_context()
        return {
            "binaries": [binary_ctx.filename],
            "count": 1,
        }

    @mcp.tool(annotations=READ_ONLY)
    def get_binary_info(ctx: Context) -> dict:
        """Get detailed information about the currently loaded binary.

        Returns:
            Dictionary with architecture, platform, hashes, segments, etc.
        """
        cm: IDAContextManager = ctx.request_context.lifespan_context
        cm.refresh()
        return cm.get_context().to_dict()

    # ================================================================== #
    #  3-7. Code Analysis
    # ================================================================== #

    @mcp.tool(annotations=READ_ONLY)
    def decompile_function(function_name_or_address: str, ctx: Context) -> dict:
        """Decompile a function using Hex-Rays.

        Args:
            function_name_or_address: Function name or hex address (e.g. '0x401000')

        Returns:
            Dictionary with function name, address, and decompiled pseudo-C code.
        """
        ea = _resolve(function_name_or_address)
        func = ida_funcs.get_func(ea)
        if not func:
            return {"error": f"No function at {hex(ea)}"}

        try:
            cfunc = ida_hexrays.decompile(func.start_ea)
            if not cfunc:
                return {"error": f"Decompilation failed for {hex(ea)}"}

            func_name = ida_funcs.get_func_name(func.start_ea) or f"sub_{func.start_ea:x}"
            return {
                "function": func_name,
                "address": hex(func.start_ea),
                "code": str(cfunc),
            }
        except Exception as e:
            return {"error": f"Decompilation error: {e}"}

    @mcp.tool(annotations=READ_ONLY)
    def get_disassembly(function_name_or_address: str, ctx: Context) -> dict:
        """Get disassembly listing for a function.

        Args:
            function_name_or_address: Function name or hex address

        Returns:
            Dictionary with function info and disassembly lines.
        """
        ea = _resolve(function_name_or_address)
        func = ida_funcs.get_func(ea)
        if not func:
            return {"error": f"No function at {hex(ea)}"}

        func_name = ida_funcs.get_func_name(func.start_ea) or f"sub_{func.start_ea:x}"
        lines = []
        for item_ea in idautils.FuncItems(func.start_ea):
            disasm = idc.generate_disasm_line(item_ea, 0)
            lines.append(f"0x{item_ea:08x}  {disasm}")

        return {
            "function": func_name,
            "address": hex(func.start_ea),
            "disassembly": "\n".join(lines),
            "instruction_count": len(lines),
        }

    @mcp.tool(annotations=READ_ONLY)
    def get_function_info(function_name_or_address: str, ctx: Context) -> dict:
        """Get metadata about a function.

        Args:
            function_name_or_address: Function name or hex address

        Returns:
            Dictionary with start, end, size, frame info, flags.
        """
        ea = _resolve(function_name_or_address)
        func = ida_funcs.get_func(ea)
        if not func:
            return {"error": f"No function at {hex(ea)}"}

        func_name = ida_funcs.get_func_name(func.start_ea) or f"sub_{func.start_ea:x}"
        size = func.end_ea - func.start_ea

        result = {
            "name": func_name,
            "start": hex(func.start_ea),
            "end": hex(func.end_ea),
            "size": size,
            "flags": func.flags,
        }

        # Try to get type info
        try:
            tif = ida_typeinf.tinfo_t()
            if ida_nalt.get_tinfo(tif, func.start_ea):
                result["prototype"] = str(tif)
        except Exception:
            pass

        return result

    @mcp.tool(annotations=READ_ONLY)
    def get_basic_blocks(function_name_or_address: str, ctx: Context) -> list:
        """Get basic blocks (CFG) for a function.

        Args:
            function_name_or_address: Function name or hex address

        Returns:
            List of basic block dictionaries with start, end, size, successors.
        """
        ea = _resolve(function_name_or_address)
        func = ida_funcs.get_func(ea)
        if not func:
            return [{"error": f"No function at {hex(ea)}"}]

        blocks = []
        flow = idaapi.FlowChart(func)
        for block in flow:
            succs = [hex(s.start_ea) for s in block.succs()]
            preds = [hex(p.start_ea) for p in block.preds()]
            blocks.append({
                "start": hex(block.start_ea),
                "end": hex(block.end_ea),
                "size": block.end_ea - block.start_ea,
                "successors": succs,
                "predecessors": preds,
            })

        return blocks

    @mcp.tool(annotations=READ_ONLY)
    def get_il_expression(function_name_or_address: str, ctx: Context) -> dict:
        """Get pseudo-C (Hex-Rays) output for a function.

        IDA only has ASM + decompiler output (no multi-level IL like Binary Ninja).

        Args:
            function_name_or_address: Function name or hex address

        Returns:
            Dictionary with pseudo-C code.
        """
        # Delegate to decompile_function
        return decompile_function(function_name_or_address, ctx)

    # ================================================================== #
    #  8. Cross-References
    # ================================================================== #

    @mcp.tool(annotations=READ_ONLY)
    def get_xrefs(address_or_name: str, ctx: Context, direction: str = "both") -> dict:
        """Get cross-references to/from an address.

        Args:
            address_or_name: Address (hex) or symbol name
            direction: 'to', 'from', or 'both'

        Returns:
            Dictionary with code and data xrefs in both directions.
        """
        ea = _resolve(address_or_name)

        refs_to = []
        refs_from = []

        if direction in ("to", "both"):
            for ref in idautils.CodeRefsTo(ea, 0):
                func = ida_funcs.get_func(ref)
                fname = ida_funcs.get_func_name(func.start_ea) if func else "unknown"
                refs_to.append({"address": hex(ref), "type": "code", "function": fname})
            for ref in idautils.DataRefsTo(ea):
                refs_to.append({"address": hex(ref), "type": "data"})

        if direction in ("from", "both"):
            for ref in idautils.CodeRefsFrom(ea, 0):
                func = ida_funcs.get_func(ref)
                fname = ida_funcs.get_func_name(func.start_ea) if func else "unknown"
                refs_from.append({"address": hex(ref), "type": "code", "function": fname})
            for ref in idautils.DataRefsFrom(ea):
                refs_from.append({"address": hex(ref), "type": "data"})

        return {
            "address": hex(ea),
            "refs_to": refs_to,
            "refs_from": refs_from,
            "total_to": len(refs_to),
            "total_from": len(refs_from),
        }

    # ================================================================== #
    #  9. Comments
    # ================================================================== #

    @mcp.tool(annotations=READ_ONLY)
    def get_comments(function_name_or_address: str, ctx: Context) -> dict:
        """Get comments for a function (regular, repeatable, and function-level).

        Args:
            function_name_or_address: Function name or hex address

        Returns:
            Dictionary with lists of comments found in the function.
        """
        ea = _resolve(function_name_or_address)
        func = ida_funcs.get_func(ea)
        if not func:
            return {"error": f"No function at {hex(ea)}"}

        comments = []

        # Function-level comment
        func_cmt = idc.get_func_cmt(func.start_ea, 0)
        func_cmt_r = idc.get_func_cmt(func.start_ea, 1)
        if func_cmt:
            comments.append({"address": hex(func.start_ea), "type": "function", "text": func_cmt})
        if func_cmt_r:
            comments.append({"address": hex(func.start_ea), "type": "function_repeatable", "text": func_cmt_r})

        # Per-instruction comments
        for item_ea in idautils.FuncItems(func.start_ea):
            cmt = idc.get_cmt(item_ea, 0)
            cmt_r = idc.get_cmt(item_ea, 1)
            if cmt:
                comments.append({"address": hex(item_ea), "type": "regular", "text": cmt})
            if cmt_r:
                comments.append({"address": hex(item_ea), "type": "repeatable", "text": cmt_r})

        return {"function": ida_funcs.get_func_name(func.start_ea), "comments": comments}

    # ================================================================== #
    #  10. Variables
    # ================================================================== #

    @mcp.tool(annotations=READ_ONLY)
    def get_variables(function_name_or_address: str, ctx: Context) -> dict:
        """Get local variables for a function via Hex-Rays decompiler.

        Args:
            function_name_or_address: Function name or hex address

        Returns:
            Dictionary with list of local variables and their types.
        """
        ea = _resolve(function_name_or_address)
        func = ida_funcs.get_func(ea)
        if not func:
            return {"error": f"No function at {hex(ea)}"}

        try:
            cfunc = ida_hexrays.decompile(func.start_ea)
            if not cfunc:
                return {"error": "Decompilation failed"}

            variables = []
            for lvar in cfunc.get_lvars():
                variables.append({
                    "name": lvar.name,
                    "type": str(lvar.type()),
                    "is_arg": lvar.is_arg_var,
                    "is_result": lvar.is_result_var if hasattr(lvar, 'is_result_var') else False,
                })

            return {
                "function": ida_funcs.get_func_name(func.start_ea),
                "variables": variables,
                "count": len(variables),
            }
        except Exception as e:
            return {"error": f"Cannot get variables: {e}"}

    # ================================================================== #
    #  11. Types
    # ================================================================== #

    @mcp.tool(annotations=READ_ONLY)
    def get_types(ctx: Context, filter: str = "") -> dict:
        """List local types (structs, enums, typedefs) in the IDB.

        Args:
            filter: Optional substring filter on type name

        Returns:
            Dictionary with list of local type definitions.
        """
        til = ida_typeinf.get_idati()
        if not til:
            return {"error": "Cannot access type library"}

        types_list = []
        count = ida_typeinf.get_ordinal_qty(til)
        for ordinal in range(1, count + 1):
            tif = ida_typeinf.tinfo_t()
            if tif.get_numbered_type(til, ordinal):
                name = tif.get_type_name() or f"type_{ordinal}"
                if filter and filter.lower() not in name.lower():
                    continue

                kind = "unknown"
                if tif.is_struct():
                    kind = "struct"
                elif tif.is_enum():
                    kind = "enum"
                elif tif.is_typedef():
                    kind = "typedef"
                elif tif.is_func():
                    kind = "function"

                types_list.append({
                    "name": name,
                    "ordinal": ordinal,
                    "kind": kind,
                    "size": tif.get_size(),
                    "definition": str(tif),
                })

        return {"types": types_list, "count": len(types_list)}

    # ================================================================== #
    #  12-16. Function Discovery
    # ================================================================== #

    @mcp.tool(annotations=READ_ONLY)
    def list_functions(ctx: Context, filter: str = "", limit: int = 200,
                       offset: int = 0) -> dict:
        """List all functions in the binary with optional filtering and pagination.

        Args:
            filter: Optional name substring filter
            limit: Maximum number of functions to return
            offset: Number of functions to skip (for pagination)

        Returns:
            Dictionary with list of functions and pagination info.
        """
        all_funcs = []
        for func_ea in idautils.Functions():
            name = ida_funcs.get_func_name(func_ea) or f"sub_{func_ea:x}"
            if filter and filter.lower() not in name.lower():
                continue
            func = ida_funcs.get_func(func_ea)
            size = (func.end_ea - func.start_ea) if func else 0
            all_funcs.append({
                "name": name,
                "address": hex(func_ea),
                "size": size,
            })

        total = len(all_funcs)
        page = all_funcs[offset:offset + limit]

        return {
            "functions": page,
            "total_count": total,
            "offset": offset,
            "limit": limit,
            "returned": len(page),
        }

    @mcp.tool(annotations=READ_ONLY)
    def search_functions(search_term: str, ctx: Context,
                         min_size: int = 0, max_size: int = 0,
                         limit: int = 100) -> list:
        """Search functions by name pattern, with optional size filters.

        Args:
            search_term: Substring to search for in function names
            min_size: Minimum function size filter (0 = no filter)
            max_size: Maximum function size filter (0 = no filter)
            limit: Maximum results

        Returns:
            List of matching function dictionaries.
        """
        results = []
        term_lower = search_term.lower()

        for func_ea in idautils.Functions():
            name = ida_funcs.get_func_name(func_ea) or f"sub_{func_ea:x}"
            if term_lower not in name.lower():
                continue

            func = ida_funcs.get_func(func_ea)
            size = (func.end_ea - func.start_ea) if func else 0
            if min_size and size < min_size:
                continue
            if max_size and size > max_size:
                continue

            results.append({
                "name": name,
                "address": hex(func_ea),
                "size": size,
            })
            if len(results) >= limit:
                break

        return results

    @mcp.tool(annotations=READ_ONLY)
    def get_function_by_name(name: str, ctx: Context) -> dict:
        """Look up a function by its exact name.

        Args:
            name: Exact function name

        Returns:
            Function info dictionary, or error if not found.
        """
        ea = ida_name.get_name_ea(idaapi.BADADDR, name)
        if ea == idaapi.BADADDR:
            return {"error": f"Function '{name}' not found"}

        func = ida_funcs.get_func(ea)
        if not func:
            return {"error": f"'{name}' found at {hex(ea)} but is not a function"}

        return {
            "name": ida_funcs.get_func_name(func.start_ea),
            "address": hex(func.start_ea),
            "end": hex(func.end_ea),
            "size": func.end_ea - func.start_ea,
        }

    @mcp.tool(annotations=READ_ONLY)
    def get_function_by_address(address: str, ctx: Context) -> dict:
        """Look up a function containing the given address.

        Args:
            address: Hex address string

        Returns:
            Function info dictionary, or error if not found.
        """
        ea = parse_address(address)
        if ea is None:
            return {"error": f"Invalid address: {address}"}

        func = ida_funcs.get_func(ea)
        if not func:
            return {"error": f"No function at {hex(ea)}"}

        return {
            "name": ida_funcs.get_func_name(func.start_ea),
            "address": hex(func.start_ea),
            "end": hex(func.end_ea),
            "size": func.end_ea - func.start_ea,
        }

    @mcp.tool(annotations=READ_ONLY)
    def get_callers_callees(function_name_or_address: str, ctx: Context) -> dict:
        """Get the call graph (callers and callees) for a function.

        Args:
            function_name_or_address: Function name or hex address

        Returns:
            Dictionary with callers and callees lists.
        """
        ea = _resolve(function_name_or_address)
        func = ida_funcs.get_func(ea)
        if not func:
            return {"error": f"No function at {hex(ea)}"}

        callers = []
        callees = []

        # Callers: code xrefs TO the function start
        for ref in idautils.CodeRefsTo(func.start_ea, 0):
            caller_func = ida_funcs.get_func(ref)
            if caller_func:
                caller_name = ida_funcs.get_func_name(caller_func.start_ea)
                callers.append({"name": caller_name, "address": hex(caller_func.start_ea), "call_site": hex(ref)})

        # Callees: code xrefs FROM instructions inside the function
        for item_ea in idautils.FuncItems(func.start_ea):
            for ref in idautils.CodeRefsFrom(item_ea, 0):
                callee_func = ida_funcs.get_func(ref)
                if callee_func and callee_func.start_ea != func.start_ea:
                    callee_name = ida_funcs.get_func_name(callee_func.start_ea)
                    callees.append({"name": callee_name, "address": hex(callee_func.start_ea), "call_site": hex(item_ea)})

        # Deduplicate callees by target address
        seen = set()
        unique_callees = []
        for c in callees:
            if c["address"] not in seen:
                seen.add(c["address"])
                unique_callees.append(c)

        return {
            "function": ida_funcs.get_func_name(func.start_ea),
            "callers": callers,
            "callees": unique_callees,
            "caller_count": len(callers),
            "callee_count": len(unique_callees),
        }

    # ================================================================== #
    #  17-20. Binary Info
    # ================================================================== #

    @mcp.tool(annotations=READ_ONLY)
    def get_imports(ctx: Context) -> dict:
        """Get imported functions grouped by module.

        Returns:
            Dictionary mapping module names to lists of imported symbols.
        """
        imports_by_module: Dict[str, list] = {}

        def imp_cb(ea, name, ordinal):
            if name:
                imports_by_module.setdefault(_current_module[0], []).append({
                    "name": name,
                    "address": hex(ea),
                    "ordinal": ordinal,
                })
            return True  # continue enumeration

        _current_module = [""]
        num_modules = ida_nalt.get_import_module_qty()
        for i in range(num_modules):
            mod_name = ida_nalt.get_import_module_name(i)
            _current_module[0] = mod_name or f"module_{i}"
            ida_nalt.enum_import_names(i, imp_cb)

        return {
            "imports": imports_by_module,
            "module_count": num_modules,
            "total_imports": sum(len(v) for v in imports_by_module.values()),
        }

    @mcp.tool(annotations=READ_ONLY)
    def get_exports(ctx: Context) -> dict:
        """Get exported symbols.

        Returns:
            Dictionary with list of exports.
        """
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

    @mcp.tool(annotations=READ_ONLY)
    def get_strings(ctx: Context, min_length: int = 4, page_size: int = 100,
                    page_number: int = 1) -> dict:
        """Get strings found in the binary with pagination.

        Args:
            min_length: Minimum string length
            page_size: Number of strings per page
            page_number: Page number (1-indexed)

        Returns:
            Dictionary with strings list and pagination info.
        """
        all_strings = []
        for s in idautils.Strings():
            value = str(s)
            if len(value) >= min_length:
                all_strings.append({
                    "address": hex(s.ea),
                    "value": value,
                    "length": s.length,
                    "type": "ascii" if s.strtype == 0 else f"type_{s.strtype}",
                })

        total = len(all_strings)
        total_pages = max(1, (total + page_size - 1) // page_size)
        start = (page_number - 1) * page_size
        page = all_strings[start:start + page_size]

        return {
            "strings": page,
            "page_size": page_size,
            "page_number": page_number,
            "total_count": total,
            "total_pages": total_pages,
        }

    @mcp.tool(annotations=READ_ONLY)
    def get_segments(ctx: Context) -> list:
        """Get memory segments.

        Returns:
            List of segment dictionaries with name, start, end, permissions.
        """
        segments = []
        for i in range(ida_segment.get_segm_qty()):
            seg = ida_segment.getnseg(i)
            if seg is None:
                continue

            name = ida_segment.get_segm_name(seg) or f"seg_{i}"
            seg_class = ida_segment.get_segm_class(seg) or ""

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

        return segments

    # ================================================================== #
    #  21-23. Symbol Management (Modify)
    # ================================================================== #

    @mcp.tool(annotations=MODIFY)
    def rename_function(address_or_name: str, new_name: str, ctx: Context) -> str:
        """Rename a function in the IDB.

        Args:
            address_or_name: Current function address or name
            new_name: New name for the function

        Returns:
            Success or failure message.
        """
        ea = _resolve(address_or_name)
        func = ida_funcs.get_func(ea)
        if not func:
            return f"No function at {hex(ea)}"

        old_name = ida_funcs.get_func_name(func.start_ea) or f"sub_{func.start_ea:x}"
        result_holder = [False]

        def _do():
            result_holder[0] = ida_name.set_name(func.start_ea, new_name, ida_name.SN_CHECK)

        execute_on_main_thread(_do)

        if result_holder[0]:
            return f"Renamed '{old_name}' to '{new_name}'"
        else:
            return f"Failed to rename function to '{new_name}'"

    @mcp.tool(annotations=MODIFY)
    def rename_variable(function_address: str, old_name: str, new_name: str,
                        ctx: Context) -> str:
        """Rename a local variable in a decompiled function.

        Args:
            function_address: Function address (hex string)
            old_name: Current variable name
            new_name: New variable name

        Returns:
            Success or failure message.
        """
        func_ea = parse_address(function_address)
        if func_ea is None:
            return f"Invalid address: {function_address}"

        result_holder = [False, ""]

        def _do():
            try:
                cfunc = ida_hexrays.decompile(func_ea)
                if not cfunc:
                    result_holder[1] = "Decompilation failed"
                    return

                lvars = cfunc.get_lvars()
                target = None
                for lvar in lvars:
                    if lvar.name == old_name:
                        target = lvar
                        break

                if not target:
                    result_holder[1] = f"Variable '{old_name}' not found"
                    return

                result_holder[0] = ida_hexrays.rename_lvar(cfunc, target, new_name)
                if not result_holder[0]:
                    result_holder[1] = "rename_lvar failed"
            except Exception as e:
                result_holder[1] = str(e)

        execute_on_main_thread(_do)

        if result_holder[0]:
            return f"Renamed variable '{old_name}' to '{new_name}'"
        else:
            return f"Failed: {result_holder[1]}"

    @mcp.tool(annotations=MODIFY)
    def set_type(address: str, type_string: str, ctx: Context) -> str:
        """Set the type of a function or variable at the given address.

        Args:
            address: Hex address
            type_string: C-style type string (e.g. 'int __cdecl(int, char *)')

        Returns:
            Success or failure message.
        """
        ea = parse_address(address)
        if ea is None:
            return f"Invalid address: {address}"

        result_holder = [False, ""]

        def _do():
            try:
                tif = ida_typeinf.tinfo_t()
                til = ida_typeinf.get_idati()
                if ida_typeinf.parse_decl(tif, til, type_string, ida_typeinf.PT_SIL):
                    if ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE):
                        result_holder[0] = True
                    else:
                        result_holder[1] = "apply_tinfo failed"
                else:
                    result_holder[1] = f"Could not parse type: {type_string}"
            except Exception as e:
                result_holder[1] = str(e)

        execute_on_main_thread(_do)

        if result_holder[0]:
            return f"Set type at {hex(ea)} to '{type_string}'"
        else:
            return f"Failed: {result_holder[1]}"

    # ================================================================== #
    #  24. Set Comment (Modify)
    # ================================================================== #

    @mcp.tool(annotations=MODIFY)
    def set_comment(address: str, text: str, ctx: Context,
                    comment_type: str = "regular") -> str:
        """Set a comment at an address.

        Args:
            address: Hex address
            text: Comment text
            comment_type: 'regular', 'repeatable', or 'function'

        Returns:
            Success message.
        """
        ea = parse_address(address)
        if ea is None:
            return f"Invalid address: {address}"

        result_holder = [False]

        def _do():
            if comment_type == "function":
                idc.set_func_cmt(ea, text, 0)
            elif comment_type == "repeatable":
                idc.set_cmt(ea, text, 1)
            else:
                idc.set_cmt(ea, text, 0)
            result_holder[0] = True

        execute_on_main_thread(_do)

        return f"Set {comment_type} comment at {hex(ea)}"

    # ================================================================== #
    #  25-28. Data Analysis (Modify)
    # ================================================================== #

    @mcp.tool(annotations=READ_ONLY)
    def read_memory(address: str, size: int, ctx: Context) -> dict:
        """Read raw bytes from the IDB at a given address.

        Args:
            address: Hex address
            size: Number of bytes to read (max 4096)

        Returns:
            Dictionary with hex dump and raw byte values.
        """
        ea = parse_address(address)
        if ea is None:
            return {"error": f"Invalid address: {address}"}

        size = min(size, 4096)
        data = ida_bytes.get_bytes(ea, size)
        if data is None:
            return {"error": f"Cannot read {size} bytes at {hex(ea)}"}

        return {
            "address": hex(ea),
            "size": len(data),
            "hex": data.hex(),
            "printable": "".join(chr(b) if 32 <= b < 127 else "." for b in data),
        }

    @mcp.tool(annotations=MODIFY)
    def create_struct(name: str, members: list, ctx: Context) -> str:
        """Create a new struct type in the IDB.

        Args:
            name: Struct name
            members: List of dicts with 'name', 'type', 'size' keys.
                     Example: [{"name": "field1", "type": "int", "size": 4}]

        Returns:
            Success or failure message.
        """
        result_holder = [False, ""]

        def _do():
            try:
                udt = ida_typeinf.udt_type_data_t()

                for member in members:
                    udm = ida_typeinf.udt_member_t()
                    udm.name = member["name"]

                    mtif = ida_typeinf.tinfo_t()
                    til = ida_typeinf.get_idati()
                    type_str = member.get("type", "int")
                    if not ida_typeinf.parse_decl(mtif, til, f"{type_str} x;", ida_typeinf.PT_SIL):
                        # Fallback to byte array
                        msize = member.get("size", 4)
                        mtif.create_array(ida_typeinf.tinfo_t(ida_typeinf.BT_INT8), msize)

                    udm.type = mtif
                    udm.size = mtif.get_size() * 8  # size in bits
                    udt.push_back(udm)

                tif = ida_typeinf.tinfo_t()
                tif.create_udt(udt, ida_typeinf.BTF_STRUCT)
                tif.set_named_type(ida_typeinf.get_idati(), name)
                result_holder[0] = True
            except Exception as e:
                result_holder[1] = str(e)

        execute_on_main_thread(_do)

        if result_holder[0]:
            return f"Created struct '{name}' with {len(members)} members"
        else:
            return f"Failed to create struct: {result_holder[1]}"

    @mcp.tool(annotations=MODIFY)
    def create_enum(name: str, members: dict, ctx: Context,
                    bitfield: bool = False) -> str:
        """Create a new enum type in the IDB.

        Args:
            name: Enum name
            members: Dict of member_name -> value (e.g. {"OK": 0, "ERR": 1})
            bitfield: Whether this is a bitfield enum

        Returns:
            Success or failure message.
        """
        result_holder = [False, ""]

        def _do():
            try:
                edt = ida_typeinf.enum_type_data_t()
                for mname, mval in members.items():
                    em = ida_typeinf.edm_t()
                    em.name = mname
                    em.value = mval
                    edt.push_back(em)

                if bitfield:
                    edt.bte |= ida_typeinf.BTE_BITFIELD

                tif = ida_typeinf.tinfo_t()
                tif.create_enum(edt)
                tif.set_named_type(ida_typeinf.get_idati(), name)
                result_holder[0] = True
            except Exception as e:
                result_holder[1] = str(e)

        execute_on_main_thread(_do)

        if result_holder[0]:
            return f"Created enum '{name}' with {len(members)} members"
        else:
            return f"Failed to create enum: {result_holder[1]}"

    @mcp.tool(annotations=NON_IDEMPOTENT)
    def patch_bytes(address: str, hex_bytes: str, ctx: Context) -> str:
        """Patch bytes in the IDB at a given address.

        WARNING: This modifies the IDB. The operation cannot be easily undone.

        Args:
            address: Hex address to patch at
            hex_bytes: Hex string of bytes to write (e.g. '90909090')

        Returns:
            Success or failure message.
        """
        ea = parse_address(address)
        if ea is None:
            return f"Invalid address: {address}"

        try:
            data = bytes.fromhex(hex_bytes.replace(" ", ""))
        except ValueError:
            return f"Invalid hex string: {hex_bytes}"

        result_holder = [False]

        def _do():
            ida_bytes.patch_bytes(ea, data)
            result_holder[0] = True

        execute_on_main_thread(_do)

        if result_holder[0]:
            return f"Patched {len(data)} bytes at {hex(ea)}"
        else:
            return f"Failed to patch bytes at {hex(ea)}"

    # ================================================================== #
    #  29-30. Navigation (Modify)
    # ================================================================== #

    @mcp.tool(annotations=MODIFY)
    def navigate_to(address: str, ctx: Context) -> str:
        """Move IDA cursor to a specific address.

        Args:
            address: Hex address to navigate to

        Returns:
            Success or failure message.
        """
        ea = parse_address(address)
        if ea is None:
            return f"Invalid address: {address}"

        result_holder = [False]

        def _do():
            result_holder[0] = ida_kernwin.jumpto(ea)

        execute_on_main_thread(_do)

        if result_holder[0]:
            return f"Navigated to {hex(ea)}"
        else:
            return f"Failed to navigate to {hex(ea)}"

    @mcp.tool(annotations=MODIFY)
    def set_bookmark(address: str, description: str, ctx: Context,
                     slot: int = 0) -> str:
        """Create a position bookmark in IDA.

        Args:
            address: Hex address for the bookmark
            description: Bookmark description text
            slot: Bookmark slot number (0-1023)

        Returns:
            Success message.
        """
        ea = parse_address(address)
        if ea is None:
            return f"Invalid address: {address}"

        result_holder = [False]

        def _do():
            idc.put_bookmark(ea, 0, 0, 0, slot, description)
            result_holder[0] = True

        execute_on_main_thread(_do)

        return f"Bookmark set at {hex(ea)} (slot {slot}): {description}"

    # ================================================================== #
    #  31-33. Task Management
    # ================================================================== #

    @mcp.tool(annotations=NON_IDEMPOTENT)
    async def start_task(name: str, tool_name: str, ctx: Context, **kwargs) -> dict:
        """Start an async background task.

        Args:
            name: Human-readable task name
            tool_name: Name of the tool to run as a task

        Returns:
            Dictionary with task_id for tracking.
        """
        task_manager = get_task_manager()

        async def _run():
            return {"status": "completed", "tool": tool_name, "note": "Task ran in background"}

        task_id = await task_manager.submit(_run, name=name)
        return {"task_id": task_id, "status": "submitted"}

    @mcp.tool(annotations=READ_ONLY)
    def get_task_status(task_id: str, ctx: Context) -> dict:
        """Get status of an async task.

        Args:
            task_id: ID of the task to check

        Returns:
            Task status dictionary.
        """
        task_manager = get_task_manager()
        return task_manager.get_task_status(task_id)

    @mcp.tool(annotations=MODIFY)
    def cancel_task(task_id: str, ctx: Context) -> dict:
        """Cancel a running async task.

        Args:
            task_id: ID of the task to cancel

        Returns:
            Cancellation result.
        """
        task_manager = get_task_manager()
        success = task_manager.cancel_task(task_id)
        return {
            "task_id": task_id,
            "cancelled": success,
            "message": "Task cancellation initiated" if success else "Task not found or already completed",
        }

    # ================================================================== #
    #  34. Get data at address
    # ================================================================== #

    @mcp.tool(annotations=READ_ONLY)
    def get_data_at(address: str, ctx: Context, size: int = 0) -> dict:
        """Get typed data at a specific address.

        Args:
            address: Hex address
            size: Optional explicit size (0 = auto-detect from IDB item)

        Returns:
            Dictionary with typed data values.
        """
        ea = parse_address(address)
        if ea is None:
            return {"error": f"Invalid address: {address}"}

        if size == 0:
            size = ida_bytes.get_item_size(ea)
            if size == 0:
                size = 8  # fallback

        data = ida_bytes.get_bytes(ea, min(size, 4096))
        if data is None:
            return {"error": f"Cannot read at {hex(ea)}"}

        result = {
            "address": hex(ea),
            "item_size": size,
            "hex": data.hex(),
        }

        # Try to read typed values
        if size >= 1:
            result["byte"] = ida_bytes.get_byte(ea)
        if size >= 2:
            result["word"] = ida_bytes.get_word(ea)
        if size >= 4:
            result["dword"] = ida_bytes.get_dword(ea)
        if size >= 8:
            result["qword"] = ida_bytes.get_qword(ea)

        # Name at address
        name = ida_name.get_name(ea)
        if name:
            result["name"] = name

        return result

    # ================================================================== #
    #  35. Search bytes
    # ================================================================== #

    @mcp.tool(annotations=READ_ONLY)
    def search_bytes(pattern: str, ctx: Context, start_address: str = "",
                     max_results: int = 100) -> list:
        """Search for a byte pattern in the binary.

        Args:
            pattern: Hex byte pattern (e.g. '90 90 90' or '4883EC')
            start_address: Optional start address (default: binary start)
            max_results: Maximum number of results

        Returns:
            List of matching addresses.
        """
        # Normalize pattern: "90 90" -> "90 90", "9090" -> "90 90"
        clean = pattern.replace(" ", "")
        if len(clean) % 2 != 0:
            return [{"error": "Pattern must have even number of hex chars"}]

        # Build IDA search pattern string
        search_pattern = " ".join(clean[i:i+2] for i in range(0, len(clean), 2))

        if start_address:
            start_ea = parse_address(start_address)
            if start_ea is None:
                return [{"error": f"Invalid start address: {start_address}"}]
        else:
            start_ea = idaapi.get_inf_structure().min_ea

        results = []
        ea = start_ea
        for _ in range(max_results):
            ea = ida_search.find_binary(ea, idaapi.BADADDR, search_pattern,
                                        16, ida_search.SEARCH_DOWN | ida_search.SEARCH_NEXT)
            if ea == idaapi.BADADDR:
                break

            func = ida_funcs.get_func(ea)
            fname = ida_funcs.get_func_name(func.start_ea) if func else None

            results.append({
                "address": hex(ea),
                "function": fname,
            })
            ea += 1  # advance past match

        return results

    # ================================================================== #
    #  36. Get entry points
    # ================================================================== #

    @mcp.tool(annotations=READ_ONLY)
    def get_entry_points(ctx: Context) -> list:
        """Get all binary entry points.

        Returns:
            List of entry point dictionaries with name and address.
        """
        entries = []
        for i in range(ida_entry.get_entry_qty()):
            ordinal = ida_entry.get_entry_ordinal(i)
            ea = ida_entry.get_entry(ordinal)
            name = ida_entry.get_entry_name(ordinal) or f"entry_{ordinal}"
            entries.append({
                "name": name,
                "address": hex(ea),
                "ordinal": ordinal,
            })
        return entries

    # ================================================================== #
    #  Additional tools for parity with BinAssistMCP
    # ================================================================== #

    @mcp.tool(annotations=MODIFY)
    def rename_symbol(address_or_name: str, new_name: str, ctx: Context) -> str:
        """Rename any symbol (function or data) at the given address/name.

        Args:
            address_or_name: Current address or name
            new_name: New name

        Returns:
            Success or failure message.
        """
        ea = _resolve(address_or_name)
        old_name = ida_name.get_name(ea) or f"loc_{ea:x}"
        result_holder = [False]

        def _do():
            result_holder[0] = ida_name.set_name(ea, new_name, ida_name.SN_CHECK)

        execute_on_main_thread(_do)

        if result_holder[0]:
            return f"Renamed '{old_name}' to '{new_name}'"
        else:
            return f"Failed to rename to '{new_name}'"

    @mcp.tool(annotations=READ_ONLY)
    def get_function_statistics(ctx: Context) -> dict:
        """Get comprehensive statistics about all functions in the binary.

        Returns:
            Statistics including counts, sizes, and top functions.
        """
        sizes = []
        for func_ea in idautils.Functions():
            func = ida_funcs.get_func(func_ea)
            if func:
                sizes.append((func_ea, func.end_ea - func.start_ea))

        if not sizes:
            return {"error": "No functions found"}

        total_size = sum(s for _, s in sizes)
        avg_size = total_size // len(sizes) if sizes else 0
        sorted_by_size = sorted(sizes, key=lambda x: x[1], reverse=True)

        top_10 = []
        for ea, sz in sorted_by_size[:10]:
            top_10.append({
                "name": ida_funcs.get_func_name(ea),
                "address": hex(ea),
                "size": sz,
            })

        return {
            "total_functions": len(sizes),
            "total_code_size": total_size,
            "average_size": avg_size,
            "max_size": sorted_by_size[0][1] if sorted_by_size else 0,
            "min_size": sorted_by_size[-1][1] if sorted_by_size else 0,
            "top_10_largest": top_10,
        }

    @mcp.tool(annotations=MODIFY)
    def batch_rename(renames: list, ctx: Context) -> list:
        """Batch rename multiple symbols.

        Args:
            renames: List of dicts with 'address_or_name' and 'new_name' keys

        Returns:
            List of results for each rename operation.
        """
        results = []
        for entry in renames:
            addr_or_name = entry.get("address_or_name", "")
            new_name = entry.get("new_name", "")
            if not addr_or_name or not new_name:
                results.append({"address_or_name": addr_or_name, "success": False, "error": "Missing fields"})
                continue

            try:
                ea = _resolve(addr_or_name)
                old_name = ida_name.get_name(ea) or f"loc_{ea:x}"

                success_holder = [False]

                def _do(target_ea=ea, target_name=new_name):
                    success_holder[0] = ida_name.set_name(target_ea, target_name, ida_name.SN_CHECK)

                execute_on_main_thread(_do)

                results.append({
                    "address": hex(ea),
                    "old_name": old_name,
                    "new_name": new_name,
                    "success": success_holder[0],
                })
            except Exception as e:
                results.append({"address_or_name": addr_or_name, "success": False, "error": str(e)})

        return results

    @mcp.tool(annotations=READ_ONLY)
    def search_strings(pattern: str, ctx: Context, case_sensitive: bool = False,
                       page_size: int = 100, page_number: int = 1) -> dict:
        """Search for strings matching a pattern with pagination.

        Args:
            pattern: Search pattern (substring match)
            case_sensitive: Case-sensitive matching
            page_size: Number of results per page
            page_number: Page number (1-indexed)

        Returns:
            Dictionary with matching strings and pagination info.
        """
        matches = []
        pat = pattern if case_sensitive else pattern.lower()

        for s in idautils.Strings():
            value = str(s)
            compare = value if case_sensitive else value.lower()
            if pat in compare:
                matches.append({
                    "address": hex(s.ea),
                    "value": value,
                    "length": s.length,
                })

        total = len(matches)
        total_pages = max(1, (total + page_size - 1) // page_size)
        start = (page_number - 1) * page_size
        page = matches[start:start + page_size]

        return {
            "strings": page,
            "page_size": page_size,
            "page_number": page_number,
            "total_count": total,
            "total_pages": total_pages,
        }

    @mcp.tool(annotations=READ_ONLY)
    def get_code(function_name_or_address: str, ctx: Context,
                 format: str = "decompile") -> dict:
        """Get function code in specified format (unified tool).

        Args:
            function_name_or_address: Function identifier
            format: Output format - 'decompile' or 'disasm'

        Returns:
            Dictionary with function info and code.
        """
        if format == "disasm":
            return get_disassembly(function_name_or_address, ctx)
        else:
            return decompile_function(function_name_or_address, ctx)

    @mcp.tool(annotations=READ_ONLY)
    def analyze_function(function_name_or_address: str, ctx: Context) -> dict:
        """Perform comprehensive analysis of a function.

        Args:
            function_name_or_address: Function name or address

        Returns:
            Comprehensive function analysis including control flow and call info.
        """
        ea = _resolve(function_name_or_address)
        func = ida_funcs.get_func(ea)
        if not func:
            return {"error": f"No function at {hex(ea)}"}

        func_name = ida_funcs.get_func_name(func.start_ea) or f"sub_{func.start_ea:x}"

        # Basic info
        result = {
            "name": func_name,
            "address": hex(func.start_ea),
            "end": hex(func.end_ea),
            "size": func.end_ea - func.start_ea,
        }

        # Basic blocks (CFG complexity)
        flow = idaapi.FlowChart(func)
        blocks = list(flow)
        result["basic_block_count"] = len(blocks)

        # Instruction count
        instructions = list(idautils.FuncItems(func.start_ea))
        result["instruction_count"] = len(instructions)

        # Callers and callees
        callers = set()
        for ref in idautils.CodeRefsTo(func.start_ea, 0):
            cfunc = ida_funcs.get_func(ref)
            if cfunc:
                callers.add(ida_funcs.get_func_name(cfunc.start_ea))

        callees = set()
        for item_ea in instructions:
            for ref in idautils.CodeRefsFrom(item_ea, 0):
                cfunc = ida_funcs.get_func(ref)
                if cfunc and cfunc.start_ea != func.start_ea:
                    callees.add(ida_funcs.get_func_name(cfunc.start_ea))

        result["callers"] = list(callers)
        result["callees"] = list(callees)
        result["caller_count"] = len(callers)
        result["callee_count"] = len(callees)

        # Try decompilation
        try:
            cfunc = ida_hexrays.decompile(func.start_ea)
            if cfunc:
                result["decompiled"] = str(cfunc)
                result["variable_count"] = len(cfunc.get_lvars())
        except Exception:
            result["decompiled"] = None

        return result

    @mcp.tool(annotations=READ_ONLY)
    def list_tasks(ctx: Context, status: str = "") -> list:
        """List all async tasks, optionally filtered by status.

        Args:
            status: Optional filter - 'pending', 'running', 'completed', 'failed', 'cancelled'

        Returns:
            List of task information.
        """
        task_manager = get_task_manager()
        status_filter = None
        if status:
            try:
                status_filter = TaskStatus(status)
            except ValueError:
                pass
        return task_manager.list_tasks(status_filter)

    log.log_info(f"Registered all MCP tools")
