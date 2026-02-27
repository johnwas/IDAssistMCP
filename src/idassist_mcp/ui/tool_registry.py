"""
Static catalog of all IDAssistMCP MCP tools with metadata.

No PySide6 imports — usable by both UI and server-side code.
"""

from dataclasses import dataclass
from typing import Dict, List


@dataclass(frozen=True)
class ToolInfo:
    """Metadata for a single MCP tool."""
    name: str
    display_name: str
    category: str
    description: str
    annotation: str  # "read_only", "modify", or "non_idempotent"


# Complete catalog of all 43 MCP tools
TOOL_CATALOG: List[ToolInfo] = [
    # Binary Management
    ToolInfo("list_binaries", "List Binaries", "Binary Management", "List the currently loaded binary", "read_only"),
    ToolInfo("get_binary_info", "Get Binary Info", "Binary Management", "Get detailed binary metadata", "read_only"),

    # Code Analysis
    ToolInfo("decompile_function", "Decompile Function", "Code Analysis", "Decompile a function using Hex-Rays", "read_only"),
    ToolInfo("get_disassembly", "Get Disassembly", "Code Analysis", "Get disassembly listing for a function", "read_only"),
    ToolInfo("get_function_info", "Get Function Info", "Code Analysis", "Get metadata about a function", "read_only"),
    ToolInfo("get_basic_blocks", "Get Basic Blocks", "Code Analysis", "Get basic blocks (CFG) for a function", "read_only"),
    ToolInfo("get_il_expression", "Get IL Expression", "Code Analysis", "Get pseudo-C output for a function", "read_only"),
    ToolInfo("get_code", "Get Code", "Code Analysis", "Get function code in specified format", "read_only"),
    ToolInfo("analyze_function", "Analyze Function", "Code Analysis", "Comprehensive function analysis", "read_only"),

    # Cross-References
    ToolInfo("get_xrefs", "Get XRefs", "Cross-References", "Get cross-references to/from an address", "read_only"),
    ToolInfo("get_callers_callees", "Get Callers/Callees", "Cross-References", "Get call graph for a function", "read_only"),

    # Comments & Variables
    ToolInfo("get_comments", "Get Comments", "Comments & Variables", "Get comments for a function", "read_only"),
    ToolInfo("get_variables", "Get Variables", "Comments & Variables", "Get local variables via Hex-Rays", "read_only"),

    # Types
    ToolInfo("get_types", "Get Types", "Types", "List local types in the IDB", "read_only"),

    # Function Discovery
    ToolInfo("list_functions", "List Functions", "Function Discovery", "List all functions with filtering", "read_only"),
    ToolInfo("search_functions", "Search Functions", "Function Discovery", "Search functions by name pattern", "read_only"),
    ToolInfo("get_function_by_name", "Get Function by Name", "Function Discovery", "Look up function by exact name", "read_only"),
    ToolInfo("get_function_by_address", "Get Function by Address", "Function Discovery", "Look up function at address", "read_only"),
    ToolInfo("get_function_statistics", "Function Statistics", "Function Discovery", "Get statistics about all functions", "read_only"),

    # Binary Info
    ToolInfo("get_imports", "Get Imports", "Binary Info", "Get imported functions by module", "read_only"),
    ToolInfo("get_exports", "Get Exports", "Binary Info", "Get exported symbols", "read_only"),
    ToolInfo("get_strings", "Get Strings", "Binary Info", "Get strings with pagination", "read_only"),
    ToolInfo("get_segments", "Get Segments", "Binary Info", "Get memory segments", "read_only"),
    ToolInfo("get_entry_points", "Get Entry Points", "Binary Info", "Get all binary entry points", "read_only"),

    # Data Analysis
    ToolInfo("read_memory", "Read Memory", "Data Analysis", "Read raw bytes from the IDB", "read_only"),
    ToolInfo("get_data_at", "Get Data At", "Data Analysis", "Get typed data at address", "read_only"),
    ToolInfo("search_bytes", "Search Bytes", "Data Analysis", "Search for byte pattern", "read_only"),
    ToolInfo("search_strings", "Search Strings", "Data Analysis", "Search strings by pattern", "read_only"),

    # Symbol Management (modify)
    ToolInfo("rename_function", "Rename Function", "Symbol Management", "Rename a function in the IDB", "modify"),
    ToolInfo("rename_variable", "Rename Variable", "Symbol Management", "Rename a local variable", "modify"),
    ToolInfo("rename_symbol", "Rename Symbol", "Symbol Management", "Rename any symbol", "modify"),
    ToolInfo("batch_rename", "Batch Rename", "Symbol Management", "Batch rename multiple symbols", "modify"),
    ToolInfo("set_type", "Set Type", "Symbol Management", "Set type of function or variable", "modify"),
    ToolInfo("set_comment", "Set Comment", "Symbol Management", "Set a comment at an address", "modify"),

    # Structure Creation (modify)
    ToolInfo("create_struct", "Create Struct", "Structure Creation", "Create a new struct type", "modify"),
    ToolInfo("create_enum", "Create Enum", "Structure Creation", "Create a new enum type", "modify"),

    # Patching (non-idempotent)
    ToolInfo("patch_bytes", "Patch Bytes", "Patching", "Patch bytes in the IDB", "non_idempotent"),

    # Navigation (modify)
    ToolInfo("navigate_to", "Navigate To", "Navigation", "Move IDA cursor to address", "modify"),
    ToolInfo("set_bookmark", "Set Bookmark", "Navigation", "Create a position bookmark", "modify"),

    # Task Management
    ToolInfo("start_task", "Start Task", "Task Management", "Start an async background task", "non_idempotent"),
    ToolInfo("get_task_status", "Get Task Status", "Task Management", "Get status of async task", "read_only"),
    ToolInfo("cancel_task", "Cancel Task", "Task Management", "Cancel a running async task", "modify"),
    ToolInfo("list_tasks", "List Tasks", "Task Management", "List all async tasks", "read_only"),
]

# Build lookup indexes
_TOOLS_BY_NAME: Dict[str, ToolInfo] = {t.name: t for t in TOOL_CATALOG}


def get_tool_info(name: str) -> ToolInfo | None:
    """Get tool info by name."""
    return _TOOLS_BY_NAME.get(name)


def get_tool_names() -> List[str]:
    """Get all tool names."""
    return [t.name for t in TOOL_CATALOG]


def get_tools_by_category() -> Dict[str, List[ToolInfo]]:
    """Get tools grouped by category."""
    result: Dict[str, List[ToolInfo]] = {}
    for tool in TOOL_CATALOG:
        result.setdefault(tool.category, []).append(tool)
    return result


def get_read_only_tool_names() -> List[str]:
    """Get names of all read-only tools."""
    return [t.name for t in TOOL_CATALOG if t.annotation == "read_only"]
