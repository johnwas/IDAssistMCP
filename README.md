# IDAssistMCP

Standalone MCP (Model Context Protocol) server plugin for **IDA Pro 9.x** that exposes IDA's analysis capabilities to LLM clients like Claude Desktop.

## Features

- **43 MCP tools** covering binary analysis, decompilation, cross-references, symbol management, type system, navigation, and more
- **8 MCP resources** for browsable binary metadata (triage, functions, imports, exports, strings, info, segments, sections)
- **7 guided prompts** for common reverse engineering workflows (function analysis, vulnerability identification, documentation, data flow tracing, function comparison, struct recovery, network protocol analysis)
- **SSE and Streamable HTTP transports** via Hypercorn ASGI server
- **Thread-safe IDB modifications** via `execute_on_main_thread()` wrapper
- **LRU analysis cache** for expensive operations like decompilation
- **Async task manager** for long-running operations
- **Pydantic configuration** with environment variable support (`IDASSISTMCP_` prefix)

## Installation

### Prerequisites

- IDA Pro 9.x with Python 3.10+
- Hex-Rays decompiler (optional, for decompilation tools)

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Install Plugin

Option 1: Symlink (recommended for development):
```bash
ln -s /path/to/IDAssistMCP/idassistmcp_plugin.py ~/.idapro/plugins/idassistmcp_plugin.py
```

Option 2: Copy the plugin file:
```bash
cp idassistmcp_plugin.py ~/.idapro/plugins/
```

**Important**: The plugin needs access to the `src/` directory. Either:
- Keep the symlink/copy next to the `src/` directory, or
- Add the IDAssistMCP directory to IDA's Python path

## Usage

### Starting the Server

1. Open a binary in IDA Pro
2. Press **Ctrl+Shift+M** or go to **Edit > Plugins > IDAssistMCP**
3. The MCP server URL will be printed to IDA's output window
4. Press Ctrl+Shift+M again to stop the server

### Claude Desktop Configuration

Add to your Claude Desktop `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "idassistmcp": {
      "url": "http://localhost:9080/mcp"
    }
  }
}
```

### Environment Variables

Configure via environment variables with the `IDASSISTMCP_` prefix:

| Variable | Default | Description |
|----------|---------|-------------|
| `IDASSISTMCP_SERVER__HOST` | `localhost` | Server bind address |
| `IDASSISTMCP_SERVER__PORT` | `9080` | Server port |
| `IDASSISTMCP_SERVER__TRANSPORT` | `streamablehttp` | Transport type (`sse` or `streamablehttp`) |
| `IDASSISTMCP_DEBUG` | `false` | Enable debug mode |
| `IDASSISTMCP_LOG_LEVEL` | `INFO` | Log level |

## Tools Reference

### Binary Management (2)
| Tool | Description |
|------|-------------|
| `list_binaries` | List the currently loaded binary |
| `get_binary_info` | Detailed binary metadata (arch, hashes, segments) |

### Code Analysis (5)
| Tool | Description |
|------|-------------|
| `decompile_function` | Hex-Rays decompiled pseudo-C output |
| `get_disassembly` | Disassembly listing for a function |
| `get_function_info` | Function metadata (start, end, size, flags) |
| `get_basic_blocks` | CFG basic blocks with successors/predecessors |
| `get_il_expression` | Pseudo-C output (alias for decompile) |

### Cross-References (2)
| Tool | Description |
|------|-------------|
| `get_xrefs` | Code/data cross-references to/from address |
| `get_callers_callees` | Call graph for a function |

### Comments & Variables (2)
| Tool | Description |
|------|-------------|
| `get_comments` | Regular, repeatable, and function-level comments |
| `get_variables` | Local variables via Hex-Rays decompiler |

### Types (1)
| Tool | Description |
|------|-------------|
| `get_types` | List local types (structs, enums, typedefs) |

### Function Discovery (5)
| Tool | Description |
|------|-------------|
| `list_functions` | All functions with filtering and pagination |
| `search_functions` | Search by name pattern and size filters |
| `get_function_by_name` | Exact name lookup |
| `get_function_by_address` | Address lookup |
| `get_function_statistics` | Aggregate statistics (counts, sizes, top-10) |

### Binary Info (4)
| Tool | Description |
|------|-------------|
| `get_imports` | Import table grouped by module |
| `get_exports` | Export table |
| `get_strings` | String table with pagination |
| `get_segments` | Memory segments with permissions |

### Symbol Management (3)
| Tool | Description |
|------|-------------|
| `rename_function` | Rename a function |
| `rename_variable` | Rename a local variable (Hex-Rays) |
| `rename_symbol` | Rename any symbol |

### Modification Tools (5)
| Tool | Description |
|------|-------------|
| `set_type` | Set type at address |
| `set_comment` | Set regular/repeatable/function comment |
| `create_struct` | Create new struct type |
| `create_enum` | Create new enum type |
| `patch_bytes` | Patch bytes in IDB |

### Data Analysis (2)
| Tool | Description |
|------|-------------|
| `read_memory` | Read raw bytes at address |
| `get_data_at` | Get typed data at address |

### Navigation (2)
| Tool | Description |
|------|-------------|
| `navigate_to` | Move IDA cursor to address |
| `set_bookmark` | Create position bookmark |

### Search (2)
| Tool | Description |
|------|-------------|
| `search_bytes` | Binary byte pattern search |
| `search_strings` | String search with pagination |

### Unified Tools (3)
| Tool | Description |
|------|-------------|
| `get_code` | Get code in specified format (decompile/disasm) |
| `analyze_function` | Comprehensive function analysis |
| `batch_rename` | Batch rename multiple symbols |

### Task Management (3)
| Tool | Description |
|------|-------------|
| `start_task` | Start async background task |
| `get_task_status` | Check task progress |
| `cancel_task` | Cancel running task |

### Entry Points (2)
| Tool | Description |
|------|-------------|
| `get_entry_points` | All binary entry points |
| `list_tasks` | List all async tasks |

## Project Structure

```
IDAssistMCP/
├── idassistmcp_plugin.py              # IDA plugin_t entry point
├── requirements.txt
├── README.md
└── src/
    └── idassist_mcp/
        ├── __init__.py
        ├── server.py                  # FastMCP server + transport
        ├── context.py                 # Single-binary IDA context
        ├── tools.py                   # 43 MCP tools (IDA API)
        ├── resources.py               # 8 MCP resources
        ├── prompts.py                 # 7 guided workflow prompts
        ├── config.py                  # Pydantic settings
        ├── cache.py                   # LRU analysis cache
        ├── tasks.py                   # Async task manager
        ├── logging.py                 # IDA logging wrapper
        └── utils.py                   # IDA-specific utilities
```

## License

See LICENSE file for details.
