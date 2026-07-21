# Ghidra Headless MCP

MCP (Model Context Protocol) server that exposes Ghidra's headless analysis capabilities to AI assistants via [pyhidra](https://github.com/dod-cyber-crime-institute/pyhidra).

## Prerequisites

- Python 3.10+
- Ghidra 11.x+ installed
- Java 17+ (required by Ghidra)

## Setup

```bash
# Install the package
pip install -e .

# Or install dependencies directly
pip install mcp pyhidra
```

## Usage

Set `GHIDRA_INSTALL_DIR` or pass `--ghidra-dir`:

```bash
# Windows
set GHIDRA_INSTALL_DIR=C:\path\to\ghidra
ghidra-mcp

# Linux/macOS
export GHIDRA_INSTALL_DIR=/opt/ghidra
ghidra-mcp
```

The server runs on stdio transport — configure it as an MCP server in your AI client:

### Claude Desktop config (`claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "ghidra-headless": {
      "command": "ghidra-mcp",
      "args": ["--ghidra-dir", "C:\\path\\to\\ghidra"],
      "env": {}
    }
  }
}
```

## Tools

### `analyze_binary`

Import a binary into a new Ghidra project with auto-analysis. Returns metadata about the binary. Subsequent tools operate on this binary until a new one is loaded.

**Parameters:**
| Param | Type | Required | Description |
|---|---|---|---|
| `binary_path` | string | yes | Path to the binary file |
| `project_dir` | string | no | Project directory (defaults to binary's parent) |

### `decompile_function`

Decompile a function to C code.

**Parameters:**
| Param | Type | Required | Description |
|---|---|---|---|
| `function_name` | string | yes | Function name (e.g. `main`) or hex address (e.g. `0x401000`) |

### `get_data_types`

List all data types defined in the loaded program.

### `get_cross_references`

Get cross-references to and from an address.

**Parameters:**
| Param | Type | Required | Description |
|---|---|---|---|
| `address` | string | yes | Address to query (e.g. `0x401000`) |
| `max_results` | integer | no | Max references per direction (default: 100) |

### `get_call_graph`

Get the call graph for a function — who it calls (recursively) and who calls it.

**Parameters:**
| Param | Type | Required | Description |
|---|---|---|---|
| `function_name` | string | yes | Function name or address |
| `max_depth` | integer | no | Recursion depth for callees (default: 3) |

## Project Structure

```
ghidra-headless-mcp/
├── pyproject.toml
├── README.md
└── src/ghidra_headless_mcp/
    ├── __init__.py
    ├── server.py          # MCP server, tool registry, stdio transport
    ├── ghidra_bridge.py   # GhidraSession — pyhidra wrapper
    └── tools/
        └── __init__.py
```

## How it works

1. `pyhidra.start()` boots Ghidra's JVM once at server startup
2. `analyze_binary` creates a temporary Ghidra project and opens the binary
3. All subsequent tools operate on the currently loaded program via Ghidra's Java API (accessed through JPype)
4. Calling `analyze_binary` again closes the previous program and loads a new one
