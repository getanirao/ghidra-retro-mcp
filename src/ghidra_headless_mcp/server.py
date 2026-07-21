import argparse
import logging
import os
import sys

from mcp.server import Server, NotificationOptions
from mcp.server.models import InitializationOptions
import mcp.server.stdio
import mcp.types as types

from .ghidra_bridge import GhidraSession

logger = logging.getLogger(__name__)

session = GhidraSession(ghidra_dir=os.environ.get("GHIDRA_INSTALL_DIR"))


async def serve():
    server = Server("ghidra-headless-mcp")

    @server.list_tools()
    async def list_tools() -> list[types.Tool]:
        return [
            types.Tool(
                name="analyze_binary",
                description="Import and analyze a binary with Ghidra (auto-analysis enabled)",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "binary_path": {
                            "type": "string",
                            "description": "Path to the binary file to analyze",
                        },
                        "project_dir": {
                            "type": "string",
                            "description": "Optional project directory (defaults to binary parent dir)",
                        },
                    },
                    "required": ["binary_path"],
                },
            ),
            types.Tool(
                name="decompile_function",
                description="Decompile a function by name or address",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "function_name": {
                            "type": "string",
                            "description": "Function name or hex address (e.g. 'main' or '0x401000')",
                        },
                    },
                    "required": ["function_name"],
                },
            ),
            types.Tool(
                name="get_data_types",
                description="List all data types defined in the program",
                inputSchema={
                    "type": "object",
                    "properties": {},
                },
            ),
            types.Tool(
                name="get_cross_references",
                description="Get cross-references to and from an address",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "address": {
                            "type": "string",
                            "description": "Address in the binary (e.g. '0x401000')",
                        },
                        "max_results": {
                            "type": "integer",
                            "description": "Maximum references per direction (default 100)",
                            "default": 100,
                        },
                    },
                    "required": ["address"],
                },
            ),
            types.Tool(
                name="get_call_graph",
                description="Get call graph for a function (who it calls and who calls it)",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "function_name": {
                            "type": "string",
                            "description": "Function name or address",
                        },
                        "max_depth": {
                            "type": "integer",
                            "description": "Max depth for nested call resolution (default 3)",
                            "default": 3,
                        },
                    },
                    "required": ["function_name"],
                },
            ),
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
        try:
            if name == "analyze_binary":
                result = session.analyze_binary(
                    binary_path=arguments["binary_path"],
                    project_dir=arguments.get("project_dir"),
                )
            elif name == "decompile_function":
                result = session.decompile_function(
                    function_name=arguments["function_name"],
                )
            elif name == "get_data_types":
                result = session.get_data_types()
            elif name == "get_cross_references":
                result = session.get_cross_references(
                    address=arguments["address"],
                    max_results=arguments.get("max_results", 100),
                )
            elif name == "get_call_graph":
                result = session.get_call_graph(
                    function_name=arguments["function_name"],
                    max_depth=arguments.get("max_depth", 3),
                )
            else:
                raise ValueError(f"Unknown tool: {name}")

            return [types.TextContent(type="text", text=_format_result(result))]
        except Exception as e:
            logger.exception("Tool call failed")
            return [types.TextContent(type="text", text=f"Error: {e}")]

    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="ghidra-headless-mcp",
                server_version="0.1.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )


def _format_result(obj) -> str:
    import json
    return json.dumps(obj, indent=2, default=str)


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s %(name)s %(message)s",
        stream=sys.stderr,
    )

    parser = argparse.ArgumentParser(description="Ghidra Headless MCP Server")
    parser.add_argument(
        "--ghidra-dir",
        default=os.environ.get("GHIDRA_INSTALL_DIR"),
        help="Path to Ghidra installation directory",
    )
    args = parser.parse_args()

    if args.ghidra_dir:
        session._ghidra_dir = args.ghidra_dir

    logger.info("Starting Ghidra headless MCP server...")
    session.start()
    logger.info("Ghidra bridge ready")

    import asyncio
    asyncio.run(serve())


if __name__ == "__main__":
    main()
