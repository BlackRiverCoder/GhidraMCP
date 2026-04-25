# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2,<3",
#     "mcp>=1.2.0,<2",
# ]
# ///

import sys
import requests
import argparse
import logging
from urllib.parse import urljoin

from mcp.server.fastmcp import FastMCP

DEFAULT_GHIDRA_SERVER = "http://127.0.0.1:8080/"

logger = logging.getLogger(__name__)

mcp = FastMCP("ghidra-mcp")

# Initialize ghidra_server_url with default value
ghidra_server_url = DEFAULT_GHIDRA_SERVER

def safe_get(endpoint: str, params: dict = None) -> list:
    """
    Perform a GET request with optional query parameters.
    """
    if params is None:
        params = {}

    url = urljoin(ghidra_server_url, endpoint)

    try:
        response = requests.get(url, params=params, timeout=5)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.splitlines()
        else:
            return [f"Error {response.status_code}: {response.text.strip()}"]
    except Exception as e:
        return [f"Request failed: {str(e)}"]

def safe_post(endpoint: str, data: dict | str) -> str:
    try:
        url = urljoin(ghidra_server_url, endpoint)
        if isinstance(data, dict):
            response = requests.post(url, data=data, timeout=5)
        else:
            response = requests.post(url, data=data.encode("utf-8"), timeout=5)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"

@mcp.tool()
def list_methods(offset: int = 0, limit: int = 100) -> list:
    """
    List all function names in the program with pagination.
    """
    return safe_get("methods", {"offset": offset, "limit": limit})

@mcp.tool()
def list_classes(offset: int = 0, limit: int = 100) -> list:
    """
    List all namespace/class names in the program with pagination.
    """
    return safe_get("classes", {"offset": offset, "limit": limit})

@mcp.tool()
def decompile_function(name: str) -> str:
    """
    Decompile a specific function by name and return the decompiled C code.
    """
    return safe_post("decompile", name)

@mcp.tool()
def rename_function(old_name: str, new_name: str) -> str:
    """
    Rename a function by its current name to a new user-defined name.
    """
    return safe_post("renameFunction", {"oldName": old_name, "newName": new_name})

@mcp.tool()
def rename_data(address: str, new_name: str) -> str:
    """
    Rename a data label at the specified address.
    """
    return safe_post("renameData", {"address": address, "newName": new_name})

@mcp.tool()
def list_segments(offset: int = 0, limit: int = 100) -> list:
    """
    List all memory segments in the program with pagination.
    """
    return safe_get("segments", {"offset": offset, "limit": limit})

@mcp.tool()
def list_imports(offset: int = 0, limit: int = 100) -> list:
    """
    List imported symbols in the program with pagination.
    """
    return safe_get("imports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_exports(offset: int = 0, limit: int = 100) -> list:
    """
    List exported functions/symbols with pagination.
    """
    return safe_get("exports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_namespaces(offset: int = 0, limit: int = 100) -> list:
    """
    List all non-global namespaces in the program with pagination.
    """
    return safe_get("namespaces", {"offset": offset, "limit": limit})

@mcp.tool()
def list_data_items(offset: int = 0, limit: int = 100) -> list:
    """
    List defined data labels and their values with pagination.
    """
    return safe_get("data", {"offset": offset, "limit": limit})

@mcp.tool()
def search_functions_by_name(query: str, offset: int = 0, limit: int = 100) -> list:
    """
    Search for functions whose name contains the given substring.
    """
    if not query:
        return ["Error: query string is required"]
    return safe_get("searchFunctions", {"query": query, "offset": offset, "limit": limit})

@mcp.tool()
def rename_variable(function_name: str, old_name: str, new_name: str) -> str:
    """
    Rename a local variable within a function.
    """
    return safe_post("renameVariable", {
        "functionName": function_name,
        "oldName": old_name,
        "newName": new_name
    })

@mcp.tool()
def get_function_by_address(address: str) -> str:
    """
    Get a function by its address.
    """
    return "\n".join(safe_get("get_function_by_address", {"address": address}))

@mcp.tool()
def get_current_address() -> str:
    """
    Get the address currently selected by the user.
    """
    return "\n".join(safe_get("get_current_address"))

@mcp.tool()
def get_current_function() -> str:
    """
    Get the function currently selected by the user.
    """
    return "\n".join(safe_get("get_current_function"))

@mcp.tool()
def list_functions() -> list:
    """
    List all functions in the database.
    """
    return safe_get("list_functions")

@mcp.tool()
def decompile_function_by_address(address: str) -> str:
    """
    Decompile a function at the given address.
    """
    return "\n".join(safe_get("decompile_function", {"address": address}))

@mcp.tool()
def disassemble_function(address: str) -> list:
    """
    Get assembly code (address: instruction; comment) for a function.
    """
    return safe_get("disassemble_function", {"address": address})

@mcp.tool()
def set_decompiler_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function pseudocode.
    """
    return safe_post("set_decompiler_comment", {"address": address, "comment": comment})

@mcp.tool()
def set_disassembly_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function disassembly.
    """
    return safe_post("set_disassembly_comment", {"address": address, "comment": comment})

@mcp.tool()
def rename_function_by_address(function_address: str, new_name: str) -> str:
    """
    Rename a function by its address.
    """
    return safe_post("rename_function_by_address", {"function_address": function_address, "new_name": new_name})

@mcp.tool()
def set_function_prototype(function_address: str, prototype: str) -> str:
    """
    Set a function's prototype.
    """
    return safe_post("set_function_prototype", {"function_address": function_address, "prototype": prototype})

@mcp.tool()
def set_local_variable_type(function_address: str, variable_name: str, new_type: str) -> str:
    """
    Set a local variable's type.
    """
    return safe_post("set_local_variable_type", {"function_address": function_address, "variable_name": variable_name, "new_type": new_type})

@mcp.tool()
def get_xrefs_to(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified address (xref to).
    
    Args:
        address: Target address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified address
    """
    return safe_get("xrefs_to", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def get_xrefs_from(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references from the specified address (xref from).
    
    Args:
        address: Source address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references from the specified address
    """
    return safe_get("xrefs_from", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def get_function_xrefs(name: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified function by name.
    
    Args:
        name: Function name to search for
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified function
    """
    return safe_get("function_xrefs", {"name": name, "offset": offset, "limit": limit})

@mcp.tool()
def list_strings(offset: int = 0, limit: int = 2000, filter: str = None) -> list:
    """
    List all defined strings in the program with their addresses.
    
    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of strings to return (default: 2000)
        filter: Optional filter to match within string content
        
    Returns:
        List of strings with their addresses
    """
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    return safe_get("strings", params)

@mcp.tool()
def list_memory_blocks(offset: int = 0, limit: int = 100) -> list:
    """
    List all memory blocks/segments with full details (name, start, end, size, permissions, type).
    """
    return safe_get("list_memory_blocks", {"offset": offset, "limit": limit})

@mcp.tool()
def set_memory_block_start(block_name: str, new_start_address: str) -> str:
    """
    Rebase/move a memory block to a new start address.
    Useful for firmware analysis where flash doesn't start at 0x0.
    
    Args:
        block_name: Name of the memory block (e.g. "ram", "FLASH", ".text")
        new_start_address: New base address in hex (e.g. "0x08000000")
    """
    return safe_post("set_memory_block_start", {"blockName": block_name, "newStart": new_start_address})

@mcp.tool()
def rename_memory_block(block_name: str, new_name: str) -> str:
    """
    Rename a memory block/segment.
    
    Args:
        block_name: Current name of the memory block
        new_name: New name for the block (e.g. "FLASH", "RAM", "EEPROM")
    """
    return safe_post("rename_memory_block", {"blockName": block_name, "newName": new_name})

@mcp.tool()
def add_memory_block(
    name: str,
    start_address: str,
    length: str,
    read: bool = True,
    write: bool = True,
    execute: bool = False,
    volatile: bool = False,
    artificial: bool = False,
    overlay: bool = False,
    block_type: str = "uninitialized",
    comment: str = ""
) -> str:
    """
    Create a new memory block — all options as seen in Ghidra's Add Memory Block dialog.

    Args:
        name: Block name (e.g. "SRAM", "PERIPH", "FLASH2")
        start_address: Start address in hex (e.g. "0x20000000")
        length: Length in hex or decimal (e.g. "0x8000")
        read: Read permission (default True)
        write: Write permission (default True)
        execute: Execute permission (default False)
        volatile: Mark as volatile — for memory-mapped peripheral registers (default False)
        artificial: Mark as artificial/internal Ghidra block (default False)
        overlay: Create as overlay block (default False)
        block_type: "uninitialized" | "initialized" | "file_bytes"
                    uninitialized = empty block, no data
                    initialized   = zeroed initialized block
                    file_bytes    = mapped from the loaded binary file
        comment: Optional comment/description
    """
    return safe_post("add_memory_block", {
        "name": name,
        "start": start_address,
        "length": length,
        "read": str(read).lower(),
        "write": str(write).lower(),
        "execute": str(execute).lower(),
        "volatile": str(volatile).lower(),
        "artificial": str(artificial).lower(),
        "overlay": str(overlay).lower(),
        "blockType": block_type,
        "comment": comment
    })

@mcp.tool()
def delete_memory_block(block_name: str) -> str:
    """
    Delete a memory block by name.
    WARNING: This removes the block and all its contents from the analysis.
    
    Args:
        block_name: Name of the memory block to delete
    """
    return safe_post("delete_memory_block", {"blockName": block_name})

@mcp.tool()
def set_memory_block_permissions(block_name: str, read: bool, write: bool, execute: bool) -> str:
    """
    Set read/write/execute permissions on a memory block.
    
    Args:
        block_name: Name of the memory block
        read: Allow read access
        write: Allow write access
        execute: Allow execute access
    """
    return safe_post("set_memory_block_permissions", {
        "blockName": block_name,
        "read": str(read),
        "write": str(write),
        "execute": str(execute)
    })

@mcp.tool()
def rebase_program(new_image_base: str) -> str:
    """
    Rebase the entire program to a new image base address.
    This moves ALL memory blocks proportionally — useful when the entire
    firmware image needs to be relocated (e.g. from 0x0 to 0x08000000).
    
    Args:
        new_image_base: New base address in hex (e.g. "0x08000000")
    """
    return safe_post("rebase_program", {"newBase": new_image_base})

@mcp.tool()
def save_ghidra_script(script_name: str, script_code: str) -> str:
    """
    Save a Ghidra script to the user scripts directory so it can be run.
    The script can be Java (.java) or Python/Jython (.py).
    Script name must end with .java or .py.
    
    Args:
        script_name: Filename e.g. "AnalyzeStrings.java" or "fix_offsets.py"
        script_code: Full source code of the script
    """
    import urllib.parse
    return safe_post("save_script", {
        "name": script_name,
        "code": script_code
    })

@mcp.tool()
def run_ghidra_script(script_name: str, script_args: str = "") -> str:
    """
    Run a previously saved Ghidra script by name and return its output.
    
    Args:
        script_name: Filename e.g. "AnalyzeStrings.java"
        script_args: Optional arguments passed to the script (space separated)
    """
    return safe_post("run_script", {
        "name": script_name,
        "args": script_args
    })

@mcp.tool()
def list_ghidra_scripts() -> list:
    """
    List all available Ghidra scripts in the user scripts directory.
    """
    return safe_get("list_scripts")

@mcp.tool()
def run_auto_analysis() -> str:
    """
    Run Ghidra's full auto-analysis on the current program.
    This will find functions, apply data types, resolve references, etc.
    May take a while on large binaries.
    """
    return safe_post("run_auto_analysis", {})

@mcp.tool()
def list_analyzers() -> list:
    """
    List all available analyzers in Ghidra with their enabled/disabled state.
    """
    return safe_get("list_analyzers")

@mcp.tool()
def run_specific_analyzers(analyzer_names: list) -> str:
    """
    Run specific Ghidra analyzers by name.
    Use list_analyzers() first to see available analyzer names.
    
    Args:
        analyzer_names: List of analyzer names to run (e.g. ["Disassembler", "Function Start Search"])
    """
    import json
    return safe_post("run_specific_analyzers", {"analyzers": json.dumps(analyzer_names)})

def main():
    parser = argparse.ArgumentParser(description="MCP server for Ghidra")
    parser.add_argument("--ghidra-server", type=str, default=DEFAULT_GHIDRA_SERVER,
                        help=f"Ghidra server URL, default: {DEFAULT_GHIDRA_SERVER}")
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1",
                        help="Host to run MCP server on (only used for sse), default: 127.0.0.1")
    parser.add_argument("--mcp-port", type=int,
                        help="Port to run MCP server on (only used for sse), default: 8081")
    parser.add_argument("--transport", type=str, default="stdio", choices=["stdio", "sse"],
                        help="Transport protocol for MCP, default: stdio")
    args = parser.parse_args()
    
    # Use the global variable to ensure it's properly updated
    global ghidra_server_url
    if args.ghidra_server:
        ghidra_server_url = args.ghidra_server
    
    if args.transport == "sse":
        try:
            # Set up logging
            log_level = logging.INFO
            logging.basicConfig(level=log_level)
            logging.getLogger().setLevel(log_level)

            # Configure MCP settings
            mcp.settings.log_level = "INFO"
            if args.mcp_host:
                mcp.settings.host = args.mcp_host
            else:
                mcp.settings.host = "127.0.0.1"

            if args.mcp_port:
                mcp.settings.port = args.mcp_port
            else:
                mcp.settings.port = 8081

            logger.info(f"Connecting to Ghidra server at {ghidra_server_url}")
            logger.info(f"Starting MCP server on http://{mcp.settings.host}:{mcp.settings.port}/sse")
            logger.info(f"Using transport: {args.transport}")

            mcp.run(transport="sse")
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        mcp.run()
        
if __name__ == "__main__":
    main()

