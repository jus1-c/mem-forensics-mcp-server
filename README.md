# MCP Memory Forensics

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![MCP](https://img.shields.io/badge/MCP-Compatible-green.svg)](https://modelcontextprotocol.io/)

A high-performance MCP Server for Memory Forensics that enables AI agents to analyze memory dumps through the Model Context Protocol. Built with two-tier architecture combining Rust speed with Volatility3 coverage.

## Credits

This project is based on the excellent work by [xtk](https://github.com/x746b) in [mem-forensics-mcp](https://github.com/x746b/mem_forensics-mcp). The Rust engine (memoxide) is a modified version of the original implementation.

## Features

- **Two-Tier Architecture**: Fast Rust engine (memoxide) + Volatility3 fallback for maximum coverage
- **Intelligent Caching**: 200-entry cache with LRU eviction (survives until server restart)
- **Auto-Detection**: Automatic OS profile detection and plugin name resolution
- **High Performance**: Rust native plugins for common operations (3s vs 60s)
- **Full Coverage**: Access to 195+ Volatility3 plugins when needed
- **Smart Routing**: Automatically selects fastest available engine
- **No Pre-analysis Required**: Plugins auto-analyze image if needed

## Performance Benchmarks

Tested on Windows crash dump (2GB, ~109 processes):

| Operation | Rust (Memoxide) | Volatility3 | Speedup |
|-----------|----------------|-------------|---------|
| Analyze Image | 3s | 60s | **20x faster** |
| Process List (pslist) | 1.5s | 15s | **10x faster** |
| Network Scan (netscan) | 2s | 20s | **10x faster** |

## Requirements

- Python 3.10+
- Volatility3 (2.5+) - optional, for Tier 2 fallback
- Rust toolchain (optional, for building memoxide from source)
- MCP-compatible client (Claude Desktop, VSCode, Cline, etc.)

## Installation

### 1. Install Volatility3 (Optional)

**Via pip:**
```bash
pip install volatility3 pefile pycryptodome
```

**Verify installation:**
```bash
vol --version
```

### 2. Install MCP Server

**From Source:**
```bash
git clone https://github.com/jus1-c/mem-forensics-mcp-server.git
cd mem-forensics-mcp-server
pip install -e .
```

## Configuration

### Claude Desktop

Edit `claude_desktop_config.json`:

**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`  
**Windows:** `%APPDATA%/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "mem-forensics": {
      "command": "python",
      "args": ["-m", "mem_forensics_mcp_server"],
      "env": {
        "VOLATILITY3_PATH": ""
      }
    }
  }
}
```

### VSCode (with Cline extension)

Add to your settings:

```json
{
  "mcpServers": {
    "mem-forensics": {
      "command": "python",
      "args": ["-m", "mem_forensics_mcp_server"],
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

## Available Tools

### 1. memory_analyze_image

Initialize memory image analysis and detect OS profile.

**Parameters:**
- `image_path`: Absolute path to memory dump (required)
- `dtb`: Override DTB address (optional, hex string)
- `kernel_base`: Override kernel base address (optional, hex string)

**Example:**
```json
{
  "image_path": "/evidence/memory.raw",
  "dtb": "0x1ad000"
}
```

### 2. memory_run_plugin

Run a forensics plugin. Auto-routes to Rust (fast) or Vol3 (fallback).

**Parameters:**
- `image_path`: Absolute path to memory dump (required)
- `plugin`: Plugin name - can be short ("pslist") or full ("windows.pslist.PsList")
- `args`: List of arguments (optional, e.g., ["--pid", "1234", "-r", "json"])
- `filter`: Server-side filter string (optional)

**Important Notes:**
- Use `args` parameter for all plugin arguments
- Include `-r json` for JSON output (auto-added if not specified)
- Short plugin names are auto-resolved to full format

**Examples:**

```json
// List all processes
{
  "image_path": "/evidence/memory.raw",
  "plugin": "pslist"
}

// Dlllist for specific PID
{
  "image_path": "/evidence/memory.raw",
  "plugin": "dlllist",
  "args": ["--pid", "3692"]
}

// Filescan with filter
{
  "image_path": "/evidence/memory.raw",
  "plugin": "filescan",
  "filter": "svchost"
}

// Using full plugin name
{
  "image_path": "/evidence/memory.raw",
  "plugin": "windows.netscan.NetScan"
}
```

### 3. memory_list_plugins

List all available plugins from both engines.

**Parameters:**
- `image_path`: Memory dump path (for context)

**Returns:**
- 9 Rust plugins (fast)
- 195 Vol3 plugins (Windows/Linux/Mac/Other)

### 4. memory_list_sessions

List all active analysis sessions.

**Parameters:** None

### 5. memory_get_status

Get server status and engine availability.

**Parameters:** None

### 6. memory_list_dumpable_files

List files found in memory using filescan plugin.

**Parameters:**
- `image_path`: Absolute path to memory dump (required)
- `args`: Optional args like `["--pid", "1234"]`

### 7. memory_get_tool_help

Get detailed help and examples for any tool.

**Parameters:**
- `tool_name`: Name of tool (e.g., "memory_run_plugin")

## Usage Examples

### Basic Analysis (Auto-detect)

```
Please analyze this memory dump and list all processes.
File: /evidence/windows.dmp
```

The server will:
1. Auto-analyze the image
2. Cache the results
3. Return process list

### Process Investigation with PID Filter

```
Get command line for process ID 1234 from this memory dump.
File: /evidence/malware.dmp
```

```json
{
  "image_path": "/evidence/malware.dmp",
  "plugin": "cmdline",
  "args": ["--pid", "1234"]
}
```

### Network Analysis

```
Find all network connections in this memory dump.
File: /evidence/c2.dmp
```

### Code Injection Detection

```
Scan for injected code (malfind) in this memory dump.
File: /evidence/suspicious.dmp
```

### List Files in Memory

```
List all files found in memory.
File: /evidence/windows.dmp
```

## Caching System

The server includes an intelligent caching system:

- **Cache Size**: 200 entries (configurable)
- **Cache Key**: `(image_path, plugin, args)`
- **Persistence**: Cache survives until server restart
- **Auto-Clear**: Cache cleared when analyzing new image
- **LRU Eviction**: Oldest entries removed when cache is full

**Benefits:**
- Second query for same plugin returns instantly
- No TTL - cache valid until server restart
- Separate cache per memory dump file

## Security Features

- **Path Validation**: Only absolute paths allowed
- **Engine Isolation**: Rust plugins run in separate subprocess
- **Timeout Protection**: 60s timeout for Rust, 300s for Vol3
- **Size Limits**: Configurable response size limits
- **No Secrets**: No logging of sensitive memory contents

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `VOLATILITY3_PATH` | Path to Volatility3 installation | auto-detect |

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────┐
│   MCP Client    │────▶│  MCP Server      │────▶│  Memoxide   │
│ (Claude/VSCode) │     │  (Python/FastMCP)│     │   (Rust)    │
└─────────────────┘     └──────────────────┘     └─────────────┘
                               │                           │
                               │                    ┌──────┴──────┐
                               │                    │ Memory Dump │
                               │                    └─────────────┘
                               ▼
                        ┌─────────────┐     ┌─────────────┐
                        │    Cache    │────▶│  Volatility3│
                        │  (200 entries│     │  (Fallback) │
                        └─────────────┘     └─────────────┘
```

## Project Structure

```
mem-forensics-mcp-server/
├── mem_forensics_mcp_server/
│   ├── __init__.py
│   ├── __main__.py              # Entry point
│   ├── server.py                # MCP server with tools
│   ├── config.py                # Configuration
│   ├── core/
│   │   ├── session.py           # Session management
│   │   ├── cache.py             # Plugin result caching
│   │   └── vol3_cli.py          # Vol3 CLI wrapper
│   ├── engine/
│   │   ├── memoxide_client.py   # Rust engine client
│   │   └── memoxide/            # Prebuilt binaries
│   │       ├── x86_64/
│   │       └── aarch64/
│   └── utils/
│       └── helpers.py
├── pyproject.toml
├── README.md
└── .gitignore
```

## Development

### Setup Development Environment

```bash
pip install -e ".[dev]"
```

### Building Rust Engine

```bash
cd mem_forensics_mcp_server/engine/memoxide-src
cargo build --release
```

## Troubleshooting

### Memoxide not available

Memoxide requires platform-specific binaries. Prebuilt binaries included for:
- Windows x86_64
- Linux x86_64
- macOS x86_64 & aarch64

To build for other platforms:
```bash
cd mem_forensics_mcp_server/engine/memoxide-src
cargo build --release --target <target-triple>
```

### Vol3 plugin requirements not met

Some memory dump formats may not be compatible with certain plugins. Error message will indicate:
- Translation layer issues (unsupported format)
- Symbol table issues (missing ISF files)

### Timeout errors on large dumps

Rust engine has 60s timeout. For very large dumps, Vol3 fallback will be used automatically.

### Plugin returns "usage: vol.EXE..."

This means the arguments passed are incorrect. Check the plugin's help:
```
vol <plugin_name> --help
```

## Recent Updates

### v0.1.19
- ✨ Added intelligent caching system (200 entries)
- ✨ Auto-plugin name resolution (pslist → windows.pslist.PsList)
- ✨ Auto-analyze on first plugin call
- ✨ Simplified args parameter (replaces pid/params)
- 🔧 Removed memory_dump_process tool
- 🔧 Improved error handling and logging

## License

MIT License - see LICENSE file for details.

## Acknowledgments

- [xtk](https://github.com/x746b) - Original author of [mem-forensics-mcp](https://github.com/x746b/mem_forensics-mcp) and the memoxide Rust engine
- [Volatility3](https://github.com/volatilityfoundation/volatility3) - Memory forensics framework
- [Model Context Protocol](https://modelcontextprotocol.io/) - MCP specification
- [FastMCP](https://github.com/modelcontextprotocol/python-sdk) - Python MCP SDK

## Support

For issues and feature requests, please use the GitHub issue tracker.
