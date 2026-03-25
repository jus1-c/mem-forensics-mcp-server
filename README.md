# MCP Memory Forensics

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![MCP](https://img.shields.io/badge/MCP-Compatible-green.svg)](https://modelcontextprotocol.io/)

A high-performance MCP Server for Memory Forensics that enables AI agents to analyze memory dumps through the Model Context Protocol. Built with two-tier architecture combining Rust speed with Volatility3 coverage.

## Credits

This project is based on the excellent work by [xtk](https://github.com/x746b) in [mem-forensics-mcp](https://github.com/x746b/mem_forensics-mcp). The Rust engine (memoxide) is a modified version of the original implementation.

## Features

- **Two-Tier Architecture**: Fast Rust engine (memoxide) + Volatility3 fallback for maximum coverage
- **Cross-Platform**: Support Windows, Linux, and macOS memory dumps
- **Auto-Detection**: Automatic OS profile detection from memory dumps
- **High Performance**: Rust native plugins for common operations (3s vs 60s)
- **Full Coverage**: Access to 195+ Volatility3 plugins when needed
- **Memory Efficient**: Streaming processing for large dumps
- **Smart Routing**: Automatically selects fastest available engine

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

**From PyPI:**
```bash
pip install mem-forensics-mcp-server
```

**From Source:**
```bash
git clone https://github.com/yourusername/mem-forensics-mcp-server.git
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
- `plugin`: Plugin name (e.g., "windows.pslist.PsList", "linux.netstat.NetStat")
- `pid`: Filter by process ID (optional)
- `params`: Plugin-specific parameters (optional, dict)
- `filter`: Server-side filter string (optional)

**Example:**
```json
{
  "image_path": "/evidence/memory.raw",
  "plugin": "windows.pslist.PsList",
  "filter": "svchost"
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

List files that can be extracted from memory cache.

**Parameters:**
- `image_path`: Absolute path to memory dump (required)
- `pid`: Filter by process ID (optional)

### 7. memory_dump_process

Dump a process from memory.

**Parameters:**
- `image_path`: Absolute path to memory dump (required)
- `pid`: Process ID to dump (required)
- `output_dir`: Output directory (optional, default: "/tmp/memdumps")

**Example:**
```json
{
  "image_path": "/evidence/memory.raw",
  "pid": 4,
  "output_dir": "/tmp/extracted"
}
```

## Usage Examples

### Basic Analysis

```
Please analyze this memory dump and detect the OS profile.
File: /evidence/windows.dmp
```

### Process Investigation

```
List all processes in this memory dump and find any suspicious ones.
File: /evidence/malware.dmp
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
                        ┌─────────────┐
                        │ Volatility3 │
                        │  (Fallback) │
                        └─────────────┘
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

## License

MIT License - see LICENSE file for details.

## Acknowledgments

- [xtk](https://github.com/x746b) - Original author of [mem-forensics-mcp](https://github.com/x746b/mem_forensics-mcp) and the memoxide Rust engine
- [Volatility3](https://github.com/volatilityfoundation/volatility3) - Memory forensics framework
- [Model Context Protocol](https://modelcontextprotocol.io/) - MCP specification
- [FastMCP](https://github.com/modelcontextprotocol/python-sdk) - Python MCP SDK

## Support

For issues and feature requests, please use the GitHub issue tracker.
