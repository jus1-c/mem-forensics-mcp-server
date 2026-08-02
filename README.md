# MCP Memory Forensics

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![MCP](https://img.shields.io/badge/MCP-Compatible-green.svg)](https://modelcontextprotocol.io/)

A high-performance MCP Server for Memory Forensics that enables AI agents to analyze memory dumps through the Model Context Protocol. Built with two-tier architecture combining Rust speed with Volatility3 coverage.

## Credits

This project is based on the excellent work by [xtk](https://github.com/x746b) in [mem-forensics-mcp](https://github.com/x746b/mem_forensics-mcp). The Rust engine (memoxide) is a modified version of the original implementation.

## Features

- **Two-Tier Architecture**: Fast Rust engine (memoxide) + Volatility3 fallback for maximum coverage
- **Bounded Sessions and Results**: Image-fingerprint sessions, LRU cache, TTL-backed pagination, and opaque artifact resources
- **Auto-Detection**: Automatic OS profile detection and plugin name resolution
- **High Performance**: Rust native plugins for common operations (3s vs 60s)
- **Full Coverage**: Access to available Volatility3 plugins through the Volatility3 API
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
- Git CLI - used to clone/update the Volatility3 `stable` branch
- Rust toolchain (optional, for building memoxide from source)
- MCP-compatible client (Claude Desktop, VSCode, Cline, etc.)

## Installation

### 1. Configure Volatility3 Source

Volatility3 prefers a managed or explicitly trusted local Git checkout. A pinned pip package is used only when no valid Git source is available.

Create `.env` in the project root:
```bash
cp .env.example .env
```

Default `.env`:
```env
VOLATILITY3_REPO_URL=https://github.com/volatilityfoundation/volatility3
VOLATILITY3_BRANCH=stable
VOLATILITY3_REPO_PATH=.cache/volatility3
VOLATILITY3_UPDATE_MODE=background
VOLATILITY3_PIP_FALLBACK=true
MEMOXIDE_SYMBOLS_ROOT=/absolute/path/to/symbols/windows
```

### 2. Install MCP Server

**From Source:**
```bash
git clone https://github.com/jus1-c/mem-forensics-mcp-server.git
cd mem-forensics-mcp-server
pip install -e .
```

## Configuration

Logs are written to `mem-forensics-mcp.log` in the project/install root, next to `.env`.

### Claude Desktop

Edit `claude_desktop_config.json`:

**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`  
**Windows:** `%APPDATA%/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "mem-forensics": {
      "command": "python",
      "args": ["-m", "mem_forensics_mcp_server"]
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
- `os_hint`: Optional `windows`, `linux`, or `mac`; use Linux/macOS hints to skip Windows-native profile detection
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
- `args`: List of plugin arguments (optional, e.g., ["--pid", "1234"])
- `params`: Typed plugin parameter object; use `memory_describe_plugin` first for requirements
- `engine`: `auto`, `rust`, or `vol3`
- `allow_fallback`: Allow Rust-to-Vol3 fallback (default `true`)
- `filter`: Server-side filter string (optional)
- `background`: Run a long full-image scan as a cancellable job and return its `job_id` (default `false`)

**Important Notes:**
- `args` supports compatibility CLI-style plugin arguments; `params` is preferred for new integrations
- Output is always JSON-rendered through the Volatility3 API
- `-r json` is accepted but ignored for backward compatibility
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
- Vol3 plugins discovered from the managed `stable` checkout (Windows/Linux/Mac/Other)

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

### Result pages and artifacts

Large row results return a cursor for `memory_get_result_page`. Large structured reports and extracted files return an opaque `memforensics://artifact/<token>` resource link. Read it with the MCP resource API and release it early with `memory_release_result`; artifacts and result cursors expire automatically.

### Native analysis tools

Native Memoxide tools include full triage, process anomalies, injected-code/C2/command analysis, registry hive enumeration and queries, KDBG/RSDS scans, and guarded hash dumping. `memory_hashdump` requires `allow_sensitive: true` because it returns credential material.

### Curated cross-platform tools

Use these wrappers when an investigation needs a common task rather than a Volatility plugin name. They still execute through the isolated Volatility3 API worker and return the resolved canonical plugin in provenance.

| Tool | Windows | Linux | macOS |
|------|---------|-------|-------|
| `memory_dump_process_memory` | Memmap | Maps | Maps |
| `memory_list_memory_maps` | VadInfo | Maps | Maps |
| `memory_list_open_handles` | Handles | Lsof | Lsof |
| `memory_list_network_connections` | NetScan | Sockstat | Netstat |
| `memory_list_kernel_modules` | DriverScan | Lsmod | Lsmod |
| `memory_list_environment` | Envars | Envars | Not available |
| `memory_list_security_ids` | GetSIDs | Not available | Not available |
| `memory_scan_callbacks` | Callbacks | Not available | Not available |

`memory_extract_files` wraps Windows `DumpFiles`. `memory_dump_process_memory` enables Volatility's dump option; extracted bytes are returned as managed MCP artifact resources, not host filesystem paths.

### Evidence workflow tools

Pass structured results from `memory_run_plugin`, curated wrappers, or `memory_full_triage` directly into these tools:

- `memory_build_timeline`: emits only parseable timestamp evidence in chronological order.
- `memory_extract_iocs`: extracts conservative IP, URL, hash, PID, port, and domain observables while excluding secret-named fields.
- `memory_diff_results`: compares two plugin result snapshots using optional identity fields such as `pid`, `offset`, or `name`.
- `memory_response_playbook`: generates a reviewable preservation, validation, containment, and reporting sequence. It never changes a host.

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

- **Cache Key**: Image fingerprint, plugin, engine, arguments, and typed parameters
- **Invalidation**: Cache is invalidated when an image changes or its session closes
- **LRU Eviction**: Oldest entries removed when cache is full

**Benefits:**
- Second query for same plugin returns instantly
- Separate cache per memory dump file

## Security Features

- **Path Validation**: Only absolute paths allowed
- **Engine Isolation**: Rust plugins run in separate subprocess
- **Artifact Isolation**: Generated files are served only through server-managed opaque resource URIs
- **Timeout Protection**: 60s for quick Rust calls; 400s for image profiling and full-image scans
- **Size Limits**: Configurable response size limits
- **No Secrets**: No logging of sensitive memory contents

## .env Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `VOLATILITY3_REPO_URL` | Volatility3 git repository URL | `https://github.com/volatilityfoundation/volatility3` |
| `VOLATILITY3_BRANCH` | Volatility3 branch to use | `stable` |
| `VOLATILITY3_REPO_PATH` | Local checkout path, relative to project root if not absolute | `.cache/volatility3` |
| `VOLATILITY3_UPDATE_MODE` | Git update mode; updates run after MCP startup | `background` |
| `VOLATILITY3_PIP_FALLBACK` | Permit pinned pip fallback when no Git source is valid | `true` |
| `VOLATILITY3_LOCAL_REPOS` | Explicit trusted local Git checkouts; comma/semicolon separated | Empty |
| `MEMOXIDE_SYMBOLS_ROOT` | Absolute local Windows ISF symbol store forwarded to Memoxide | `symbols/windows` |

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
                         │  LRU Cache  │────▶│  Volatility3│
                         │             │     │ API Fallback│
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
│   │   ├── settings.py          # .env settings loader
│   │   ├── vol3_provider.py     # Managed/trusted Volatility3 source selection
│   │   ├── vol3_worker.py       # Isolated Vol3 Python API worker
│   │   ├── results.py           # Pagination and artifact lifecycle
│   │   └── jobs.py              # Background job lifecycle
│   ├── engine/
│   │   ├── memoxide_client.py   # Rust engine client
│   │   └── memoxide/            # Prebuilt binaries
│   │       ├── x86_64/
│   │       └── aarch64/
│   └── utils/
│       └── helpers.py
├── pyproject.toml
├── .env.example
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

Memoxide requires platform-specific binaries. This package currently includes:
- Windows x86_64
- Linux x86_64
- Linux aarch64

macOS uses Volatility3 unless a matching Memoxide binary is built and installed. The
GitHub Actions `native` job builds a macOS binary for the current `macos-latest`
runner architecture, stages it as `memoxide.macos`, builds a wheel, and uploads
the wheel and raw binary as workflow artifacts.

To build for other platforms:
```bash
cd mem_forensics_mcp_server/engine/memoxide-src
cargo build --release --target <target-triple>
```

After building, place the executable under
`mem_forensics_mcp_server/engine/memoxide/<architecture>/` using these names:

- Linux: `memoxide`
- Windows: `memoxide.exe`
- macOS: `memoxide.macos`

Run the `CI` workflow manually with **Run workflow** to produce platform build
artifacts without requiring a local cross-compilation toolchain. The workflow
does not commit generated binaries; download the matching wheel or binary from
the workflow run. Platforms without a matching native binary continue using the
Volatility3 fallback.

### Vol3 plugin requirements not met

Some memory dump formats may not be compatible with certain plugins. Error message will indicate:
- Translation layer issues (unsupported format)
- Symbol table issues (missing ISF files)

### Timeout errors on large dumps

Quick Rust calls have a 60s timeout. Image profiling and full-image native scans have a 400s timeout.
Use `background: true` for scans expected to exceed interactive latency, then poll `memory_get_job` or stop them with
`memory_cancel_job`.

### Plugin argument errors

This means the arguments passed do not match the plugin's Volatility3 requirements.
Use `memory_describe_plugin` for typed requirements or call `memory_list_plugins` to verify the
resolved plugin name.

## Recent Updates

### v0.2.0
- Added isolated Volatility3 API workers with background Git source refresh and pinned pip fallback
- Added typed plugin discovery, pagination, background jobs, YARA scanning, native registry tools, and sensitive hashdump gate
- Added server-managed MCP artifact resources, session cleanup, bounded symbol fallback, and explicit incomplete-triage reporting
- Added Python/Rust CI checks, platform-native Memoxide builds, and wheel packaging audit

## License

MIT License - see LICENSE file for details.

## Acknowledgments

- [xtk](https://github.com/x746b) - Original author of [mem-forensics-mcp](https://github.com/x746b/mem_forensics-mcp) and the memoxide Rust engine
- [Volatility3](https://github.com/volatilityfoundation/volatility3) - Memory forensics framework
- [Model Context Protocol](https://modelcontextprotocol.io/) - MCP specification
- [FastMCP](https://github.com/modelcontextprotocol/python-sdk) - Python MCP SDK

## Support

For issues and feature requests, please use the GitHub issue tracker.
