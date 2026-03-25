# mem-forensics-mcp-server

Memory Forensics MCP Server - Two-tier engine combining Rust speed with Volatility3 coverage.

## Architecture

```
┌────────────────────────────────────────┐
│         MCP Server (Python)            │
│                                        │
│   ┌──────────────┐  ┌──────────────┐   │
│   │  Tier 1      │  │  Tier 2      │   │
│   │  Rust Engine │  │  Volatility3 │   │
│   │  (memoxide)  │  │  (Fallback)  │   │
│   │              │  │              │   │
│   │  • pslist    │  │  • filescan  │   │
│   │  • psscan    │  │  • handles   │   │
│   │  • malfind   │  │  • svcscan   │   │
│   │  • netscan   │  │  • etc...    │   │
│   └──────────────┘  └──────────────┘   │
│                                        │
│        Auto-Routing (Rust → Vol3)      │
└────────────────────────────────────────┘
```

## Installation

```bash
pip install mem-forensics-mcp-server
```

Or with Volatility3:
```bash
pip install mem-forensics-mcp-server[volatility3]
```

## Usage

```python
# Initialize
memory_analyze_image(image_path="/path/to/memory.raw")

# Run plugin (auto-routed to fastest engine)
memory_run_plugin(
    image_path="/path/to/memory.raw",
    plugin="pslist"
)

# List files in memory
memory_list_dumpable_files(image_path="/path/to/memory.raw")
```

## Building Rust Engine

If prebuilt binaries don't work for your platform:

```bash
cd mem_forensics_mcp_server/engine/memoxide-src
cargo build --release
```

## License

MIT
