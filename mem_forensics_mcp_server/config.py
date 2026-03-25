"""Configuration settings for mem-forensics-mcp-server."""

import os
import platform
from pathlib import Path

__version__ = "0.1.0"

# Response size limits
MAX_RESPONSE_SIZE = 40000

# Timeouts
PLUGIN_TIMEOUT = 300
MEMOXIDE_CALL_TIMEOUT = 60

# Paths
DEFAULT_DUMP_DIR = Path("/tmp/memforensics_dumps")

# Architecture detection
_ARCH_MAP = {"AMD64": "x86_64", "x86_64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}
_ARCH = _ARCH_MAP.get(platform.machine(), platform.machine())

# Memoxide binary path (inside package)
_PACKAGE_DIR = Path(__file__).parent

# Use .exe extension on Windows
_is_windows = platform.system() == "Windows"
_memoxide_name = "memoxide.exe" if _is_windows else "memoxide"
MEMOXIDE_BINARY = _PACKAGE_DIR / "engine" / "memoxide" / _ARCH / _memoxide_name
MEMOXIDE_SRC_DIR = _PACKAGE_DIR / "engine" / "memoxide-src"

# Volatility3 settings
VOLATILITY3_PATH = os.environ.get("VOLATILITY3_PATH", "")

# Plugins supported by Rust engine (from memoxide source)
RUST_PLUGINS = {
    # Process plugins
    "pslist",  # List processes
    "psscan",  # Scan for processes
    "cmdline",  # Process command lines
    "dlllist",  # List loaded DLLs
    "cmdscan",  # Scan for command history
    # Memory plugins
    "malfind",  # Find injected code
    "netscan",  # Network connections
    "search",  # Memory search (memsearch.rs)
    "memsearch",  # Alias for search
}
