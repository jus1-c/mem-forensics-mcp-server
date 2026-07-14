"""Configuration settings for mem-forensics-mcp-server."""

import os
import platform
import tempfile
from pathlib import Path
from typing import Mapping, Optional

from dotenv import dotenv_values

__version__ = "0.2.0"

# Response size limits
MAX_RESPONSE_SIZE = 40000
DEFAULT_PAGE_SIZE = 200
MAX_PAGE_SIZE = 1000

# Timeouts
PLUGIN_TIMEOUT = 400
MEMOXIDE_CALL_TIMEOUT = 60
MEMOXIDE_STOP_TIMEOUT = 5

# Paths
DEFAULT_DUMP_DIR = Path(tempfile.gettempdir()) / "memforensics_dumps"
DEFAULT_RESULT_DIR = Path(tempfile.gettempdir()) / "memforensics_results"
RESULT_TTL_SECONDS = 3600
MAX_STORED_RESULTS = 100
SESSION_TTL_SECONDS = 3600
MAX_SESSIONS = 16
MAX_YARA_RULE_SOURCE_BYTES = 256 * 1024
MAX_YARA_MATCH_INSTANCES = 1000
DEFAULT_YARA_TIMEOUT_SECONDS = 60

# Architecture detection
_ARCH_MAP = {"AMD64": "x86_64", "x86_64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}
_ARCH = _ARCH_MAP.get(platform.machine(), platform.machine())
_SYSTEM = {"darwin": "macos"}.get(platform.system().lower(), platform.system().lower())

# Memoxide binary path (inside package)
_PACKAGE_DIR = Path(__file__).parent

def bundled_memoxide_binary(system: str, architecture: str) -> Optional[Path]:
    """Return only a binary known to match its bundled operating system."""
    engine_root = _PACKAGE_DIR / "engine" / "memoxide"
    if system == "windows" and architecture == "x86_64":
        return engine_root / "x86_64" / "memoxide.exe"
    if system == "linux" and architecture in {"x86_64", "aarch64"}:
        return engine_root / architecture / "memoxide"
    if system in {"macos", "darwin"} and architecture in {"x86_64", "aarch64"}:
        return engine_root / architecture / "memoxide.macos"
    return None


MEMOXIDE_BINARY = bundled_memoxide_binary(_SYSTEM, _ARCH)
MEMOXIDE_SRC_DIR = _PACKAGE_DIR / "engine" / "memoxide-src"


def get_memoxide_symbols_root(
    *,
    environment: Optional[Mapping[str, str]] = None,
    dotenv_path: Optional[Path] = None,
) -> Path:
    """Resolve the symbol store without mutating process environment state."""
    environment = os.environ if environment is None else environment
    dotenv_path = dotenv_path or (_PACKAGE_DIR.parent / ".env")
    file_values = dotenv_values(dotenv_path) if dotenv_path.is_file() else {}
    environment_value = environment.get("MEMOXIDE_SYMBOLS_ROOT")
    raw = environment_value or file_values.get("MEMOXIDE_SYMBOLS_ROOT")
    path = Path(raw or (_PACKAGE_DIR.parent / "symbols" / "windows")).expanduser()
    if not path.is_absolute():
        path = (_PACKAGE_DIR.parent if environment_value else dotenv_path.parent) / path
    return path.resolve()


MEMOXIDE_SYMBOLS_ROOT = get_memoxide_symbols_root()

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
    "readraw",  # Read raw physical memory
    "rsds",  # Scan debug directory records for symbol discovery
}

# Compatibility aliases accepted by the Python MCP facade. The Rust engine
# exposes only canonical names over its own MCP transport.
RUST_PLUGIN_ALIASES = {
    "memsearch": "search",
}
