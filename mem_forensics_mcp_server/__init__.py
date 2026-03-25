"""Memory Forensics MCP Server"""

from .config import __version__
from .core import get_session

__all__ = ["__version__", "get_session"]
