"""Volatility3 CLI wrapper."""

from __future__ import annotations

import asyncio
import csv
import io
import json
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


async def run_vol3_cli(
    image_path: str,
    plugin: str,
    args: Optional[list[str]] = None,
    **kwargs,
) -> dict[str, Any]:
    """Run Volatility3 via CLI.

    Args:
        image_path: Path to memory dump
        plugin: Full plugin name (e.g., windows.pslist.PsList)
        args: Optional list of additional arguments (e.g., ["--pid", "1234", "-r", "json"])
    """

    # Try to find vol.py or use volatility3 module
    vol3_path = os.environ.get("VOLATILITY3_PATH", "")

    if vol3_path and Path(vol3_path).exists():
        # Use specified vol.py
        cmd = [str(Path(vol3_path) / "vol.py"), "-f", str(image_path)]
    else:
        # Try to find vol.exe or vol.py in PATH
        import shutil

        vol_exe = shutil.which("vol") or shutil.which("vol.exe")
        if vol_exe:
            cmd = [vol_exe, "-f", str(image_path)]
        else:
            # Fallback to python -m volatility3
            try:
                import volatility3

                vol3_installed = True
            except ImportError:
                vol3_installed = False

            if not vol3_installed:
                return {
                    "error": "Volatility3 not found. Install with: pip install volatility3",
                    "engine": "vol3",
                }

            cmd = ["python", "-m", "volatility3", "-f", str(image_path)]

    # Add any extra args before plugin
    if args:
        cmd.extend(args)
    else:
        # Default to JSON output if no args specified
        cmd.extend(["-r", "json"])

    # Check if -r already in args, if not add default
    if "-r" not in cmd and "--renderer" not in cmd:
        cmd.extend(["-r", "json"])

    # Add plugin name (full format)
    cmd.append(plugin)

    logger.info(f"Running Vol3 CLI: {' '.join(cmd)}")

    try:
        # Use different approach for Windows vs Unix
        if sys.platform == "win32":
            # Windows: use subprocess.Popen directly in thread
            from concurrent.futures import ThreadPoolExecutor

            def run_in_thread():
                proc = subprocess.Popen(
                    cmd,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                stdout, stderr = proc.communicate()
                return proc.returncode, stdout, stderr

            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor(max_workers=1) as executor:
                returncode, stdout, stderr = await loop.run_in_executor(executor, run_in_thread)
        else:
            # Unix/Linux: use asyncio subprocess with large buffer
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                limit=250 * 1024 * 1024,  # 250MB buffer for large outputs
            )

            stdout, stderr = await proc.communicate()
            returncode = proc.returncode

        if returncode != 0:
            stderr_text = stderr.decode()
            # Check for specific Vol3 errors
            if "Unsatisfied requirement" in stderr_text:
                # Extract the specific requirements
                import re

                requirements = re.findall(r"Unsatisfied requirement [\w.]+", stderr_text)
                return {
                    "error": f"Plugin requirements not met: {', '.join(requirements)}",
                    "engine": "vol3",
                    "details": "The memory dump format may not be supported by this plugin",
                }
            elif "Unable to validate the plugin requirements" in stderr_text:
                return {
                    "error": "Unable to validate plugin requirements - memory dump may be incompatible",
                    "engine": "vol3",
                    "details": stderr_text[:300],
                }
            return {"error": f"Vol3 failed: {stderr_text[:500]}", "engine": "vol3"}

        # Parse JSON output
        output = stdout.decode()
        try:
            data = json.loads(output)
            return {"results": data, "engine": "vol3"}
        except json.JSONDecodeError:
            # Try CSV parsing
            return _parse_csv_output(output)

    except Exception as e:
        return {"error": str(e), "engine": "vol3"}


def _parse_csv_output(output: str) -> dict[str, Any]:
    """Parse CSV output from Vol3."""
    lines = output.strip().split("\n")

    # Find CSV header
    csv_start = 0
    for i, line in enumerate(lines):
        if "," in line and not line.startswith("Volatility"):
            csv_start = i
            break

    csv_text = "\n".join(lines[csv_start:])
    reader = csv.DictReader(io.StringIO(csv_text))
    rows = list(reader)

    return {"results": rows, "engine": "vol3", "format": "csv"}


async def list_vol3_plugins() -> dict[str, Any]:
    """List all available Volatility3 plugins by parsing vol --help."""
    import shutil
    import re

    vol_exe = shutil.which("vol") or shutil.which("vol.exe")
    if not vol_exe:
        return {"error": "Volatility3 not found in PATH"}

    try:
        if sys.platform == "win32":
            # Windows: use subprocess in thread
            from concurrent.futures import ThreadPoolExecutor

            def run_help():
                proc = subprocess.Popen(
                    [vol_exe, "--help"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.DEVNULL,
                )
                stdout, stderr = proc.communicate(timeout=30)  # Timeout 30s
                return proc.returncode, stdout, stderr

            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor(max_workers=1) as executor:
                returncode, stdout, stderr = await asyncio.wait_for(
                    loop.run_in_executor(executor, run_help), timeout=35
                )
        else:
            proc = await asyncio.create_subprocess_exec(
                vol_exe,
                "--help",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
            returncode = proc.returncode

        if returncode != 0:
            return {"error": f"Failed to get help: {stderr.decode()[:200]}"}

        output = stdout.decode()

        # Parse plugins from help output - optimized version
        # Compile regex once
        os_pattern = re.compile(r"^(windows|linux|mac)\.([\w.]+)$")

        plugins = {
            "windows": set(),
            "linux": set(),
            "mac": set(),
            "other": set(),
        }

        for line in output.split("\n"):
            line = line.strip()
            if not line:
                continue

            parts = line.split()
            if not parts:
                continue

            plugin_full = parts[0]
            if "." not in plugin_full:
                continue

            # Match OS-specific plugins: "windows.pslist.PsList"
            match = os_pattern.match(plugin_full)
            if match:
                plugins[match.group(1)].add(match.group(2))
                continue

            # Match standalone plugins
            parts = plugin_full.split(".")
            if len(parts) >= 2 and parts[-1] and parts[-1][0].isupper():
                plugins["other"].add(plugin_full)

        # Convert sets to sorted lists
        return {
            "plugins": {k: sorted(v) for k, v in plugins.items()},
            "count": sum(len(v) for v in plugins.values()),
            "engine": "vol3",
        }
    except asyncio.TimeoutError:
        return {"error": "Timeout getting plugin list (30s)", "engine": "vol3"}
    except subprocess.TimeoutExpired:
        return {"error": "Timeout getting plugin list (30s)", "engine": "vol3"}
    except Exception as e:
        return {"error": str(e), "engine": "vol3"}
