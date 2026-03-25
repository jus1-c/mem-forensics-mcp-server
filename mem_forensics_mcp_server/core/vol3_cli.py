"""Volatility3 CLI wrapper."""

from __future__ import annotations

import asyncio
import csv
import io
import json
import logging
import os
import subprocess
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


async def run_vol3_cli(
    image_path: str,
    plugin: str,
    pid: Optional[int] = None,
    output_dir: Optional[str] = None,
    **kwargs,
) -> dict[str, Any]:
    """Run Volatility3 via CLI."""

    # Try to find vol.py or use volatility3 module
    vol3_path = os.environ.get("VOLATILITY3_PATH", "")

    if vol3_path and Path(vol3_path).exists():
        # Use specified vol.py
        cmd = [str(Path(vol3_path) / "vol.py"), "-f", str(image_path), "-r", "json"]
    else:
        # Try to find vol.exe or vol.py in PATH
        import shutil

        vol_exe = shutil.which("vol") or shutil.which("vol.exe")
        if vol_exe:
            cmd = [vol_exe, "-f", str(image_path), "-r", "json"]
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

            cmd = ["python", "-m", "volatility3", "-f", str(image_path), "-r", "json"]

    if pid is not None:
        cmd.extend(["--pid", str(pid)])

    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        cmd.extend(["-o", output_dir])

    # Add plugin
    cmd.append(plugin)

    logger.info(f"Running Vol3 CLI: {' '.join(cmd)}")

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)

        if proc.returncode != 0:
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

    except asyncio.TimeoutError:
        return {"error": "Vol3 timed out after 300s", "engine": "vol3"}
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
        proc = await asyncio.create_subprocess_exec(
            vol_exe,
            "--help",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)

        if proc.returncode != 0:
            return {"error": f"Failed to get help: {stderr.decode()[:200]}"}

        output = stdout.decode()

        # Parse plugins from help output
        # Format: "    windows.pslist.PsList"
        # or: "    linux.pslist.PsList"
        # or: "    mac.pslist.PsList"
        # or standalone: "    timeliner.Timeliner"

        plugins = {
            "windows": [],
            "linux": [],
            "mac": [],
            "other": [],
        }

        for line in output.split("\n"):
            line = line.strip()

            # Skip empty lines
            if not line:
                continue

            # Extract plugin name (first word before any spaces/descriptions)
            # Format: "    banners.Banners     Attempts to identify..."
            parts = line.split()
            if not parts:
                continue

            plugin_full = parts[0]

            # Skip lines without dots (not plugins)
            if "." not in plugin_full:
                continue

            # Match OS-specific plugins: "windows.pslist.PsList"
            match = re.match(r"^(windows|linux|mac)\.([\w\.]+)$", plugin_full)
            if match:
                os_type = match.group(1)
                plugin_name = match.group(2)
                plugins[os_type].append(plugin_name)
                continue

            # Match standalone plugins: any format like "module.Class"
            # Must have at least one dot and look like PluginName.ClassName
            parts = plugin_full.split(".")
            if len(parts) >= 2:
                # Check if last part starts with uppercase (class name)
                if parts[-1] and parts[-1][0].isupper():
                    plugins["other"].append(plugin_full)

        # Sort and remove duplicates
        for key in plugins:
            plugins[key] = sorted(set(plugins[key]))

        return {
            "plugins": plugins,
            "count": sum(len(v) for v in plugins.values()),
            "engine": "vol3",
        }

    except asyncio.TimeoutError:
        return {"error": "Timeout getting plugin list"}
    except Exception as e:
        return {"error": str(e)}
