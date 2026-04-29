"""Volatility3 API backend using a managed git checkout."""

from __future__ import annotations

import asyncio
import datetime as _datetime
import importlib
import io
import json
import logging
import sys
from pathlib import Path
from typing import Any, Optional

from ..config import DEFAULT_DUMP_DIR
from .vol3_repo import ensure_volatility3_repo, inspect_volatility3_repo

logger = logging.getLogger(__name__)

_plugins_imported = False
_plugin_import_failures: list[str] = []
_loaded_repo_path: Optional[Path] = None


def _module_path(module: object) -> Optional[Path]:
    module_file = getattr(module, "__file__", None)
    if not module_file:
        return None
    return Path(module_file).resolve()


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _purge_non_repo_volatility_modules(repo_path: Path) -> None:
    module = sys.modules.get("volatility3")
    if module is None:
        return

    module_path = _module_path(module)
    if module_path and _is_relative_to(module_path, repo_path):
        return

    for name in list(sys.modules):
        if name == "volatility3" or name.startswith("volatility3."):
            del sys.modules[name]


def _prepare_repo():
    global _loaded_repo_path

    if _loaded_repo_path is None:
        status = ensure_volatility3_repo()
    else:
        status = inspect_volatility3_repo()

    if not status.available:
        raise RuntimeError(status.error or "Volatility3 git checkout is unavailable")

    repo_path = Path(status.repo_path).resolve()
    if str(repo_path) not in sys.path:
        sys.path.insert(0, str(repo_path))

    _purge_non_repo_volatility_modules(repo_path)
    importlib.invalidate_caches()
    _loaded_repo_path = repo_path
    return status, repo_path


def _load_volatility3_modules() -> dict[str, Any]:
    status, repo_path = _prepare_repo()

    import volatility3
    import volatility3.plugins
    from volatility3 import framework
    from volatility3.framework import (
        automagic,
        constants,
        contexts,
        exceptions,
        interfaces,
        plugins,
    )
    from volatility3.framework.automagic import stacker
    from volatility3.framework.configuration import requirements
    from volatility3.framework.renderers import format_hints

    module_path = _module_path(volatility3)
    if not module_path or not _is_relative_to(module_path, repo_path):
        raise RuntimeError(
            f"Imported volatility3 from {module_path}, expected checkout under {repo_path}"
        )

    framework.require_interface_version(2, 0, 0)

    return {
        "status": status,
        "volatility3": volatility3,
        "framework": framework,
        "automagic": automagic,
        "constants": constants,
        "contexts": contexts,
        "exceptions": exceptions,
        "interfaces": interfaces,
        "plugins": plugins,
        "requirements": requirements,
        "stacker": stacker,
        "format_hints": format_hints,
    }


def _import_plugins(modules: dict[str, Any]) -> None:
    global _plugins_imported, _plugin_import_failures

    if _plugins_imported:
        return

    failures = modules["framework"].import_files(modules["volatility3"].plugins, True)
    _plugin_import_failures = sorted(failures) if failures else []
    _plugins_imported = True


def _strip_global_args(
    args: Optional[list[str]],
    constants: Any,
) -> tuple[list[str], Path]:
    tokens = list(args or [])
    filtered: list[str] = []
    output_dir = DEFAULT_DUMP_DIR
    skip_value_flags = {
        "-r",
        "--renderer",
        "--cache-path",
        "--parallelism",
        "--remote-isf-url",
        "--single-location",
        "--filters",
        "--hide-columns",
    }

    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token in skip_value_flags:
            index += 2
            continue
        if any(
            token.startswith(flag + "=") for flag in skip_value_flags if flag.startswith("--")
        ):
            index += 1
            continue
        if token in {"-o", "--output-dir"}:
            if index + 1 < len(tokens):
                output_dir = Path(tokens[index + 1]).expanduser().resolve()
            index += 2
            continue
        if token.startswith("--output-dir="):
            output_dir = Path(token.split("=", 1)[1]).expanduser().resolve()
            index += 1
            continue
        if token == "--offline":
            constants.OFFLINE = True
            index += 1
            continue
        filtered.append(token)
        index += 1

    return filtered, output_dir


def _bool_from_string(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _convert_value(value: str, requirement: Any, requirements: Any) -> Any:
    if isinstance(requirement, requirements.IntRequirement):
        return int(value, 0)
    if isinstance(requirement, requirements.BooleanRequirement):
        return _bool_from_string(value)
    if isinstance(requirement, requirements.URIRequirement):
        return requirements.URIRequirement.location_from_file(value)
    return requirement.instance_type(value)


def _convert_list(values: list[str], requirement: Any) -> list[Any]:
    if requirement.element_type is int:
        return [int(value, 0) for value in values]
    return [requirement.element_type(value) for value in values]


def _apply_plugin_args(
    context: Any,
    plugin: Any,
    plugin_config_path: str,
    args: list[str],
    interfaces: Any,
    requirements: Any,
) -> None:
    requirement_map = {}
    for requirement in plugin.get_requirements():
        option = "--" + requirement.name.replace("_", "-")
        requirement_map[option] = requirement
        requirement_map["--" + requirement.name] = requirement

    index = 0
    while index < len(args):
        token = args[index]
        if not token.startswith("--"):
            raise ValueError(f"Unexpected Volatility3 argument: {token}")

        inline_value: Optional[str] = None
        option = token
        if "=" in token:
            option, inline_value = token.split("=", 1)

        requirement = requirement_map.get(option)
        if requirement is None:
            raise ValueError(f"Unknown Volatility3 plugin argument: {option}")

        config_path = interfaces.configuration.path_join(
            plugin_config_path,
            requirement.name,
        )

        if isinstance(requirement, requirements.BooleanRequirement):
            if inline_value is not None:
                context.config[config_path] = _bool_from_string(inline_value)
            elif index + 1 < len(args) and args[index + 1].lower() in {
                "true",
                "false",
            }:
                context.config[config_path] = _bool_from_string(args[index + 1])
                index += 1
            else:
                context.config[config_path] = True
            index += 1
            continue

        values: list[str] = []
        if inline_value is not None:
            values.append(inline_value)
        else:
            index += 1
            while index < len(args) and not args[index].startswith("--"):
                values.append(args[index])
                index += 1
            index -= 1

        if not values:
            raise ValueError(f"Missing value for Volatility3 argument: {option}")

        if isinstance(requirement, requirements.ListRequirement):
            context.config[config_path] = _convert_list(values, requirement)
        elif isinstance(requirement, requirements.ChoiceRequirement):
            if values[0] not in requirement.choices:
                raise ValueError(f"Invalid value for {option}: {values[0]}")
            context.config[config_path] = values[0]
        elif isinstance(requirement, interfaces.configuration.SimpleTypeRequirement):
            context.config[config_path] = _convert_value(
                values[0],
                requirement,
                requirements,
            )
        else:
            raise ValueError(f"Unsupported Volatility3 argument: {option}")

        index += 1


def _unique_output_path(output_dir: Path, filename: str) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    candidate = output_dir / filename
    stem = candidate.stem
    suffix = candidate.suffix
    counter = 1
    while candidate.exists():
        candidate = output_dir / f"{stem}-{counter}{suffix}"
        counter += 1
    return candidate


def _file_handler_factory(output_dir: Path, dumped_files: list[str], interfaces: Any):
    class MCPFileHandler(io.BytesIO, interfaces.plugins.FileHandlerInterface):
        def __init__(self, filename: str):
            io.BytesIO.__init__(self)
            safe_name = self.sanitize_filename(filename)
            interfaces.plugins.FileHandlerInterface.__init__(self, safe_name)

        def close(self):
            if self.closed:
                return None

            self.seek(0)
            output_path = _unique_output_path(output_dir, self.preferred_filename)
            with output_path.open("wb") as output_file:
                output_file.write(self.read())
            self.preferred_filename = output_path.name
            dumped_files.append(str(output_path))
            return super().close()

    return MCPFileHandler


def _render_value(value: Any, interfaces: Any) -> Any:
    if isinstance(value, interfaces.renderers.BaseAbsentValue):
        return None
    if isinstance(value, _datetime.datetime):
        return value.isoformat()
    if isinstance(value, bytes):
        return " ".join(f"{byte:02x}" for byte in value)
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    try:
        json.dumps(value)
        return value
    except TypeError:
        return str(value)


def _treegrid_to_json(grid: Any, interfaces: Any) -> list[dict[str, Any]]:
    final_output: tuple[dict[str, dict[str, Any]], list[dict[str, Any]]] = ({}, [])

    def visitor(
        node: Any,
        accumulator: tuple[dict[str, dict[str, Any]], list[dict[str, Any]]],
    ):
        acc_map, final_tree = accumulator
        node_dict: dict[str, Any] = {"__children": []}
        values = list(node.values)

        for column_index, column in enumerate(grid.columns):
            node_dict[column.name] = _render_value(values[column_index], interfaces)

        if node.parent:
            acc_map[node.parent.path]["__children"].append(node_dict)
        else:
            final_tree.append(node_dict)
        acc_map[node.path] = node_dict
        return accumulator

    if not grid.populated:
        grid.populate(visitor, final_output)
    else:
        grid.visit(node=None, function=visitor, initial_accumulator=final_output)

    return final_output[1]


def _unsatisfied_details(excp: Any) -> list[str]:
    return [
        f"{path}: {requirement.description}"
        for path, requirement in excp.unsatisfied.items()
    ]


def _run_vol3_api_sync(
    image_path: str,
    plugin_name: str,
    args: Optional[list[str]] = None,
) -> dict[str, Any]:
    modules = _load_volatility3_modules()
    _import_plugins(modules)

    framework = modules["framework"]
    automagic = modules["automagic"]
    contexts = modules["contexts"]
    exceptions = modules["exceptions"]
    interfaces = modules["interfaces"]
    plugins = modules["plugins"]
    requirements = modules["requirements"]
    stacker = modules["stacker"]
    constants = modules["constants"]
    status = modules["status"]

    plugin_list = framework.list_plugins()
    if plugin_name not in plugin_list:
        suggestions = [
            name for name in sorted(plugin_list) if plugin_name.lower() in name.lower()
        ]
        return {
            "error": f"Volatility3 plugin not found: {plugin_name}",
            "engine": "vol3",
            "suggestions": suggestions[:20],
        }

    context = contexts.Context()
    available_automagics = automagic.available(context)
    plugin = plugin_list[plugin_name]
    base_config_path = "plugins"
    plugin_config_path = interfaces.configuration.path_join(
        base_config_path,
        plugin.__name__,
    )
    context.config["automagic.LayerStacker.single_location"] = (
        requirements.URIRequirement.location_from_file(str(image_path))
    )

    plugin_args, output_dir = _strip_global_args(args, constants)
    selected_automagics = automagic.choose_automagic(available_automagics, plugin)
    if context.config.get("automagic.LayerStacker.stackers", None) is None:
        context.config["automagic.LayerStacker.stackers"] = stacker.choose_os_stackers(
            plugin
        )
    _apply_plugin_args(
        context,
        plugin,
        plugin_config_path,
        plugin_args,
        interfaces,
        requirements,
    )

    dumped_files: list[str] = []

    try:
        constructed = plugins.construct_plugin(
            context,
            selected_automagics,
            plugin,
            base_config_path,
            lambda _progress, _description=None: None,
            _file_handler_factory(output_dir, dumped_files, interfaces),
        )
        grid = constructed.run()
        result: dict[str, Any] = {
            "results": _treegrid_to_json(grid, interfaces),
            "engine": "vol3",
            "volatility3": status.to_dict(),
        }
        if dumped_files:
            result["dumped_files"] = dumped_files
        if _plugin_import_failures:
            result["plugin_import_failures"] = _plugin_import_failures
        return result
    except exceptions.UnsatisfiedException as excp:
        return {
            "error": "Unable to validate plugin requirements",
            "engine": "vol3",
            "details": _unsatisfied_details(excp),
        }
    except exceptions.VolatilityException as excp:
        return {"error": f"Volatility3 failed: {excp}", "engine": "vol3"}
    except Exception as exc:
        logger.exception("Volatility3 API execution failed")
        return {"error": str(exc), "engine": "vol3"}


async def run_vol3_api(
    image_path: str,
    plugin: str,
    args: Optional[list[str]] = None,
    **_kwargs: Any,
) -> dict[str, Any]:
    """Run a Volatility3 plugin through the Python API."""
    return await asyncio.to_thread(_run_vol3_api_sync, image_path, plugin, args)


def _list_vol3_plugins_sync() -> dict[str, Any]:
    modules = _load_volatility3_modules()
    _import_plugins(modules)
    plugin_list = modules["framework"].list_plugins()

    plugins_by_os = {"windows": set(), "linux": set(), "mac": set(), "other": set()}
    for plugin_name in plugin_list:
        parts = plugin_name.split(".")
        if parts[0] in {"windows", "linux", "mac"} and len(parts) > 1:
            plugins_by_os[parts[0]].add(".".join(parts[1:]))
        else:
            plugins_by_os["other"].add(plugin_name)

    result = {
        "plugins": {key: sorted(value) for key, value in plugins_by_os.items()},
        "count": sum(len(value) for value in plugins_by_os.values()),
        "engine": "vol3",
        "source": "api",
        "volatility3": modules["status"].to_dict(),
    }
    if _plugin_import_failures:
        result["plugin_import_failures"] = _plugin_import_failures
    return result


async def list_vol3_plugins() -> dict[str, Any]:
    """List available Volatility3 plugins through the Python API."""
    try:
        return await asyncio.to_thread(_list_vol3_plugins_sync)
    except Exception as exc:
        return {"error": str(exc), "engine": "vol3"}


def get_vol3_status() -> dict[str, Any]:
    """Return Volatility3 repository/API status."""
    status = inspect_volatility3_repo().to_dict()
    status["api_loaded"] = _loaded_repo_path is not None
    status["source"] = "git"
    status["plugin_import_failures"] = _plugin_import_failures
    try:
        modules = (
            _load_volatility3_modules() if _loaded_repo_path is not None else None
        )
        if modules:
            status["package_version"] = modules["constants"].PACKAGE_VERSION
    except Exception as exc:
        status["error"] = status.get("error") or str(exc)
    return status
