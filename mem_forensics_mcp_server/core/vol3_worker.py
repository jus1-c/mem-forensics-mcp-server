"""JSON-lines worker that runs the Volatility3 Python API without its CLI.

This module deliberately imports Volatility3 only after selecting a source. A
fresh worker process lets the MCP facade move between Git revisions and pip
without mutating ``sys.modules`` in a live server process.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as datetime_module
import importlib
import io
import json
import logging
import sys
import traceback
from pathlib import Path
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)
_PROTOCOL_OUT = sys.stdout


class WorkerError(Exception):
    """Expected client-facing error with a stable code."""

    def __init__(self, code: str, message: str, details: Optional[list[str]] = None):
        super().__init__(message)
        self.code = code
        self.details = details or []


class Vol3ApiWorker:
    """Own one Volatility3 interpreter and serialize its API calls."""

    def __init__(self, source_kind: str, source_path: Optional[str]):
        self.source_kind = source_kind
        self.source_path = Path(source_path).resolve() if source_path else None
        self.modules: Optional[dict[str, Any]] = None
        self.plugin_import_failures: list[str] = []
        self.plugins_imported = False

    def source_metadata(self) -> dict[str, Any]:
        return {
            "source": self.source_kind,
            "path": str(self.source_path) if self.source_path else None,
        }

    def bootstrap(self) -> dict[str, Any]:
        if self.modules is not None:
            return self._health_result()

        if self.source_kind == "git":
            if self.source_path is None or not (self.source_path / "volatility3" / "__init__.py").is_file():
                raise WorkerError("source_unavailable", "Configured Git Volatility3 source is unavailable")
            sys.path.insert(0, str(self.source_path))

        importlib.invalidate_caches()
        try:
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
        except Exception as exc:
            raise WorkerError("bootstrap_failed", f"Could not import Volatility3: {exc}") from exc

        module_path = Path(getattr(volatility3, "__file__", "")).resolve()
        if self.source_kind == "git":
            try:
                module_path.relative_to(self.source_path)
            except ValueError as exc:
                raise WorkerError(
                    "wrong_source",
                    f"Imported Volatility3 from {module_path}, expected {self.source_path}",
                ) from exc

        try:
            framework.require_interface_version(2, 0, 0)
            failures = framework.import_files(volatility3.plugins, True)
        except Exception as exc:
            raise WorkerError("bootstrap_failed", f"Volatility3 initialization failed: {exc}") from exc

        self.modules = {
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
        }
        self.plugin_import_failures = sorted(failures) if failures else []
        self.plugins_imported = True

        plugin_names = set(framework.list_plugins())
        required = {"windows.info.Info", "windows.pslist.PsList", "banners.Banners"}
        missing = sorted(required - plugin_names)
        if missing:
            raise WorkerError("bootstrap_failed", f"Missing core Volatility3 plugins: {missing}")
        return self._health_result()

    def _health_result(self) -> dict[str, Any]:
        assert self.modules is not None
        constants = self.modules["constants"]
        return {
            "ok": True,
            "engine": "vol3",
            "volatility3": {
                **self.source_metadata(),
                "package_version": getattr(constants, "PACKAGE_VERSION", None),
                "plugin_import_failures": self.plugin_import_failures,
                "plugin_count": len(self.modules["framework"].list_plugins()),
            },
        }

    def list_plugins(self) -> dict[str, Any]:
        self.bootstrap()
        assert self.modules is not None
        plugin_list = self.modules["framework"].list_plugins()
        descriptors = [
            self._plugin_descriptor(name, plugin)
            for name, plugin in sorted(plugin_list.items(), key=lambda item: item[0].lower())
        ]
        groups = {"windows": [], "linux": [], "mac": [], "other": []}
        for descriptor in descriptors:
            groups[descriptor["os"]].append(descriptor)
        return {
            "engine": "vol3",
            "plugins": groups,
            "count": len(descriptors),
            "volatility3": self._health_result()["volatility3"],
        }

    def describe_plugin(self, plugin_name: str) -> dict[str, Any]:
        self.bootstrap()
        assert self.modules is not None
        plugin = self.modules["framework"].list_plugins().get(plugin_name)
        if plugin is None:
            raise self._plugin_not_found(plugin_name)
        return {
            "engine": "vol3",
            "plugin": self._plugin_descriptor(plugin_name, plugin),
            "volatility3": self._health_result()["volatility3"],
        }

    def _plugin_descriptor(self, name: str, plugin: Any) -> dict[str, Any]:
        parts = name.split(".")
        os_name = parts[0] if len(parts) > 1 and parts[0] in {"windows", "linux", "mac"} else "other"
        # Canonical names may include namespaces, for example
        # windows.registry.printkey.PrintKey. The useful short alias is the
        # module immediately before the class, not the first namespace.
        alias = parts[-2] if len(parts) >= 2 else parts[0]
        doc = (plugin.__doc__ or "").strip().split("\n\n", 1)[0]
        return {
            "canonical_name": name,
            "aliases": [alias.lower()],
            "os": os_name,
            "description": doc,
            "parameters": [self._requirement_descriptor(requirement) for requirement in plugin.get_requirements()],
        }

    def _requirement_descriptor(self, requirement: Any) -> dict[str, Any]:
        assert self.modules is not None
        requirements = self.modules["requirements"]
        kind = "automagic"
        item_type: Optional[str] = None
        choices: Optional[list[str]] = None
        user_configurable = False
        if isinstance(requirement, requirements.BooleanRequirement):
            kind = "boolean"
            user_configurable = True
        elif isinstance(requirement, requirements.IntRequirement):
            kind = "integer"
            user_configurable = True
        elif isinstance(requirement, requirements.URIRequirement):
            kind = "uri"
            user_configurable = True
        elif isinstance(requirement, requirements.ListRequirement):
            kind = "array"
            user_configurable = True
            item_type = getattr(requirement.element_type, "__name__", str(requirement.element_type))
        elif isinstance(requirement, requirements.ChoiceRequirement):
            kind = "choice"
            user_configurable = True
            choices = [str(choice) for choice in requirement.choices]
        elif getattr(requirement, "instance_type", None) is not None:
            kind = getattr(requirement.instance_type, "__name__", "string")
            user_configurable = True
        default = getattr(requirement, "default", None)
        try:
            json.dumps(default)
        except TypeError:
            default = str(default)
        return {
            "name": requirement.name,
            "option": "--" + requirement.name.replace("_", "-"),
            "description": getattr(requirement, "description", ""),
            "required": user_configurable and not bool(getattr(requirement, "optional", False)),
            "managed_by_automagic": not user_configurable,
            "kind": kind,
            "item_type": item_type,
            "choices": choices,
            "default": default,
        }

    def _plugin_not_found(self, plugin_name: str) -> WorkerError:
        assert self.modules is not None
        names = sorted(self.modules["framework"].list_plugins())
        query = plugin_name.lower()
        suggestions = [name for name in names if query in name.lower()][:20]
        return WorkerError(
            "plugin_not_found",
            f"Volatility3 plugin not found: {plugin_name}",
            suggestions,
        )

    def run_plugin(
        self,
        image_path: str,
        plugin_name: str,
        args: Optional[list[str]] = None,
        params: Optional[dict[str, Any]] = None,
        output_dir: Optional[str] = None,
        progress: Optional[Callable[[float, Optional[str]], None]] = None,
    ) -> dict[str, Any]:
        self.bootstrap()
        assert self.modules is not None
        image = Path(image_path).expanduser().resolve()
        if not image.is_file():
            raise WorkerError("image_not_found", f"Memory image is not a regular file: {image}")

        framework = self.modules["framework"]
        plugin = framework.list_plugins().get(plugin_name)
        if plugin is None:
            raise self._plugin_not_found(plugin_name)

        contexts = self.modules["contexts"]
        automagic = self.modules["automagic"]
        interfaces = self.modules["interfaces"]
        plugins = self.modules["plugins"]
        requirements = self.modules["requirements"]
        stacker = self.modules["stacker"]
        constants = self.modules["constants"]
        exceptions = self.modules["exceptions"]
        context = contexts.Context()
        base_config_path = "plugins"
        plugin_config_path = interfaces.configuration.path_join(base_config_path, plugin.__name__)
        context.config["automagic.LayerStacker.single_location"] = requirements.URIRequirement.location_from_file(
            str(image)
        )

        plugin_args, offline, warnings = self._strip_legacy_args(args or [])
        previous_offline = getattr(constants, "OFFLINE", False)
        constants.OFFLINE = offline
        try:
            self._apply_plugin_args(context, plugin, plugin_config_path, plugin_args)
            self._apply_plugin_params(context, plugin, plugin_config_path, params or {})
            available_automagics = automagic.available(context)
            selected_automagics = automagic.choose_automagic(available_automagics, plugin)
            if context.config.get("automagic.LayerStacker.stackers", None) is None:
                context.config["automagic.LayerStacker.stackers"] = stacker.choose_os_stackers(plugin)

            artifact_dir = self._validated_output_dir(output_dir)
            dumped_files: list[str] = []

            def report_progress(value: float, description: Optional[str] = None) -> None:
                if progress:
                    progress(value, description)

            try:
                constructed = plugins.construct_plugin(
                    context,
                    selected_automagics,
                    plugin,
                    base_config_path,
                    report_progress,
                    self._file_handler_factory(artifact_dir, dumped_files),
                )
                grid = constructed.run()
                result: dict[str, Any] = {
                    "results": self._treegrid_to_json(grid),
                    "engine": "vol3",
                    "warnings": warnings,
                    "volatility3": self._health_result()["volatility3"],
                }
                if dumped_files:
                    result["dumped_files"] = dumped_files
                if self.plugin_import_failures:
                    result["plugin_import_failures"] = self.plugin_import_failures
                return result
            except exceptions.UnsatisfiedException as excp:
                raise WorkerError(
                    "requirements_unsatisfied",
                    "Unable to validate plugin requirements",
                    self._unsatisfied_details(excp),
                ) from excp
            except exceptions.VolatilityException as excp:
                raise WorkerError("volatility_error", f"Volatility3 failed: {excp}") from excp
        finally:
            constants.OFFLINE = previous_offline

    def _strip_legacy_args(self, args: list[str]) -> tuple[list[str], bool, list[str]]:
        """Accept harmless CLI compatibility flags but never delegate to a CLI."""
        filtered: list[str] = []
        warnings: list[str] = []
        offline = False
        skip_value_flags = {
            "-r",
            "--renderer",
            "--cache-path",
            "--parallelism",
            "--remote-isf-url",
            "--single-location",
            "--filters",
            "--hide-columns",
            "-o",
            "--output-dir",
        }
        index = 0
        while index < len(args):
            token = args[index]
            if token == "--offline":
                offline = True
                index += 1
                continue
            if token in skip_value_flags:
                warnings.append(f"Ignored CLI-only option: {token}")
                index += 2
                continue
            if any(token.startswith(flag + "=") for flag in skip_value_flags if flag.startswith("--")):
                warnings.append(f"Ignored CLI-only option: {token.split('=', 1)[0]}")
                index += 1
                continue
            filtered.append(token)
            index += 1
        return filtered, offline, warnings

    def _apply_plugin_args(self, context: Any, plugin: Any, config_path: str, args: list[str]) -> None:
        requirement_map = self._requirement_map(plugin)
        index = 0
        while index < len(args):
            token = args[index]
            if not token.startswith("--"):
                raise WorkerError("invalid_arguments", f"Unexpected Volatility3 argument: {token}")
            option, separator, inline_value = token.partition("=")
            requirement = requirement_map.get(option)
            if requirement is None:
                raise WorkerError("invalid_arguments", f"Unknown Volatility3 plugin argument: {option}")
            values: list[Any]
            if self._is_boolean(requirement):
                if separator:
                    values = [inline_value]
                elif index + 1 < len(args) and args[index + 1].lower() in {"true", "false"}:
                    values = [args[index + 1]]
                    index += 1
                else:
                    values = [True]
            elif separator:
                values = [inline_value]
            else:
                index += 1
                values = []
                while index < len(args) and not args[index].startswith("--"):
                    values.append(args[index])
                    index += 1
                index -= 1
            self._set_requirement_value(context, config_path, requirement, values)
            index += 1

    def _apply_plugin_params(
        self,
        context: Any,
        plugin: Any,
        config_path: str,
        params: dict[str, Any],
    ) -> None:
        if not isinstance(params, dict):
            raise WorkerError("invalid_parameters", "Plugin params must be a JSON object")
        requirements_by_name: dict[str, Any] = {}
        for requirement in plugin.get_requirements():
            # Volatility uses both underscore and hyphenated requirement names
            # (for example, ``ignore-case``). Accept either JSON spelling.
            requirements_by_name[requirement.name] = requirement
            requirements_by_name[requirement.name.replace("-", "_")] = requirement
            requirements_by_name[requirement.name.replace("_", "-")] = requirement
        for name, value in params.items():
            requirement = requirements_by_name.get(name)
            if requirement is None:
                raise WorkerError("invalid_parameters", f"Unknown Volatility3 plugin parameter: {name}")
            values = value if isinstance(value, list) and self._is_list(requirement) else [value]
            self._set_requirement_value(context, config_path, requirement, values)

    def _requirement_map(self, plugin: Any) -> dict[str, Any]:
        mapped: dict[str, Any] = {}
        for requirement in plugin.get_requirements():
            mapped["--" + requirement.name.replace("_", "-")] = requirement
            mapped["--" + requirement.name] = requirement
        return mapped

    def _is_boolean(self, requirement: Any) -> bool:
        assert self.modules is not None
        return isinstance(requirement, self.modules["requirements"].BooleanRequirement)

    def _is_list(self, requirement: Any) -> bool:
        assert self.modules is not None
        return isinstance(requirement, self.modules["requirements"].ListRequirement)

    def _set_requirement_value(
        self,
        context: Any,
        config_path: str,
        requirement: Any,
        values: list[Any],
    ) -> None:
        assert self.modules is not None
        interfaces = self.modules["interfaces"]
        requirements = self.modules["requirements"]
        path = interfaces.configuration.path_join(config_path, requirement.name)
        try:
            if isinstance(requirement, requirements.BooleanRequirement):
                value = values[0]
                context.config[path] = self._bool(value)
            elif isinstance(requirement, requirements.ListRequirement):
                context.config[path] = [self._convert_list_item(value, requirement.element_type) for value in values]
            elif isinstance(requirement, requirements.ChoiceRequirement):
                value = str(values[0])
                if value not in requirement.choices:
                    raise ValueError(f"Invalid value for --{requirement.name}: {value}")
                context.config[path] = value
            elif isinstance(requirement, requirements.IntRequirement):
                value = values[0]
                context.config[path] = int(value, 0) if isinstance(value, str) else int(value)
            elif isinstance(requirement, requirements.URIRequirement):
                value = str(values[0])
                context.config[path] = requirements.URIRequirement.location_from_file(value)
            elif isinstance(requirement, interfaces.configuration.SimpleTypeRequirement):
                context.config[path] = requirement.instance_type(values[0])
            else:
                raise ValueError(f"Unsupported Volatility3 parameter: --{requirement.name}")
        except (TypeError, ValueError) as exc:
            raise WorkerError("invalid_parameters", str(exc)) from exc

    @staticmethod
    def _convert_list_item(value: Any, item_type: Any) -> Any:
        if item_type is int:
            return int(value, 0) if isinstance(value, str) else int(value)
        return item_type(value)

    @staticmethod
    def _bool(value: Any) -> bool:
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in {"1", "true", "yes", "on"}

    @staticmethod
    def _validated_output_dir(output_dir: Optional[str]) -> Path:
        if not output_dir:
            raise WorkerError("artifact_directory_missing", "Worker was not assigned an artifact directory")
        directory = Path(output_dir).expanduser().resolve()
        directory.mkdir(parents=True, exist_ok=True)
        if not directory.is_dir():
            raise WorkerError("artifact_directory_invalid", f"Artifact path is not a directory: {directory}")
        return directory

    def _file_handler_factory(self, output_dir: Path, dumped_files: list[str]) -> type:
        assert self.modules is not None
        interfaces = self.modules["interfaces"]

        class MCPFileHandler(io.BytesIO, interfaces.plugins.FileHandlerInterface):
            def __init__(self, filename: str):
                io.BytesIO.__init__(self)
                safe_name = self.sanitize_filename(filename)
                interfaces.plugins.FileHandlerInterface.__init__(self, safe_name)

            def close(self):
                if self.closed:
                    return None
                self.seek(0)
                output_path = Vol3ApiWorker._unique_output_path(output_dir, self.preferred_filename)
                with output_path.open("wb") as output_file:
                    output_file.write(self.read())
                self.preferred_filename = output_path.name
                dumped_files.append(str(output_path))
                return super().close()

        return MCPFileHandler

    @staticmethod
    def _unique_output_path(output_dir: Path, filename: str) -> Path:
        candidate = output_dir / Path(filename).name
        stem = candidate.stem
        suffix = candidate.suffix
        counter = 1
        while candidate.exists():
            candidate = output_dir / f"{stem}-{counter}{suffix}"
            counter += 1
        return candidate

    def _treegrid_to_json(self, grid: Any) -> list[dict[str, Any]]:
        assert self.modules is not None
        interfaces = self.modules["interfaces"]
        final_output: tuple[dict[str, dict[str, Any]], list[dict[str, Any]]] = ({}, [])

        def visitor(
            node: Any,
            accumulator: tuple[dict[str, dict[str, Any]], list[dict[str, Any]]],
        ):
            node_map, tree = accumulator
            row: dict[str, Any] = {"__children": []}
            for index, column in enumerate(grid.columns):
                row[column.name] = self._render_value(list(node.values)[index], interfaces)
            if node.parent and node.parent.path in node_map:
                node_map[node.parent.path]["__children"].append(row)
            else:
                tree.append(row)
            node_map[node.path] = row
            return accumulator

        if not grid.populated:
            grid.populate(visitor, final_output)
        else:
            grid.visit(node=None, function=visitor, initial_accumulator=final_output)
        return final_output[1]

    @staticmethod
    def _render_value(value: Any, interfaces: Any) -> Any:
        if isinstance(value, interfaces.renderers.BaseAbsentValue):
            return None
        if isinstance(value, datetime_module.datetime):
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

    @staticmethod
    def _unsatisfied_details(excp: Any) -> list[str]:
        return [
            f"{path}: {requirement.description}"
            for path, requirement in excp.unsatisfied.items()
        ]


def _send(message: dict[str, Any]) -> None:
    _PROTOCOL_OUT.write(json.dumps(message, default=str, separators=(",", ":")) + "\n")
    _PROTOCOL_OUT.flush()


def _handle_request(worker: Vol3ApiWorker, request: dict[str, Any]) -> dict[str, Any]:
    method = request.get("method")
    params = request.get("params") or {}
    if method == "health":
        return worker.bootstrap()
    if method == "list_plugins":
        return worker.list_plugins()
    if method == "describe_plugin":
        return worker.describe_plugin(str(params.get("plugin", "")))
    if method == "run_plugin":
        request_id = request.get("id")

        def progress(value: float, description: Optional[str] = None) -> None:
            _send(
                {
                    "id": request_id,
                    "type": "progress",
                    "progress": value,
                    "description": description,
                }
            )

        return worker.run_plugin(
            image_path=str(params["image_path"]),
            plugin_name=str(params["plugin"]),
            args=params.get("args"),
            params=params.get("plugin_params"),
            output_dir=params.get("output_dir"),
            progress=progress,
        )
    if method == "shutdown":
        return {"ok": True, "shutdown": True}
    raise WorkerError("unknown_method", f"Unknown Volatility3 worker method: {method}")


def main() -> None:
    parser = argparse.ArgumentParser(description="mem-forensics Volatility3 API worker")
    parser.add_argument("--source-kind", choices=("git", "pip"), required=True)
    parser.add_argument("--source-path")
    parsed = parser.parse_args()
    worker = Vol3ApiWorker(parsed.source_kind, parsed.source_path)

    # Protect protocol stdout from accidental prints made by plugins or their
    # dependencies. Explicit protocol writes retain the original stream.
    with contextlib.redirect_stdout(sys.stderr):
        for line in sys.stdin:
            try:
                request = json.loads(line)
                request_id = request.get("id")
                result = _handle_request(worker, request)
                _send({"id": request_id, "type": "result", "result": result})
                if request.get("method") == "shutdown":
                    return
            except WorkerError as exc:
                _send(
                    {
                        "id": request.get("id") if "request" in locals() else None,
                        "type": "error",
                        "error": {
                            "code": exc.code,
                            "message": str(exc),
                            "details": exc.details,
                        },
                    }
                )
            except Exception as exc:  # Defensive boundary around third-party plugins.
                logger.error("Unhandled Volatility3 worker failure: %s", traceback.format_exc())
                _send(
                    {
                        "id": request.get("id") if "request" in locals() else None,
                        "type": "error",
                        "error": {
                            "code": "internal_error",
                            "message": str(exc),
                            "details": [],
                        },
                    }
                )


if __name__ == "__main__":
    main()
