from mem_forensics_mcp_server.config import bundled_memoxide_binary, get_memoxide_symbols_root


def test_symbols_root_uses_dotenv_when_environment_is_unset(tmp_path) -> None:
    dotenv_path = tmp_path / ".env"
    dotenv_path.write_text("MEMOXIDE_SYMBOLS_ROOT=custom-symbols\n", encoding="utf-8")

    resolved = get_memoxide_symbols_root(environment={}, dotenv_path=dotenv_path)

    assert resolved == (tmp_path / "custom-symbols").resolve()


def test_symbols_root_environment_overrides_dotenv(tmp_path) -> None:
    dotenv_path = tmp_path / ".env"
    dotenv_path.write_text("MEMOXIDE_SYMBOLS_ROOT=dotenv-symbols\n", encoding="utf-8")
    override = tmp_path / "environment-symbols"

    resolved = get_memoxide_symbols_root(
        environment={"MEMOXIDE_SYMBOLS_ROOT": str(override)}, dotenv_path=dotenv_path
    )

    assert resolved == override.resolve()


def test_native_binary_selection_does_not_use_linux_bundle_on_macos() -> None:
    assert bundled_memoxide_binary("linux", "x86_64").name == "memoxide"
    assert bundled_memoxide_binary("windows", "x86_64").name == "memoxide.exe"
    assert bundled_memoxide_binary("macos", "aarch64").name == "memoxide.macos"
    assert bundled_memoxide_binary("darwin", "x86_64").name == "memoxide.macos"
    assert bundled_memoxide_binary("windows", "aarch64") is None
