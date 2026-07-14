from pathlib import Path

from mem_forensics_mcp_server.core.settings import Volatility3Settings
from mem_forensics_mcp_server.core.vol3_provider import Volatility3Provider


def make_settings(tmp_path: Path, *, pip_fallback: bool = False) -> Volatility3Settings:
    return Volatility3Settings(
        repo_url="https://github.com/volatilityfoundation/volatility3",
        branch="stable",
        repo_path=tmp_path / "managed",
        auto_update=False,
        update_interval_seconds=1,
        update_mode="never",
        fetch_timeout_seconds=1,
        clone_timeout_seconds=1,
        pip_fallback=pip_fallback,
        keep_good_revisions=2,
        local_repos=(),
        allowed_origins=("https://github.com/volatilityfoundation/volatility3",),
        worktrees_root=tmp_path / "worktrees",
        env_path=tmp_path / ".env",
    )


def test_provider_uses_none_when_no_git_or_pip_fallback(tmp_path: Path) -> None:
    provider = Volatility3Provider(make_settings(tmp_path))
    assert provider.select_initial_source().kind == "none"


def test_provider_status_does_not_attempt_network(tmp_path: Path) -> None:
    provider = Volatility3Provider(make_settings(tmp_path))
    status = provider.status()
    assert status["update_attempted"] is False
    assert status["selected_source"] == "none"


def test_prune_keeps_active_worktree_paths(tmp_path: Path, monkeypatch) -> None:
    settings = make_settings(tmp_path)
    settings.worktrees_root.mkdir()
    active = settings.worktrees_root / "active"
    stale = settings.worktrees_root / "stale"
    active.mkdir()
    stale.mkdir()
    removed: list[Path] = []
    provider = Volatility3Provider(settings)

    def fake_git(args, *, cwd=None, timeout):
        removed.append(Path(args[-1]))
        return ""

    monkeypatch.setattr(provider, "_run_git", fake_git)
    provider.prune_worktrees((active,))

    assert active not in removed
