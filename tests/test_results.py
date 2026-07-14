import pytest

from mem_forensics_mcp_server.core.results import ResultStore


def test_result_store_paginates_without_losing_rows(tmp_path) -> None:
    store = ResultStore(tmp_path, ttl_seconds=60)
    source = {"ok": True, "engine": "test", "results": [{"id": value} for value in range(7)]}

    prepared = store.prepare(source, page_size=3)
    assert [row["id"] for row in prepared.data["results"]] == [0, 1, 2]
    assert prepared.data["page"]["total"] == 7
    cursor = prepared.data["page"]["next_cursor"]

    second = store.get_page(cursor, 3)
    assert [row["id"] for row in second["results"]] == [3, 4, 5]
    third = store.get_page(second["page"]["next_cursor"], 3)
    assert [row["id"] for row in third["results"]] == [6]
    assert third["page"]["complete"]


def test_result_store_keeps_small_results_inline(tmp_path) -> None:
    store = ResultStore(tmp_path)
    prepared = store.prepare({"ok": True, "results": [{"id": 1}]}, page_size=10)
    assert prepared.data == {"ok": True, "results": [{"id": 1}]}


def test_result_store_registers_and_reads_managed_artifacts(tmp_path) -> None:
    store = ResultStore(tmp_path, ttl_seconds=60)
    artifact_path = tmp_path / "dump.bin"
    artifact_path.write_bytes(b"memory artifact")

    artifact = store.register_artifact(artifact_path)
    uri = store.artifact_uri(artifact.token)
    payload, mime_type = store.read_artifact(uri)

    assert payload == b"memory artifact"
    assert mime_type == "application/octet-stream"
    assert store.release(uri)
    assert not artifact_path.exists()


def test_result_store_refuses_unmanaged_artifacts(tmp_path) -> None:
    store = ResultStore(tmp_path / "results", ttl_seconds=60)
    unmanaged = tmp_path / "unmanaged.bin"
    unmanaged.write_bytes(b"not server owned")

    with pytest.raises(ValueError, match="outside server-managed"):
        store.register_artifact(unmanaged)
