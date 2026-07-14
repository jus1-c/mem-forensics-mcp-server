import asyncio

import pytest

from mem_forensics_mcp_server.core.yara_scan import YaraScanError, scan_yara


def test_yara_scan_returns_match_offsets(tmp_path) -> None:
    image = tmp_path / "memory.raw"
    image.write_bytes(b"prefix MALWARE suffix MALWARE")
    result = asyncio.run(
        scan_yara(
            image,
            'rule marker { strings: $marker = "MALWARE" condition: $marker }',
            timeout_seconds=10,
        )
    )
    assert result["match_count"] == 1
    instances = result["results"][0]["strings"][0]["instances"]
    assert [instance["offset"] for instance in instances] == [7, 22]


def test_yara_scan_rejects_includes(tmp_path) -> None:
    image = tmp_path / "memory.raw"
    image.write_bytes(b"data")
    with pytest.raises(YaraScanError, match="include"):
        asyncio.run(scan_yara(image, 'include "host-file.yar"'))
