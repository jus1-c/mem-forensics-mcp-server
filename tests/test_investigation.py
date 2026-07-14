from mem_forensics_mcp_server.core.investigation import (
    build_timeline,
    diff_rows,
    extract_iocs,
    response_playbook,
)


def test_timeline_only_emits_parseable_timestamp_fields() -> None:
    result = build_timeline(
        {
            "processes": {
                "results": [
                    {"PID": 4, "CreateTime": "2025-01-02T03:04:05Z", "Name": "System"},
                    {"PID": 8, "Name": "no timestamp"},
                ]
            }
        }
    )

    assert result["event_count"] == 1
    assert result["events"][0]["timestamp"] == "2025-01-02T03:04:05Z"
    assert result["events"][0]["source"] == "processes"


def test_ioc_extraction_omits_secret_fields() -> None:
    result = extract_iocs(
        {
            "network": {
                "results": [
                    {
                        "RemoteAddr": "203.0.113.5",
                        "RemotePort": 443,
                        "Password": "not-an-ioc",
                        "CommandLine": "curl https://example.test/path",
                    }
                ]
            }
        }
    )

    types = {(item["type"], item["value"]) for item in result["iocs"]}
    assert ("ip", "203.0.113.5") in types
    assert ("port", "443") in types
    assert ("url", "https://example.test/path") in types
    assert all("not-an-ioc" not in item["value"] for item in result["iocs"])


def test_diff_uses_forensic_identity_fields() -> None:
    result = diff_rows(
        {"results": [{"PID": 10, "Name": "before.exe"}, {"PID": 20, "Name": "gone.exe"}]},
        {"results": [{"PID": 10, "Name": "after.exe"}, {"PID": 30, "Name": "new.exe"}]},
        identity_fields=("pid",),
    )

    assert result["added_count"] == 1
    assert result["removed_count"] == 1
    assert result["changed_count"] == 1
    assert result["changed"][0]["before"]["Name"] == "before.exe"
    assert result["changed"][0]["after"]["Name"] == "after.exe"


def test_playbook_requires_validation_for_incomplete_triage() -> None:
    result = response_playbook(
        {
            "threat_level": "inconclusive",
            "analysis_complete": False,
            "partial_failures": [{"component": "netscan", "reason": "missing symbols"}],
            "iocs": [{"type": "ip", "value": "203.0.113.5"}],
        }
    )

    assert not result["analysis_complete"]
    assert any(step["phase"] == "validate" for step in result["steps"])
