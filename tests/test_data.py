from pepperspray.data import TOOL_EFFECTIVENESS, tools_for_target


def test_tools_for_target_ranked():
    ranked = tools_for_target("web_application")
    assert ranked[0] in {"nuclei", "wpscan"}  # highest effectiveness
    assert "nmap" in ranked


def test_unknown_target_empty():
    assert tools_for_target("nope") == []
    assert "network_host" in TOOL_EFFECTIVENESS
