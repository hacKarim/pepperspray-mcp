import operator

from langgraph.graph.message import add_messages  # noqa: F401 ensure dep

from pepperspray.core.state import AssessmentState, new_state


def test_new_state_defaults():
    s = new_state(target="example.com", objective="recon", authorized=True)
    assert s["target"] == "example.com"
    assert s["authorized"] is True
    assert s["findings"] == [] and s["tool_results"] == []
    assert s["step_budget"] >= 1


def test_findings_reducer_appends():
    # the annotated reducer for findings/tool_results must be operator.add (append)
    ann = AssessmentState.__annotations__["findings"]
    # Annotated[list, operator.add] -> metadata contains operator.add
    assert operator.add in getattr(ann, "__metadata__", ())
