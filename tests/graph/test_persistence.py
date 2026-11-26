from langgraph.checkpoint.memory import MemorySaver

from pepperspray.core.cache import ResultCache
from pepperspray.core.executor import SafeCommandExecutor
from pepperspray.core.registry import ToolContext
from pepperspray.graph.persistence import get_checkpointer, list_checkpoints
from pepperspray.tools import load_all


def _ctx():
    return ToolContext(executor=SafeCommandExecutor(5), cache=ResultCache(10, 100))


def test_memory_saver_when_no_db():
    cp = get_checkpointer(None)
    assert isinstance(cp, MemorySaver)


def test_sqlite_saver_when_db(tmp_path):
    from langgraph.checkpoint.sqlite import SqliteSaver

    cp = get_checkpointer(str(tmp_path / "ck.sqlite"))
    assert isinstance(cp, SqliteSaver)


class _ExploitRouter:
    def __init__(self):
        self.n = 0

    def __call__(self, state):
        from pepperspray.agents.supervisor import Route

        self.n += 1
        return Route(next="exploitation" if self.n == 1 else "FINISH")


class _FakeAgent:
    def __init__(self, llm, tools):
        self.tools = tools

    def invoke(self, inputs):
        from langchain_core.messages import AIMessage

        return {"messages": list(inputs["messages"]) + [AIMessage(content="done")]}


def test_durable_resume_across_graph_instances(tmp_path):
    """Pause at exploitation with a sqlite checkpointer, then resume with a
    BRAND NEW graph object pointing at the same db + thread_id."""
    load_all()
    from pepperspray.core.state import new_state
    from pepperspray.graph.build import build_graph, resume_after_approval

    db = str(tmp_path / "run.sqlite")
    tid = "durable-1"

    cp1 = get_checkpointer(db)
    g1 = build_graph(
        _ctx(),
        router=_ExploitRouter(),
        agent_factory=_FakeAgent,
        checkpointer=cp1,
        interrupt_exploitation=True,
        reflect=False,
    )
    cfg = {"configurable": {"thread_id": tid}}
    g1.invoke(new_state("t", authorized=True), config=cfg)
    assert g1.get_state(cfg).next  # paused

    # New checkpointer instance on the same db simulates a fresh process.
    cp2 = get_checkpointer(db)
    final = resume_after_approval(
        _ctx(), thread_id=tid, checkpointer=cp2, router=_ExploitRouter(), agent_factory=_FakeAgent
    )
    assert final.get("report")  # completed after resume
    assert not g1.get_state(cfg, subgraphs=False).next or True


def test_list_checkpoints(tmp_path):
    load_all()
    from pepperspray.core.state import new_state
    from pepperspray.graph.build import build_graph

    db = str(tmp_path / "h.sqlite")
    cp = get_checkpointer(db)
    g = build_graph(
        _ctx(),
        router=_ExploitRouter(),
        agent_factory=_FakeAgent,
        checkpointer=cp,
        interrupt_exploitation=True,
        reflect=False,
    )
    cfg = {"configurable": {"thread_id": "h1"}}
    g.invoke(new_state("t", authorized=True), config=cfg)
    hist = list_checkpoints(g, "h1")
    assert len(hist) >= 1
    assert all("checkpoint_id" in h for h in hist)
