"""Node-level resilience: retry on transient failure, per-run node caching,
and the exploitation gate self-routing via Command(goto)."""

from langchain_core.messages import AIMessage
from langgraph.types import RetryPolicy

from pepperspray.agents.supervisor import Route
from pepperspray.core.cache import ResultCache
from pepperspray.core.errors import AuthorizationError
from pepperspray.core.executor import SafeCommandExecutor
from pepperspray.core.registry import ToolContext
from pepperspray.graph.build import build_graph, run_assessment
from pepperspray.graph.resilience import (
    DEFAULT_RETRY,
    should_retry,
    specialist_cache_policy,
)
from pepperspray.tools import load_all


def _ctx():
    return ToolContext(executor=SafeCommandExecutor(5), cache=ResultCache(10, 100))


class _SeqRouter:
    def __init__(self):
        self.calls = 0

    def __call__(self, state):
        self.calls += 1
        return Route(next="recon" if self.calls == 1 else "FINISH")


def test_should_retry_excludes_auth_errors():
    assert should_retry(RuntimeError("transient")) is True
    assert should_retry(TimeoutError()) is True
    assert should_retry(AuthorizationError("not authorized")) is False


def test_default_retry_recovers_flaky_specialist():
    load_all()

    class _FlakyAgent:
        tries = {"n": 0}

        def __init__(self, llm, tools):
            self.tools = tools

        def invoke(self, inputs):
            _FlakyAgent.tries["n"] += 1
            if _FlakyAgent.tries["n"] < 3:
                raise RuntimeError("transient boom")
            return {"messages": list(inputs["messages"]) + [AIMessage(content="done")]}

    fast = RetryPolicy(
        max_attempts=3, initial_interval=0.001, backoff_factor=1.0, retry_on=should_retry
    )
    final = run_assessment(
        "example.com",
        objective="recon",
        authorized=True,
        ctx=_ctx(),
        router=_SeqRouter(),
        agent_factory=_FlakyAgent,
        interrupt_exploitation=False,
        reflect=False,
        retry_policy=fast,
        thread_id="retry-1",
    )
    assert _FlakyAgent.tries["n"] >= 3  # it actually retried
    assert "recon" in final.get("completed_steps", [])
    assert final.get("report")


def test_specialist_cache_policy_key_depends_on_target():
    pol = specialist_cache_policy("recon", ttl=60)
    k1 = pol.key_func({"target": "a.com", "objective": "o", "authorized": True})
    k2 = pol.key_func({"target": "a.com", "objective": "o", "authorized": True})
    k3 = pol.key_func({"target": "b.com", "objective": "o", "authorized": True})
    assert k1 == k2  # stable for the same target/objective
    assert k1 != k3  # different target -> different cache slot
    assert pol.ttl == 60


def test_default_retry_is_a_retry_policy():
    assert isinstance(DEFAULT_RETRY, RetryPolicy)
    assert DEFAULT_RETRY.max_attempts >= 2


def test_gate_self_routes_via_command_goto():
    load_all()
    g = build_graph(
        _ctx(),
        router=_SeqRouter(),
        agent_factory=lambda llm, tools: None,
        interrupt_exploitation=True,
        reflect=False,
    )
    edges = {(e.source, e.target) for e in g.get_graph().edges}
    assert ("exploitation_gate", "exploitation") in edges
    assert ("exploitation_gate", "supervisor") in edges
