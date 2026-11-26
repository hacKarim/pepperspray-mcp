# PepperSpray — LangGraph Multi-Agent Rewrite (Design)

**Date:** 2026-11-25
**Status:** Awaiting approval
**Branch:** `feat/langgraph-multi-agent-rewrite`

## 1. Intent & why

PepperSpray today is an **MCP server**: a 17k-line Flask API (`pepperspray_server.py`,
157 routes) that shells out to ~150 pentest CLIs, fronted by a thin FastMCP layer
(`pepperspray_mcp.py`, 151 pass-through tools) that an *external* AI (Claude) drives
over a stdio→TCP→socat bridge. The "intelligence" classes are almost entirely
hardcoded dictionaries and `confidence += 0.2` keyword counters — not real logic.

We are rewriting it so the **system itself is agentic**: a LangGraph multi-agent
framework where a supervisor routes work to specialist agents that plan, call tools,
communicate through shared state, and run as composable chains — while still being
usable from Claude Code as an MCP server.

**Why:** a cleaner, genuinely-agentic architecture; real inter-agent orchestration
instead of canned dict lookups; a safe, declarative tool layer replacing
`subprocess.Popen(shell=True)` + f-string command building; and an extensible
framework rather than a monolith.

## 2. Decisions (locked with the user)

1. **Interface:** LangGraph is the brain. Expose it both as a **CLI**
   (`pepperspray run --target …`) and as an **MCP server** (so Claude Code can drive
   it). The old bridge/socat stack is retired; MCP uses FastMCP directly.
2. **LLM:** **Anthropic Claude by default**, behind a provider abstraction
   (`LLM_PROVIDER=anthropic|openai|ollama`). Live reasoning needs `ANTHROPIC_API_KEY`.
3. **Tool coverage:** **Full parity — all ~150 tools** ported into the new registry.
4. **Runnable target:** **Docker is the runtime.** The real system runs in the
   Kali-based image with binaries + an LLM key. (Pure-Python unit tests still run in
   CI without binaries — see §9.)
5. **Agent topology:** **Supervisor + specialist agents** (option A), with named
   chain subgraphs. Structured to grow into hierarchical teams later.

## 3. Goals / non-goals / anti-goals

**Goals**
- A real LangGraph `StateGraph`: supervisor + specialist ReAct agents, shared state,
  inter-agent messaging, conditional routing, parallel fan-out, checkpointing.
- A declarative, **safe** tool registry covering all ~150 tools (argv lists, no
  `shell=True`), grouped by family, with graceful degradation when a binary is absent.
- Preserve the genuinely-valuable logic: `CVEIntelligenceManager` (NVD + GitHub +
  CVSS) and CTF flag extraction/validation.
- Migrate the useful *domain data* (tool-effectiveness tables, attack patterns,
  per-tool parameter recipes, CTF category→tool maps) into config.
- CLI + MCP entrypoints; Docker image; pytest suite; CI with lint + tests.
- Authorized-use safety: explicit authorization gate + human-in-the-loop interrupt
  before exploitation-class actions.

**Non-goals**
- No lightweight "mock everything" distribution (user chose Docker-as-runtime).
- Not rebuilding the ~1,400 lines of custom process-pool/cache/perf infra — stdlib +
  LangGraph + `cachetools` replace it.
- No web UI.

**Anti-goals (failure even if it "works")**
- Re-importing the hardcoded `confidence += 0.2` pseudo-intelligence.
- Keeping `shell=True` + f-string command construction.
- A "multi-agent" system that is secretly one giant tool belt with no real routing.
- Tool specs that are registered but structurally broken (bad argv builders).

## 4. Constraints

- Python 3.11+ (keep 3.11/3.12/3.13 matrix).
- Kali-rolling base retains the heavy binaries (Metasploit, Ghidra, Volatility,
  hashcat, angr, cloud suites, plus the ~50 light Go/C CLIs).
- LangGraph + LangChain + `langchain-anthropic` added; `flask` dropped from the core
  runtime (MCP via FastMCP; optional FastAPI only if REST is wanted later).
- Live agent runs cost Anthropic tokens and require network.

## 5. Approaches considered (topology)

- **A — Supervisor + specialists (CHOSEN).** Supervisor agent routes to family
  specialists (Recon, Scanning, Web, Exploitation, Binary/CTF, Cloud, Forensics,
  CVE-Intel, Reporting), each a ReAct agent bound to its slice of tools. Agents share
  graph state + a message channel; chain subgraphs encode fixed workflows. Matches
  "multiple agents communicating + chains"; scales to 150 tools without one giant
  belt.
- **B — Single ReAct agent, flat 150-tool belt.** Rejected: not really multi-agent;
  150 tools on one agent wrecks planning quality.
- **C — Hierarchical teams (graph-of-graphs).** Deferred: more structure than needed
  now; A is built so C is a later refactor, not a rewrite.

## 6. Target architecture

```
pepperspray/
  config.py                 # pydantic-settings; env + .env
  llm/provider.py           # get_llm(role) -> chat model; Anthropic default, pluggable
  core/
    state.py                # AssessmentState (graph state, TypedDict + reducers)
    messages.py             # inter-agent message / handoff types
    executor.py             # SafeCommandExecutor: argv list, timeout, stream, no shell=True
    registry.py             # ToolSpec dataclass + ToolRegistry (+ graceful degradation)
    errors.py               # error classification + retry/recovery policy (clean)
    cache.py                # cachetools TTL wrapper
  tools/
    specs/<family>.py       # ~150 ToolSpec entries across the families
    cve_intel.py            # PRESERVED: NVD + GitHub + CVSS, as a tool node
    flag_tools.py           # PRESERVED: CTF flag extraction/validation regexes
  agents/
    base.py                 # make_specialist(tools, prompt) -> ReAct node
    supervisor.py           # router agent (structured output -> next | FINISH)
    recon.py scanning.py web.py exploitation.py binary.py cloud.py
    forensics.py cve.py reporting.py
  graph/
    build.py                # build_graph() -> compiled StateGraph + checkpointer
    chains.py               # named chain subgraphs (recon->scan->exploit->report)
    routing.py              # conditional edges + authorization/HITL gate
  data/                     # migrated domain dicts (effectiveness, patterns, recipes)
  interfaces/
    cli.py                  # `pepperspray run|chain|mcp|list-tools`
    mcp_server.py           # FastMCP: graph entrypoints + all ~150 tools
  reporting/report.py       # findings -> markdown/JSON report
tests/                      # pytest: registry, argv builders, state, routing, CVE, flags
legacy/                     # old server/mcp/bridge moved here (removed in a later release)
```

**Graph state (`AssessmentState`):** `target`, `authorized: bool`, `objective`,
`messages` (add_messages reducer), `plan`, `completed_steps`, `tool_results` (append
reducer), `findings` (append reducer), `next` (routing), `report`.

**Supervisor:** LLM with structured output picks the next specialist or `FINISH`
based on objective + findings so far. **Specialists:** `create_react_agent` bound to
their family tools; each writes findings/tool_results back to state and returns to the
supervisor. **Checkpointer:** `MemorySaver` (CLI) / `SqliteSaver` (persistent) enables
resume + **human-in-the-loop interrupt** before exploitation-class tools.

**Chains:** fixed linear subgraphs (e.g. `recon_chain`, `bugbounty_recon`) for
deterministic workflows that don't need LLM routing — exposed as CLI/MCP entrypoints.

**Tool layer:** `ToolSpec{ name, family, binary|None, build_argv(params)->list[str],
timeout, cacheable, requires[], executor_kind∈{shell,python,orchestrator,http} }`.
`SafeCommandExecutor` runs argv lists with timeout + streaming. Pure-Python tools
(JWT, HTTP framework, file ops, CVE intel, flag tools) run in-process. Missing binary
→ structured "degraded/unavailable" result, never a crash.

**MCP server:** FastMCP exposing (a) high-level entrypoints — `run_assessment`,
`run_chain`, per-agent runners — and (b) all ~150 individual tools (thin wrappers over
the registry) so Claude Code keeps the granular toolbelt.

## 7. What is preserved / migrated / discarded

- **Preserve as code:** `CVEIntelligenceManager` (real NVD/GitHub/CVSS), CTF flag
  regexes. Rewritten into clean tool modules, logic intact.
- **Migrate as data:** tool-effectiveness tables, attack patterns, per-tool parameter
  recipes, CTF category→tool maps, error→recovery mappings, tech-detection signatures.
- **Discard:** ProcessPool, AdvancedCache, EnhancedProcessManager, ResourceMonitor,
  PerformanceDashboard, ProcessManager, PythonEnvironmentManager, the
  `confidence += 0.2` scorers, the self-admitted stub `_detect_technologies`, the
  Flask API, the TCP/stdio/socat bridge stack.

## 8. Safety / authorized-use

Keep the authorized-use notice. Add: (1) an explicit `authorized` flag required before
any active tool runs (CLI `--i-am-authorized`, MCP arg), and (2) a LangGraph
**interrupt** before exploitation-class tools (metasploit, sqlmap exploit, hydra,
msfvenom, payload delivery) so a human approves. This is defensive and keeps the
project within authorized-testing scope.

## 9. Testing & CI

- **Unit tests (run in CI, no binaries):** registry loads all specs; every spec's
  `build_argv` produces correct argv for representative params (covers all ~150);
  state reducers; supervisor routing with a stub LLM; CVE parsing with mocked HTTP;
  flag extraction/validation; executor timeout/argv behavior with a trivial command.
- **Integration (Docker):** graph end-to-end against a bundled vulnerable target,
  real binaries, real/offline LLM — run in the image, not required for CI green.
- **CI:** add ruff + black (already configured but unenforced) + pytest to the
  workflow, keep the 3.11/3.12/3.13 matrix.

"Runnable, no bugs" bar: the graph + agents + registry + CLI + MCP run end-to-end;
every tool spec is registered and unit-tested for correct argv; tools whose binary is
present execute for real; nothing crashes on a missing binary.

## 10. Build approach (for the plan)

- Scaffold package, config, LLM provider, state, executor, registry, cache, errors.
- Port the ~150 tool specs **by family, in parallel** (mined from the existing MCP arg
  signatures + Flask command builders) with per-spec argv unit tests.
- Preserve CVE-intel + flag tools.
- Build specialists + supervisor + graph + chains + routing/HITL gate.
- CLI + MCP server; reporting.
- Dockerfile/compose rewrite; CI (lint+tests); README/docs.
- Move old files to `legacy/`. Open PR.

## 11. Open calls made by the builder (my defaults, overridable)

- Old monolith moved to `legacy/` (not deleted) for one release, then removed.
- `langchain-anthropic` as the default LLM binding; `langgraph` checkpointer =
  `MemorySaver` for CLI, `SqliteSaver` when a persistence path is set.
- MCP exposes both high-level graph entrypoints and all 150 individual tools.
- A small bundled vulnerable target (e.g. OWASP Juice Shop container) is referenced in
  compose for integration runs, not shipped inside the main image.
