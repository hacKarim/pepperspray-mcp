# PepperSpray LangGraph Multi-Agent Rewrite — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the Flask-API-plus-thin-MCP monolith with a LangGraph multi-agent framework (supervisor + specialist agents, shared state, chains) that ports all ~150 tools into a safe declarative registry and is usable from both a CLI and an MCP server.

**Architecture:** A `pepperspray/` package. A LangGraph `StateGraph` runs a supervisor agent that routes to specialist ReAct agents (recon, scanning, web, exploitation, binary, cloud, forensics, cve, reporting), each bound to its family's tools. Tools are `ToolSpec` entries executed via a single `SafeCommandExecutor` (argv lists, no `shell=True`). Entrypoints: a Typer CLI and a FastMCP server exposing both high-level graph runs and all individual tools.

**Tech Stack:** Python 3.11+, `langgraph`, `langchain-core`, `langchain-anthropic` (+ optional `langchain-openai`, `langchain-ollama`), `mcp`/`fastmcp`, `pydantic`/`pydantic-settings`, `typer`, `httpx`, `cachetools`, `pytest`, `ruff`, `black`.

**Spec:** `docs/superpowers/specs/2026-11-25-langgraph-multi-agent-rewrite-design.md`

## Global Constraints

- Python 3.11+; keep CI matrix 3.11 / 3.12 / 3.13.
- No `subprocess` call anywhere uses `shell=True`; every external tool runs as an argv `list[str]`.
- No module re-introduces `confidence += <float>` keyword-counter "scoring".
- Every active (network-touching / exploitation) tool run requires `state.authorized is True`; exploitation-family tools additionally require a human-in-the-loop interrupt.
- Package import name: `pepperspray`. Line length 100 (ruff/black already configured in `pyproject.toml`).
- Unit tests must pass with **no external binaries and no `ANTHROPIC_API_KEY`** (mock the LLM and the HTTP/subprocess boundary). Live/integration runs are Docker-only.
- Missing binary or missing API key must yield a structured result/error, never an uncaught exception.

## Review Focus

- **Argv injection via tool params** (e.g. a target like `localhost; rm -rf /`): argv-list construction must pass it as a single argument, never a shell token — pinned in Task 3 and each family task's builder tests.
- **Unauthorized active scan** (`authorized=False`): the graph/registry must refuse to execute active tools — pinned in Task 10 (gate) tests.
- **Missing binary at call time** (tool's `binary` not on `PATH`): returns `status="unavailable"`, not a crash — pinned in Task 2 and Task 3 tests.
- **Unknown LLM provider / missing key**: `get_llm` raises a clear configuration error, not an opaque import error — pinned in Task 1 tests.
- **Supervisor routing to a nonexistent / repeated agent** (loop / invalid `next`): routing clamps to known agents and a max-step budget, ending at `FINISH` — pinned in Task 10 tests.

---

## Task 0: Package scaffold, dependencies, config

**Files:**
- Create: `pepperspray/__init__.py`, `pepperspray/config.py`
- Modify: `pyproject.toml` (add `[project]` + deps + `pytest`/`ruff`/`black` config), create `requirements.txt` (core), keep `requirements-docker.txt` updated
- Test: `tests/test_config.py`

**Interfaces:**
- Produces: `pepperspray.config.Settings` (pydantic-settings) with fields: `llm_provider: str = "anthropic"`, `model: str = "claude-opus-4-8"` (override via `PEPPERSPRAY_MODEL`), `anthropic_api_key: str | None`, `command_timeout: int = 300`, `cache_ttl: int = 3600`, `cache_size: int = 1000`, `results_dir: Path = Path("results")`, `checkpoint_db: str | None = None`. `get_settings() -> Settings` (cached).

- [ ] **Step 1: Write failing test** — `tests/test_config.py::test_settings_defaults_and_env_override` asserts `get_settings().llm_provider == "anthropic"` and that setting env `PEPPERSPRAY_MODEL=foo` makes `model == "foo"`.
- [ ] **Step 2: Run** `pytest tests/test_config.py -v` → FAIL (module missing).
- [ ] **Step 3:** Convert `pyproject.toml` to a real packaging file: add `[project]` (name `pepperspray`, deps above, `requires-python = ">=3.11"`), `[project.scripts] pepperspray = "pepperspray.interfaces.cli:app"`, `[tool.pytest.ini_options]`. Implement `Settings`/`get_settings` in `pepperspray/config.py` using `pydantic_settings.BaseSettings` with env prefix `PEPPERSPRAY_` and `.env` support.
- [ ] **Step 4: Run** `pytest tests/test_config.py -v` → PASS.
- [ ] **Step 5: Commit** `feat: package scaffold, settings, dependency manifest`.

---

## Task 1: LLM provider abstraction

**Files:**
- Create: `pepperspray/llm/__init__.py`, `pepperspray/llm/provider.py`
- Test: `tests/test_llm_provider.py`

**Interfaces:**
- Produces: `get_llm(role: str = "default", **overrides) -> BaseChatModel`. Reads `Settings`. `provider=="anthropic"` → `ChatAnthropic(model=..., temperature=0)`; `"openai"` → `ChatOpenAI`; `"ollama"` → `ChatOllama`. Unknown provider → `ConfigurationError`. Missing required key for anthropic/openai → `ConfigurationError` with a clear message. `ConfigurationError(Exception)` exported from `pepperspray/llm/provider.py`.

- [ ] **Step 1: Write failing tests** — `test_unknown_provider_raises` (monkeypatch settings `llm_provider="bogus"` → `pytest.raises(ConfigurationError)`); `test_anthropic_missing_key_raises` (provider anthropic, no key → `ConfigurationError`); `test_returns_chat_model` (monkeypatch `ChatAnthropic` with a stub, assert instance returned).
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3:** Implement `provider.py`. Import the langchain bindings lazily inside each branch so a missing optional binding becomes a `ConfigurationError`, not an ImportError at module load.
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(llm): pluggable chat-model provider (anthropic default)`.

---

## Task 2: SafeCommandExecutor

**Files:**
- Create: `pepperspray/core/__init__.py`, `pepperspray/core/executor.py`
- Test: `tests/core/test_executor.py`

**Interfaces:**
- Produces: `@dataclass ToolResult{ tool: str, status: Literal["success","failed","timeout","unavailable"], returncode: int|None, stdout: str, stderr: str, duration: float, argv: list[str], error: str|None }`.
- Produces: `class SafeCommandExecutor: __init__(self, default_timeout: int)`; `run(self, tool: str, argv: list[str], timeout: int|None=None, input_text: str|None=None) -> ToolResult`. Uses `subprocess.Popen(argv, shell=False, stdout=PIPE, stderr=PIPE, text=True)`, enforces timeout (terminate→kill), `shutil.which(argv[0])` check first → `status="unavailable"` when absent. Never raises for process errors; returns a `ToolResult`.

- [ ] **Step 1: Write failing tests** — `test_runs_echo` (argv `["echo","hi"]` → status success, stdout contains "hi"); `test_missing_binary` (argv `["definitely_not_a_binary_xyz"]` → status "unavailable", no exception); `test_timeout` (argv `["sleep","5"]`, timeout=1 → status "timeout"); `test_argv_is_not_shell` (argv `["echo","a; whoami"]` → stdout contains literal `a; whoami`, proving no shell).
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3:** Implement `executor.py`.
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(core): safe argv command executor`.

---

## Task 3: ToolSpec, ToolRegistry, cache, errors

**Files:**
- Create: `pepperspray/core/registry.py`, `pepperspray/core/cache.py`, `pepperspray/core/errors.py`
- Test: `tests/core/test_registry.py`, `tests/core/test_cache.py`

**Interfaces:**
- Produces (`registry.py`):
  - `@dataclass ToolSpec{ name: str, family: str, executor_kind: Literal["shell","python","orchestrator","http"], binary: str|None, build_argv: Callable[[dict], list[str]]|None, run: Callable[[dict, "ToolContext"], ToolResult]|None, timeout: int|None, cacheable: bool, active: bool, exploitation: bool, description: str }`.
  - `class ToolContext{ executor: SafeCommandExecutor, cache, settings }`.
  - `class ToolRegistry: register(spec)`, `get(name) -> ToolSpec`, `all() -> list[ToolSpec]`, `by_family(family) -> list[ToolSpec]`, `execute(name: str, params: dict, ctx: ToolContext, authorized: bool) -> ToolResult`. `execute` raises `AuthorizationError` when `spec.active and not authorized`; for `shell` kind builds argv via `build_argv(params)` then `ctx.executor.run(...)`; for `python`/`orchestrator`/`http` calls `spec.run(params, ctx)`; applies cache when `spec.cacheable`.
  - Module-level singleton `REGISTRY = ToolRegistry()` and decorator `@tool(...)` that builds a `ToolSpec` from a function and registers it.
- Produces (`errors.py`): `AuthorizationError`, `ToolExecutionError`, and `classify_error(stderr: str, returncode: int) -> str` (returns a category label from a small mapping — migrate the useful error→category pairs from `pepperspray_server.py` `IntelligentErrorHandler._initialize_error_patterns`).
- Produces (`cache.py`): `class ResultCache` wrapping `cachetools.TTLCache`; `key(name, params)` = sha256 of canonical json; `get`/`set`.

- [ ] **Step 1: Write failing tests** — `test_register_and_get`; `test_execute_shell_builds_argv` (register a spec whose `build_argv` returns `["echo", params["x"]]`, execute → ToolResult success); `test_execute_active_unauthorized_raises` (`active=True`, `authorized=False` → `AuthorizationError`); `test_argv_injection_is_arg` (param `"a; id"` stays one argv element); `test_cache_hit` (second identical cacheable execute does not re-run — assert via a counter).
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3:** Implement the three modules.
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(core): tool registry, spec model, cache, error classification`.

---

## Task 4: CVE intelligence tool (preserved logic)

**Files:**
- Create: `pepperspray/tools/__init__.py`, `pepperspray/tools/cve_intel.py`
- Test: `tests/tools/test_cve_intel.py`
- Source to port: `pepperspray_server.py` `CVEIntelligenceManager` (`fetch_latest_cves`, `analyze_cve_exploitability`, `search_existing_exploits`).

**Interfaces:**
- Produces: `fetch_latest_cves(days: int, severity: str|None) -> list[dict]` (NVD REST v2), `analyze_cve_exploitability(cve_id: str) -> dict` (CVSS-component heuristic preserved verbatim in weights), `search_existing_exploits(cve_id: str) -> list[dict]` (GitHub search). All HTTP via `httpx`. Registered as `python` ToolSpecs `cve_monitor`, `cve_exploitability`, `cve_exploit_search` (family `cve`, `active=False`).

- [ ] **Step 1: Write failing tests** — mock `httpx` responses with a saved NVD JSON fixture; `test_parse_cvss_v31` (severity + score extracted); `test_exploitability_network_lowcomplexity_scores_high` (asserts the preserved weight math: NETWORK +0.4, LOW complexity +0.3, etc.); `test_exploit_search_filters_mentions`.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3:** Port the logic; replace `requests` with `httpx`; keep CVSS weights and NVD/GitHub field handling identical.
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(tools): preserve CVE intelligence (NVD + GitHub + CVSS)`.

---

## Task 5: CTF flag tools (preserved regexes)

**Files:**
- Create: `pepperspray/tools/flag_tools.py`
- Test: `tests/tools/test_flag_tools.py`
- Source: `pepperspray_server.py` `CTFChallengeAutomator._extract_flag_candidates` / `_validate_flag_format`.

**Interfaces:**
- Produces: `extract_flags(text: str, fmt: str|None=None) -> list[str]`, `validate_flag(flag: str, fmt: str|None=None) -> bool`. Registered as `python` ToolSpecs `flag_extract`, `flag_validate` (family `binary`, `active=False`).

- [ ] **Step 1: Write failing tests** — `test_extract_default_flagbrace` (`flag{abc_123}` found), `test_extract_hash_patterns`, `test_validate_rejects_garbage`.
- [ ] **Step 2: Run** → FAIL.  **Step 3:** Port regexes verbatim.  **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(tools): preserve CTF flag extraction/validation`.

---

## Tasks 6–9: Port the 98 CLI tool specs, by family

Each task creates `pepperspray/tools/specs/<file>.py`, registering `ToolSpec`s (`executor_kind="shell"`) for the listed tools. **For every tool, port its command construction from the matching `pepperspray_server.py` Flask handler** (endpoint `api/tools/<name>`), converting the f-string command into a `build_argv(params) -> list[str]`. Carry over each tool's current default args/flags as spec defaults. Mark `active=True` for all network/host-touching tools; `exploitation=True` for the exploitation set. Each task's test file asserts **argv correctness for every tool it adds** (one `build_argv` test per tool with representative params, including one param containing `"; id"` to prove it stays a single argv element) and that `REGISTRY.by_family(...)` returns the expected count.

- [ ] **Task 6 — Recon / scanning / discovery specs** (`specs/recon.py`): nmap, nmap-advanced, rustscan, masscan, autorecon, amass, subfinder, fierce, dnsenum, wafw00f, enum4linux, enum4linux-ng, rpcclient, nbtscan, arp-scan, smbmap, netexec, responder, gau, waybackurls, hakrawler, katana. (TDD steps 1–5 as above; commit `feat(tools): recon/discovery tool specs`.)
- [ ] **Task 7 — Web / fuzzing / param / vuln specs** (`specs/web.py`): gobuster, dirb, ffuf, feroxbuster, dirsearch, wfuzz, dotdotpwn, xsser, dalfox, httpx, nikto, nuclei, wpscan, jaeles, arjun, paramspider, x8, anew, qsreplace, uro, burpsuite, zap, burpsuite-alternative. Commit `feat(tools): web/fuzzing/vuln tool specs`.
- [ ] **Task 8 — Exploitation / cracking / binary specs** (`specs/offense.py`): sqlmap, metasploit (temp `.rc` file pattern), msfvenom, hydra, pacu, john, hashcat, hashpump, gdb, gdb-peda, radare2, ghidra, binwalk, ropgadget, ropper, checksec, xxd, strings, objdump, pwntools, one-gadget, libc-database, angr, pwninit. All `active=True`; exploitation set (`sqlmap, metasploit, msfvenom, hydra, pacu`) `exploitation=True`. Commit `feat(tools): exploitation/cracking/binary tool specs`.
- [ ] **Task 9 — Cloud / container / forensics specs** (`specs/cloud_forensics.py`): prowler, scout-suite, cloudmapper, kube-hunter, kube-bench, docker-bench-security, clair, falco, checkov, terrascan, trivy, volatility, volatility3, foremost, steghide, exiftool. Commit `feat(tools): cloud/container/forensics tool specs`.

---

## Task 10: Python/HTTP/orchestrator + system tool specs (the 53 non-CLI tools)

**Files:**
- Create: `pepperspray/tools/specs/http_framework.py`, `pepperspray/tools/specs/python_tools.py`, `pepperspray/tools/specs/system.py`
- Test: `tests/tools/test_python_http_system.py`
- Source: the `api/files`, `api/python`, `api/visual`, `api/processes`, `api/cache`, `api/telemetry`, `http-framework`, `api_fuzzer`, `graphql_scanner`, `jwt_analyzer`, `api_schema_analyzer` handlers.

**Interfaces:**
- `python` specs: `jwt_analyzer`, `generate_payload`, `create_file`/`modify_file`/`delete_file`/`list_files` (sandboxed to `results_dir`), `install_python_package`, `execute_python_script`.
- `http` specs: `http_framework_test`, `http_repeater`, `http_intruder`, `http_set_rules`, `http_set_scope`, `api_fuzzer`, `graphql_scanner`, `api_schema_analyzer` (use `httpx`; `api_fuzzer`/`graphql_scanner` keep their `ffuf`/`curl` shell-out but via argv).
- `system` specs (operate on `ToolContext`, not network): `server_health`, `get_cache_stats`, `clear_cache`, `get_telemetry`, process list/status/dashboard (reimplemented over stdlib/`psutil`; drop pause/resume/terminate of arbitrary PIDs unless trivially safe).

- [ ] **Step 1: Write failing tests** — `test_jwt_decode` (decodes a known unsigned JWT), `test_file_ops_sandboxed` (write outside `results_dir` rejected), `test_http_repeater_builds_request` (with mocked `httpx`), `test_system_health_shape`.
- [ ] **Step 2: Run** → FAIL. **Step 3:** Implement. **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(tools): python/http/system tool specs`.

---

## Task 11: Graph state + inter-agent messages

**Files:**
- Create: `pepperspray/core/state.py`, `pepperspray/core/messages.py`
- Test: `tests/core/test_state.py`

**Interfaces:**
- Produces: `AssessmentState(TypedDict)` with `target: str`, `authorized: bool`, `objective: str`, `messages: Annotated[list, add_messages]`, `plan: list[str]`, `completed_steps: Annotated[list[str], operator.add]`, `tool_results: Annotated[list[dict], operator.add]`, `findings: Annotated[list[dict], operator.add]`, `next: str`, `step_budget: int`, `report: str | None`.
- `messages.py`: `Handoff{ to: str, reason: str }`, helper `record_finding(...)`.

- [ ] **Step 1: Write failing test** — `test_reducers_append` (merging two partial states appends `findings`/`tool_results` rather than replacing).
- [ ] **Step 2: Run** → FAIL. **Step 3:** Implement. **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(core): assessment graph state + reducers`.

---

## Task 12: Specialist agent factory + the nine specialists

**Files:**
- Create: `pepperspray/agents/__init__.py`, `pepperspray/agents/base.py`, `pepperspray/agents/{recon,scanning,web,exploitation,binary,cloud,forensics,cve,reporting}.py`
- Test: `tests/agents/test_specialists.py`

**Interfaces:**
- Produces: `make_specialist(name: str, families: list[str], system_prompt: str, ctx: ToolContext) -> Callable[[AssessmentState], dict]`. Builds LangChain tools from `REGISTRY.by_family(...)` (wrapping `REGISTRY.execute`, passing `authorized` from state), creates a ReAct agent via `langgraph.prebuilt.create_react_agent(get_llm(name), tools)`, and returns a node function that runs the agent on the state slice, appends `tool_results`/`findings`, and returns `{"next": "supervisor", ...}`.
- Each specialist module exposes `build(ctx) -> node` with its family list + prompt (prompts seeded from the migrated effectiveness/attack-pattern data in `pepperspray/data/`).

- [ ] **Step 1: Write failing test** — `test_specialist_node_runs_with_stub_llm`: monkeypatch `create_react_agent` to return a fake that calls one registry tool; assert the node appends a `tool_results` entry and sets `next="supervisor"`. `test_unauthorized_specialist_records_refusal`.
- [ ] **Step 2: Run** → FAIL. **Step 3:** Implement `base.py` + the nine modules. **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(agents): specialist factory + nine domain agents`.

---

## Task 13: Supervisor agent + routing + authorization/HITL gate

**Files:**
- Create: `pepperspray/agents/supervisor.py`, `pepperspray/graph/__init__.py`, `pepperspray/graph/routing.py`
- Test: `tests/graph/test_routing.py`
- Data: `pepperspray/data/__init__.py` (migrate effectiveness tables / attack patterns from `IntelligentDecisionEngine`).

**Interfaces:**
- Produces: `supervisor_node(state) -> dict` — LLM with structured output (`Route(next: Literal[<agents>, "FINISH"])`) chooses the next specialist from `objective` + `findings`. Clamps `next` to known agents; decrements `step_budget`; routes to `FINISH` when budget hits 0 or objective satisfied.
- `routing.py`: `route_from_supervisor(state) -> str` (the conditional edge target), `requires_human_approval(state) -> bool` (true before an exploitation-family step), `authorization_gate(state)`.

- [ ] **Step 1: Write failing tests** — `test_supervisor_clamps_unknown_next` (stub LLM returns `"bogus"` → routed to `FINISH` or a valid agent, never `"bogus"`); `test_step_budget_forces_finish`; `test_exploitation_requires_approval`.
- [ ] **Step 2: Run** → FAIL. **Step 3:** Implement. **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(graph): supervisor routing + authorization/HITL gate`.

---

## Task 14: Graph assembly + chains + checkpointing

**Files:**
- Create: `pepperspray/graph/build.py`, `pepperspray/graph/chains.py`
- Test: `tests/graph/test_build.py`

**Interfaces:**
- Produces: `build_graph(ctx: ToolContext, checkpointer=None) -> CompiledGraph`. Nodes: `supervisor` + nine specialists. Edges: `START→supervisor`; conditional edge from `supervisor` via `route_from_supervisor` to each specialist or `END`; each specialist → `supervisor`. Interrupt-before on exploitation per the gate. Checkpointer: `MemorySaver()` default, `SqliteSaver` when `settings.checkpoint_db` set.
- `chains.py`: `recon_chain(ctx)`, `bugbounty_recon(ctx)`, `comprehensive_assessment(ctx)` — linear/fixed subgraphs (migrate step sequences from `BugBountyWorkflowManager`). `run_assessment(target, objective, authorized, ctx) -> AssessmentState` convenience wrapper.

- [ ] **Step 1: Write failing tests** — `test_graph_compiles` (node set correct); `test_end_to_end_with_stub_llm` (supervisor stub routes recon→FINISH; assert returned state has `tool_results` and a `report` after reporting agent); `test_recon_chain_runs`.
- [ ] **Step 2: Run** → FAIL. **Step 3:** Implement. **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(graph): StateGraph assembly, chains, checkpointing`.

---

## Task 15: Reporting

**Files:**
- Create: `pepperspray/reporting/__init__.py`, `pepperspray/reporting/report.py`
- Test: `tests/test_reporting.py`

**Interfaces:**
- Produces: `render_report(state: AssessmentState) -> str` (markdown: target, objective, findings table, tool runs, CVE enrichment). Used by the reporting agent and the CLI.

- [ ] **Step 1: Write failing test** — `test_report_contains_findings` (given a state with two findings → markdown mentions both + target).
- [ ] **Step 2–4:** TDD. **Step 5: Commit** `feat(reporting): markdown assessment report`.

---

## Task 16: CLI

**Files:**
- Create: `pepperspray/interfaces/__init__.py`, `pepperspray/interfaces/cli.py`
- Test: `tests/interfaces/test_cli.py`

**Interfaces:**
- Produces: Typer `app` with commands: `run --target --objective --authorized/--no-authorized --model` (runs the graph, prints the report), `chain <name> --target`, `list-tools [--family]`, `mcp` (launch the MCP server). Refuses active runs unless `--authorized`.

- [ ] **Step 1: Write failing tests** (Typer `CliRunner`) — `test_list_tools_lists_families`; `test_run_requires_authorization` (without `--authorized`, active run exits non-zero with a clear message); `test_run_with_stub_graph` (monkeypatch `run_assessment` → prints report).
- [ ] **Step 2–4:** TDD. **Step 5: Commit** `feat(cli): typer entrypoint (run/chain/list-tools/mcp)`.

---

## Task 17: MCP server

**Files:**
- Create: `pepperspray/interfaces/mcp_server.py`
- Test: `tests/interfaces/test_mcp_server.py`

**Interfaces:**
- Produces: `build_mcp() -> FastMCP`. Registers high-level tools `run_assessment`, `run_chain`, and per-agent runners; plus, generated from `REGISTRY.all()`, one MCP tool per individual tool (thin wrapper calling `REGISTRY.execute`, threading an `authorized` arg). `main()` runs `mcp.run()` (stdio).

- [ ] **Step 1: Write failing tests** — `test_mcp_registers_all_tools` (tool count == len(REGISTRY.all()) + high-level count); `test_mcp_tool_invokes_registry` (call one wrapper with a stub registry → returns ToolResult dict).
- [ ] **Step 2–4:** TDD. **Step 5: Commit** `feat(mcp): FastMCP server exposing graph + all tools`.

---

## Task 18: Docker + compose + CI + docs + legacy move

**Files:**
- Modify: `Dockerfile` (keep Kali base + binaries; install the `pepperspray` package via `pip install .`; `CMD ["python","-m","pepperspray.interfaces.mcp_server"]`), `docker-compose.yml` (one service for the MCP server + optional `juice-shop` integration target; drop the TCP-bridge service), `.github/workflows/ci.yml` (add `ruff check`, `black --check`, `pytest` to the existing matrix), `README.md`, `.env.example` (add `LLM_PROVIDER`, `ANTHROPIC_API_KEY`, `PEPPERSPRAY_MODEL`)
- Create: `legacy/README.md`
- Move: `pepperspray_server.py`, `pepperspray_mcp.py`, `tcp_stdio_bridge.py`, `mcp-pepperspray-wrapper.sh`, `requirements-docker.txt`(old) → `legacy/`

- [ ] **Step 1:** Move old files to `legacy/` (`git mv`) with a `legacy/README.md` note (removed in a later release).
- [ ] **Step 2:** Rewrite `Dockerfile`/`docker-compose.yml` for the package; keep binary installs.
- [ ] **Step 3:** Update CI to run `ruff`, `black --check`, `pytest` on 3.11/3.12/3.13.
- [ ] **Step 4:** Rewrite `README.md` (new architecture, CLI/MCP usage, authorized-use notice) and `.env.example`.
- [ ] **Step 5: Run** full `pytest -q && ruff check . && black --check .` → all green. **Commit** `build: dockerize package, CI lint+tests, docs, move legacy`.

---

## Task 19: Whole-branch verification + PR

- [ ] **Step 1:** Run `ruff check . && black --check . && pytest -q` → capture green output.
- [ ] **Step 2:** `docker build` the image (smoke: image builds, `pepperspray list-tools` runs inside it).
- [ ] **Step 3:** Push branch, open PR with summary + the attribution lines.
