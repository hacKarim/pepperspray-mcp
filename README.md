# PepperSpray

[![CI](https://github.com/hacKarim/pepperspray-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/hacKarim/pepperspray-mcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](./LICENSE)
![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)
![LangGraph](https://img.shields.io/badge/LangGraph-multi--agent-111)

A **LangGraph multi-agent framework** for authorized security assessment. A
supervisor agent routes work to specialist agents (recon, web, exploitation,
binary/CTF, cloud, forensics, CVE intelligence), each backed by a declarative,
injection-safe registry of 110+ security tools. It runs as a CLI and as an MCP
server, so you can drive it autonomously or from an MCP client like Claude Code.

> ### ⚠️ Authorized use only
>
> For **authorized security testing, research, and education** only. Only run it
> against systems you own or have **explicit written permission** to test.
> Active assessments require an explicit `--authorized` flag, and
> exploitation-class actions are gated behind a human-in-the-loop interrupt.
> Provided **as-is, with no warranty**.

## Architecture

```
                    ┌───────────────────────────────────────────┐
  CLI ──┐           │              LangGraph StateGraph          │
        ├──────────►│  START → supervisor ⇄ specialists → report │
  MCP ──┘           │             (recon, web, exploitation,     │
                    │        binary, cloud, forensics, cve)      │
                    └───────────────────────┬───────────────────┘
                                            │
                                   ┌────────▼─────────┐
                                   │  Tool registry   │  argv-only, no shell
                                   │  110+ ToolSpecs  │  graceful degradation
                                   └──────────────────┘
```

- **`pepperspray/core/`** — graph state, safe argv executor, tool registry, cache, errors
- **`pepperspray/tools/`** — the tool specs by family, plus preserved CVE intel and CTF flag tools
- **`pepperspray/agents/`** — the specialist factory, the roster, the supervisor, and the **critic** (reflection)
- **`pepperspray/graph/`** — the StateGraph assembly, chains, **parallel fan-out**, routing, and safety gates
- **`pepperspray/interfaces/`** — the Typer CLI and the FastMCP server
- **`legacy/`** — the original v1 Flask/MCP code, kept for reference (to be removed)

### Advanced agentic workflows

- **Parallel fan-out (`Send` API).** The `parallel_scan` chain probes many
  sub-targets **concurrently** and merges their findings via the append-reducers:
  `discover → Send(probe_worker) × N → collect → report`.
  ```bash
  pepperspray chain parallel_scan --target example.com \
    --subtargets "a.example.com,b.example.com,c.example.com" --authorized
  ```
- **Reflection loop (critic + verify).** After the specialists finish, a critic
  agent dedupes and scores findings by confidence and flags the weak ones; a
  verify node re-checks them, looping under `--verify-budget` before reporting.
  Reports show per-finding **confidence** and a **verified** flag. On by default;
  disable with `--no-reflect`.
- **Specialists as nested subgraphs.** Each specialist is its own compiled
  `plan → act → verify` subgraph, not a single node — a two-tier reflection
  (local verify inside each specialist, global critic across all findings).
- **Concurrent specialists.** The supervisor can dispatch several independent
  specialists (e.g. recon + cve) in a single superstep — they run concurrently
  and their findings merge through the append-reducers, instead of one agent
  per hop. Exploitation always runs solo so the human gate reasons about one
  step at a time.
- **Real human-in-the-loop (approve / deny / edit).** Exploitation pauses at a
  dynamic `interrupt()` gate that surfaces an approval-request payload. The
  operator can **approve** (optionally editing scope first), or **deny** — which
  records a finding and routes back to the supervisor instead of exploiting.
  The reflection verifier is non-stub: it re-runs a finding's read-only tool to
  confirm it (never re-running exploitation-class tools).
- **Durable persistence + time-travel.** Set `PEPPERSPRAY_CHECKPOINT_DB` to
  persist runs to SQLite: a run can **pause at exploitation, survive a restart,
  and resume on approval**. Inspect and resume durable runs:
  ```bash
  pepperspray history <thread-id>                      # checkpoint timeline
  pepperspray resume  <thread-id>                      # approve + continue
  pepperspray resume  <thread-id> --no-allow-exploitation  # deny + finish
  ```

## Requirements

- Docker (the security binaries live in the image — this is the supported runtime)
- An LLM API key for the agents' reasoning (`ANTHROPIC_API_KEY` by default)

## Quick start (Docker)

```bash
git clone https://github.com/hacKarim/pepperspray-mcp pepperspray && cd pepperspray
cp .env.example .env            # set ANTHROPIC_API_KEY
docker compose build
```

Run the autonomous assessment (CLI) against an authorized target:

```bash
docker compose run --rm pepperspray \
  pepperspray run --target https://target.example --authorized
```

Run a fixed workflow (chain):

```bash
docker compose run --rm pepperspray \
  pepperspray chain recon_chain --target target.example --authorized
```

List the registered tools:

```bash
docker compose run --rm pepperspray pepperspray list-tools --family recon
```

### Optional integration target

A local OWASP Juice Shop is bundled for authorized testing:

```bash
docker compose --profile integration up -d juice-shop
docker compose run --rm pepperspray \
  pepperspray run --target http://juice-shop:3000 --authorized
```

## Use it from Claude Code (MCP)

Register the MCP server (stdio) with your MCP client:

```json
{
  "mcpServers": {
    "pepperspray": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "-e", "ANTHROPIC_API_KEY", "pepperspray:2.0.0"]
    }
  }
}
```

The server exposes high-level tools (`run_assessment`, `run_chain`, `list_tools`)
plus every individual tool in the registry.

## Local development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,openai,ollama]"
ruff check pepperspray tests && black --check pepperspray tests && pytest -q
```

Unit tests run without any security binaries or an API key (the LLM and the
subprocess boundary are stubbed). Real tool execution happens in the Docker image.

## Configuration

See `.env.example`. `LLM_PROVIDER` selects `anthropic` (default), `openai`, or
`ollama`; the matching key is required for live runs.

## License

[MIT](./LICENSE)
