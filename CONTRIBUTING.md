# Contributing

## Before anything else

This drives offensive tooling. Do not open an issue containing output from a
system you do not own, and do not paste a real target into a bug report.
Redact hostnames and addresses.

## Running it

```bash
docker compose up --build
```

Running the server on the host works but is not the supported path. The
container is where the toolchain is pinned, and it is what keeps a scanner off
your own machine.

## Adding a tool

Every MCP tool takes a target from the client and turns it into a command
line. That is the whole attack surface, so:

- Build the argument list, never a shell string. No `shell=True`.
- Validate the target before the tool runs, not inside the command.
- Write output under `results/` and nowhere else.
- Give it a timeout. A scan that hangs takes the server with it.

A pull request that adds a tool without the first and third of those will not
be merged.

## Before you open a pull request

CI byte-compiles the three entry points across supported Python versions. Run
it yourself:

```bash
python -m compileall -q pepperspray_server.py pepperspray_mcp.py tcp_stdio_bridge.py
```

Catch exceptions you mean to catch. Bare `except:` swallows `KeyboardInterrupt`
and the repository was cleaned of them once already.
