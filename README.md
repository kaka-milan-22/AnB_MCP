# AnB-MCP

An MCP server front-end for [AnB](https://github.com/kaka-milan-22/AnB) that lets AI
agents **use** secrets without ever **seeing** them.

![anb-mcp quickstart](docs/quickstart.gif)

> **Headline guarantee:** even a fully prompt-injected agent, calling every tool in
> every way, cannot extract a raw key. No tool returns a plaintext secret; reveal
> paths require a TTY that this server does not have, so `alice` refuses them.

Unlike a naive "secrets MCP" that hands the key to the model, here the agent gets
placeholders and outcomes — the plaintext stays behind the `anb-mcp → alice → Bob`
boundary.

## How it works

```
Agent (untrusted) ──MCP/stdio──► anb-mcp ──exec──► alice ──mTLS──► Bob ──► master key
                                  (this repo)      (AnB client)   (AnB KMS daemon)
```

`anb-mcp` runs as a **dedicated, narrowly-scoped AnB identity** (not your operator
CLI identity), so a compromised agent's blast radius is limited to what Bob authorizes
for that identity.

## Tools

| Tool | Does | Returns |
|------|------|---------|
| `anb_list` | List secret keys this identity may reference | names + metadata, **no values** |
| `anb_exec` | Run an operator-allowlisted command with secrets injected into the child's env | exit code + **redacted** stdout/stderr |
| `anb_status` | Health / authz self-check | Bob reachability, identity, authorized prefixes, rule count |
| `anb_redact` | Scrub text — secret values + high-entropy tokens → `<agent-vault:key>` | redacted text |
| `anb_render_to_file` | Render a placeholder template, write a 0600 file under the render dir | the path, **never the content** |

Never exposed: any reveal / get-plaintext / shell tool.

## Prerequisites

This is a thin front-end; it depends on AnB. For v0.1 you need:

1. **A working `alice` + `bob`** (AnB) on the host.
2. **A dedicated MCP identity** enrolled with Bob, scoped to only the key prefixes the
   agent should use. Point the server at it via `ANB_MCP_ALICE_DIR`
   (default `~/.anb/alice-mcp`). Do **not** reuse your operator identity.
3. **Exec allowlist with scope tags** — `alice`'s exec rules carry a 4th `scope`
   column; only rules tagged `mcp` apply to this surface (default-deny). Tag a rule
   for the agent by appending `mcp` (e.g. `^/opt/.../curl ...$\tOPENAI_KEY\t# call\tmcp`).
   *(Requires AnB with `alice exec --surface`, `alice redact`, and `alice status --json`
   — all shipped.)*

## Build

```bash
go mod tidy
go build -o anb-mcp .
```

## Register with Claude Code

```bash
claude mcp add -s user -e ANB_MCP_ALICE_DIR=$HOME/.anb/alice-mcp \
  anb -- /path/to/anb-mcp
```

Or in `~/.claude.json` under `mcpServers`:

```json
{
  "mcpServers": {
    "anb": {
      "command": "/path/to/anb-mcp",
      "env": { "ANB_MCP_ALICE_DIR": "/Users/you/.anb/alice-mcp" }
    }
  }
}
```

Tools surface as `mcp__anb__anb_list`, `mcp__anb__anb_exec`, `mcp__anb__anb_status`.

## Status

**v0.1 — done, verified end-to-end (and by a real agent).** All three tools work
against a live Bob: `anb_status` returns real KMS state; `anb_exec` runs allowlisted
commands and denies the rest; and a secret injected via `--env <agent-vault:key>` is
used by the child process while the caller receives only the redacted placeholder —
the plaintext never reaches the agent. Confirmed both by go-sdk-client invariant
tests (`test/`) and by an independent Claude Code session calling the tools over MCP.
See [CHANGELOG.md](./CHANGELOG.md).

Roadmap: see [PLAN.md](./PLAN.md). (v0.2 adds `anb_render_to_file` + a dedicated
`anb_redact` tool; v0.3 lowers per-call latency and adds per-agent ephemeral,
short-TTL scoped credentials — **while keeping `alice` as a separate process**, so the
no-reveal guarantee stays *structural*, not a code-discipline promise.)

## License

MIT
