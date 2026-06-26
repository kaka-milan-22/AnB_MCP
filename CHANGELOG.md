# Changelog

## v0.1.0 — first working end-to-end

The first functional release of **AnB-MCP**: an MCP server front-end for
[AnB](https://github.com/kaka-milan-22/AnB) that lets AI agents **use** secrets
without ever **seeing** the plaintext.

### Tools
- `anb_list` — list secret key names/metadata this identity may reference (no values).
- `anb_exec` — run an operator-allowlisted command with secrets injected into the
  child process env; returns exit code + **redacted** stdout/stderr.
- `anb_status` — enrollment / Bob reachability / unlock self-check (no values).

### Security model
- The agent/LLM is untrusted; the MCP server is the trust boundary, running as a
  **dedicated, narrowly-scoped AnB identity** (not the operator's).
- Tool surface is **use-don't-reveal**: no tool returns plaintext. Reveal/shell
  paths require a TTY the server does not have, so `alice` refuses them —
  the guarantee is **structural, not prompt-based**.
- `anb_exec` is **default-deny**: only commands matching a `scope=mcp` exec rule run.

### Implementation
- Go + the official `modelcontextprotocol/go-sdk` (v1.2).
- Thin wrapper that shells out to `alice` — all security-critical logic
  (redaction, allowlist, no-reveal) stays in `alice`, single source of truth.
- Depends on AnB shipping `alice exec --surface`, `alice redact` (stdin filter),
  and `alice status --json` — all added alongside this release.

### Verified
- **End-to-end against a live Bob**: `anb_status` returns real KMS state;
  `anb_exec` runs an allowlisted command; a non-allowlisted command is denied;
  and a secret injected via `--env <agent-vault:key>` is used by the child
  (`printenv` printed it) while the caller receives only the redacted
  placeholder `<agent-vault:…>`.
- **By a real independent agent**: a separate Claude Code session called the
  tools over MCP, used the secret, and confirmed the plaintext never entered its
  context — the no-reveal property holding against an actual LLM.
- go-sdk-client invariant tests (`test/`): tool surface is exactly
  {list, exec, status} with no reveal tool; exec is allowlist-gated.

### Known observations
- `alice redact` (AnB's redaction engine) can over-redact short fragments in
  passthrough text (e.g. a character of an audit-line label coinciding with a
  secret fragment). This is fail-safe (over-redaction, never under), but the
  match granularity in `internal/redact` is worth tightening upstream.

### Setup (runtime, per host)
1. Enroll a dedicated identity into a separate dir (e.g. `~/.anb/alice-mcp`).
2. Grant it a narrow prefix in Bob's `authz.json` (preserve other identities;
   restart `bob serve` to reload).
3. Add `scope=mcp` exec rules (4 tab fields: `regex⇥env-csv⇥#label⇥mcp`).
4. `claude mcp add anb -e ANB_MCP_ALICE_DIR=$HOME/.anb/alice-mcp -- /path/to/anb-mcp`.

### Not yet
- `anb_render_to_file` + a dedicated `anb_redact` tool (v0.2).
- Refactor to a direct, per-agent scoped Bob client (v0.3 — enables ephemeral
  scoped credentials).
