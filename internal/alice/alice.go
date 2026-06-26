// Package alice is a thin wrapper around the `alice` CLI (the AnB client).
//
// All security-critical logic lives in `alice`, not here:
//   - the redaction engine,
//   - the exec allowlist (default-deny, RE2 rules, scope tags),
//   - the structural no-reveal guarantee (reveal/shell require a TTY, which
//     this process does not have, so alice refuses them).
//
// This package never reimplements any of that — it only shells out. Keeping a
// single source of truth for the security logic is deliberate (decisions #2/#3):
// a second implementation could drift and become a hole.
package alice

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
)

// Config configures how we invoke the alice binary.
type Config struct {
	Bin      string // path/name of the alice binary (default "alice")
	StateDir string // dedicated, narrowly-scoped MCP identity state (NOT the operator's ~/.anb/alice)
	Surface  string // "mcp": alice applies only exec rules tagged scope=mcp
}

// Client invokes alice with a fixed identity + surface.
type Client struct{ cfg Config }

func New(cfg Config) *Client { return &Client{cfg: cfg} }

// KeyInfo is metadata about a secret key — never its value.
type KeyInfo struct {
	Key      string `json:"key" jsonschema:"the secret key name"`
	Prefix   string `json:"prefix,omitempty" jsonschema:"the authz prefix this key falls under"`
	HasValue bool   `json:"has_value" jsonschema:"whether a value is stored for this key"`
	Meta     string `json:"meta,omitempty" jsonschema:"optional metadata label"`
}

// ExecResult is the outcome of an allowlisted command. It carries redacted
// output only — never the secret that was injected.
type ExecResult struct {
	ExitCode       int    `json:"exit_code"`
	StdoutRedacted string `json:"stdout_redacted"`
	StderrRedacted string `json:"stderr_redacted"`
}

// StatusInfo is the identity/health self-check. No secret values.
type StatusInfo struct {
	BobReachable       bool     `json:"bob_reachable"`
	Identity           string   `json:"identity"`
	AuthorizedPrefixes []string `json:"authorized_prefixes"`
	ExecRulesN         int      `json:"exec_rules_n"`
}

// run executes `alice [--surface <s>] --state <dir> <args...>` and returns
// stdout. This process has no TTY, so alice will refuse any reveal/shell path
// automatically — we rely on that for the no-reveal guarantee.
func (c *Client) run(ctx context.Context, args ...string) ([]byte, error) {
	var pre []string
	if c.cfg.Surface != "" {
		// PREREQUISITE (alice): add a --surface flag so only exec rules tagged
		// scope=<surface> apply on this path (decision #2). Until alice ships
		// it, scope is enforced by what rules this MCP identity can see.
		pre = append(pre, "--surface", c.cfg.Surface)
	}
	pre = append(pre, "--state", c.cfg.StateDir)
	cmd := exec.CommandContext(ctx, c.cfg.Bin, append(pre, args...)...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("alice %v: %w: %s", args, err, errb.String())
	}
	return out.Bytes(), nil
}

// List returns the key names/metadata this identity may reference (no values).
func (c *Client) List(ctx context.Context) ([]KeyInfo, error) {
	// TODO(alice flags): confirm `alice list --json` output shape.
	out, err := c.run(ctx, "list", "--json")
	if err != nil {
		return nil, err
	}
	var keys []KeyInfo
	if err := json.Unmarshal(out, &keys); err != nil {
		return nil, fmt.Errorf("parse list output: %w", err)
	}
	return keys, nil
}

// Exec runs an operator-allowlisted command with the named secrets resolved
// into the child process's env. alice enforces the allowlist (default-deny) and
// the scope tag, and redacts the output. The secret value is never returned to
// this process in plaintext.
func (c *Client) Exec(ctx context.Context, rule, command string, args, envKeys []string) (ExecResult, error) {
	call := []string{"exec"}
	if rule != "" {
		call = append(call, "--rule", rule)
	}
	for _, k := range envKeys {
		// alice resolves <agent-vault:k> into the child env.
		call = append(call, "--env", k)
	}
	// TODO(alice flags): confirm a `--json` exec mode that returns
	// {exit_code, stdout_redacted, stderr_redacted}. The redaction is alice's.
	call = append(call, "--json", "--", command)
	call = append(call, args...)

	out, err := c.run(ctx, call...)
	if err != nil {
		// An allowlist denial surfaces here as an error — the agent gets no secret.
		return ExecResult{}, err
	}
	var r ExecResult
	if err := json.Unmarshal(out, &r); err != nil {
		return ExecResult{}, fmt.Errorf("parse exec output: %w", err)
	}
	return r, nil
}

// Redact scrubs known secret values and high-entropy tokens from text using
// alice's redaction engine (decision #3 — single source of truth).
func (c *Client) Redact(ctx context.Context, text string) (string, error) {
	cmd := exec.CommandContext(ctx, c.cfg.Bin, "--state", c.cfg.StateDir, "redact")
	cmd.Stdin = bytes.NewBufferString(text)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("alice redact: %w: %s", err, errb.String())
	}
	return out.String(), nil
}

// Status returns the identity/health self-check.
func (c *Client) Status(ctx context.Context) (StatusInfo, error) {
	out, err := c.run(ctx, "status", "--json")
	if err != nil {
		return StatusInfo{}, err
	}
	var s StatusInfo
	if err := json.Unmarshal(out, &s); err != nil {
		return StatusInfo{}, fmt.Errorf("parse status output: %w", err)
	}
	return s, nil
}
