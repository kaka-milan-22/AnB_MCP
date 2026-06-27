// Package alice is a thin wrapper around the `alice` CLI (the AnB client).
//
// All security-critical logic lives in `alice`, not here: the redaction engine,
// the exec allowlist (default-deny, RE2 rules, scope tags), and the structural
// no-reveal guarantee (reveal/shell paths require a TTY this process does not
// have, so alice refuses them). This package never reimplements any of it — it
// only shells out, keeping a single source of truth for the security logic.
//
// alice CLI facts this wrapper relies on:
//   - --dir is a PER-SUBCOMMAND flag (alice <sub> --dir D ...), not global.
//   - exec replaces its process via syscall.Exec, so the child's stdout/stderr
//     are captured by THIS process's pipes; there is no --json exec mode.
//   - --surface (cli|mcp) selects which scoped exec rules apply; we pass mcp.
//   - `alice redact` is a stdin->stdout redaction filter.
//   - `alice list --json` -> {"keys":[...]}; `alice status --json` -> object.
package alice

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// redactStreamSplit separates stdout from stderr when Exec redacts both streams
// in a single `alice redact` pass (instead of one spawn per stream). The NUL
// bytes make it implausible in real command output and break any high-entropy
// run that could otherwise straddle the boundary, so the redactor leaves the
// literal intact and we can split on it afterward.
const redactStreamSplit = "\x00--anb-stream-split--\x00"

// splitRedacted recovers (stdout, stderr) from a redacted combined buffer. ok
// is false if the sentinel did not survive redaction — the caller must then
// fall back to redacting each stream on its own rather than mis-attributing
// bytes across streams.
func splitRedacted(combined string) (stdout, stderr string, ok bool) {
	before, after, found := strings.Cut(combined, redactStreamSplit)
	if !found {
		return "", "", false
	}
	return before, after, true
}

// Config configures how we invoke the alice binary.
type Config struct {
	Bin     string // path/name of the alice binary (default "alice")
	Dir     string // alice --dir: the dedicated, narrowly-scoped MCP identity state
	Surface string // "mcp": passed to `alice exec --surface` (exec only)
}

// Client invokes alice with a fixed identity (--dir) and exec surface.
type Client struct{ cfg Config }

func New(cfg Config) *Client { return &Client{cfg: cfg} }

// KeyInfo mirrors localvault.Listing (alice list --json) — metadata, never a value.
type KeyInfo struct {
	Key         string `json:"key" jsonschema:"the secret key name"`
	Desc        string `json:"desc,omitempty" jsonschema:"optional description"`
	KeyEpoch    int    `json:"keyEpoch,omitempty"`
	LenBytes    int    `json:"lenBytes,omitempty"`
	EntropyBits int    `json:"entropyBits,omitempty"`
}

// ExecResult carries redacted output only — never the injected secret.
type ExecResult struct {
	ExitCode       int    `json:"exit_code"`
	StdoutRedacted string `json:"stdout_redacted"`
	StderrRedacted string `json:"stderr_redacted"`
}

// Status mirrors `alice status --json`. No secret values.
type Status struct {
	Enrolled     bool   `json:"enrolled"`
	Identity     string `json:"identity,omitempty"`
	BobAddr      string `json:"bob_addr,omitempty"`
	ServerName   string `json:"server_name,omitempty"`
	ClientCert   bool   `json:"client_cert"`
	BobReachable bool   `json:"bob_reachable"`
	BobUnlocked  bool   `json:"bob_unlocked"`
	IdleTTLSec   int    `json:"idle_ttl_seconds,omitempty"`
	Error        string `json:"error,omitempty"`
}

// subArgs prepends the subcommand and the per-subcommand --dir flag.
func (c *Client) subArgs(sub string, args ...string) []string {
	return append([]string{sub, "--dir", c.cfg.Dir}, args...)
}

// output runs alice and returns stdout, wrapping failures with stderr context.
func (c *Client) output(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, c.cfg.Bin, args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("alice %v: %w (stderr: %s)", args, err, strings.TrimSpace(errb.String()))
	}
	return out.Bytes(), nil
}

// List returns key names/metadata this identity may reference (never values).
func (c *Client) List(ctx context.Context) ([]KeyInfo, error) {
	out, err := c.output(ctx, c.subArgs("list", "--json")...)
	if err != nil {
		return nil, err
	}
	var wrap struct {
		Keys []KeyInfo `json:"keys"`
	}
	if err := json.Unmarshal(out, &wrap); err != nil {
		return nil, fmt.Errorf("parse list output: %w", err)
	}
	return wrap.Keys, nil
}

// Status returns the identity/health self-check.
func (c *Client) Status(ctx context.Context) (Status, error) {
	out, err := c.output(ctx, c.subArgs("status", "--json")...)
	if err != nil {
		return Status{}, err
	}
	var s Status
	if err := json.Unmarshal(out, &s); err != nil {
		return Status{}, fmt.Errorf("parse status output: %w", err)
	}
	return s, nil
}

// Redact scrubs known secret values and high-entropy tokens from text using
// alice's redaction engine (single source of truth).
func (c *Client) Redact(ctx context.Context, text string) (string, error) {
	cmd := exec.CommandContext(ctx, c.cfg.Bin, c.subArgs("redact")...)
	cmd.Stdin = strings.NewReader(text)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("alice redact: %w (stderr: %s)", err, strings.TrimSpace(errb.String()))
	}
	return out.String(), nil
}

// RenderToFile resolves <agent-vault:key> placeholders in templateContent and
// writes the result to outAbsPath (mode 0600 via `alice template`). The agent's
// template carries only placeholders, so the temp source file holds no secrets;
// the resolved plaintext lands only in the destination file, never returned to
// the caller. Keys it references must be authorized for this identity.
func (c *Client) RenderToFile(ctx context.Context, templateContent, outAbsPath string) error {
	tmp, err := os.CreateTemp("", "anb-tpl-*")
	if err != nil {
		return fmt.Errorf("temp template: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.WriteString(templateContent); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp template: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(outAbsPath), 0o700); err != nil {
		return fmt.Errorf("mkdir render dir: %w", err)
	}
	if _, err := c.output(ctx, c.subArgs("template", tmpName, outAbsPath)...); err != nil {
		return err
	}
	return nil
}

// Exec runs an allowlisted command with secrets injected into the child's env.
// env entries are "KEY=VALUE" where VALUE may contain <agent-vault:key>
// placeholders (alice resolves them via Bob). alice enforces the allowlist
// (default-deny) and the scope=mcp tag, then syscall.Exec's into the child —
// so this subprocess captures the child's stdout/stderr. Both streams are then
// run through `alice redact` before returning, so a secret echoed by the child
// never reaches the caller in plaintext.
//
// On an allowlist denial (or any alice pre-exec failure) the child never runs;
// alice exits non-zero with the reason on stderr, which surfaces here as a
// non-zero ExitCode plus the (redacted) message in StderrRedacted.
func (c *Client) Exec(ctx context.Context, command string, args, env []string) (ExecResult, error) {
	call := []string{"exec", "--dir", c.cfg.Dir}
	if c.cfg.Surface != "" {
		call = append(call, "--surface", c.cfg.Surface)
	}
	for _, e := range env {
		call = append(call, "--env", e) // "KEY=VALUE", VALUE may be a placeholder
	}
	call = append(call, "--", command)
	call = append(call, args...)

	cmd := exec.CommandContext(ctx, c.cfg.Bin, call...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb

	exitCode := 0
	if runErr := cmd.Run(); runErr != nil {
		var ee *exec.ExitError
		if errors.As(runErr, &ee) {
			exitCode = ee.ExitCode()
		} else {
			// Could not even start alice (binary missing, etc.).
			return ExecResult{}, fmt.Errorf("alice exec: %w (stderr: %s)", runErr, strings.TrimSpace(errb.String()))
		}
	}

	// Redact both streams in a SINGLE `alice redact` pass (was one spawn each):
	// concatenate with a sentinel, redact once, split back. If the sentinel did
	// not survive redaction, fall back to per-stream redaction — correctness
	// over the spawn saving, never mis-attribute bytes across streams.
	combined, err := c.Redact(ctx, out.String()+redactStreamSplit+errb.String())
	if err != nil {
		return ExecResult{}, fmt.Errorf("redact output: %w", err)
	}
	stdoutR, stderrR, ok := splitRedacted(combined)
	if !ok {
		if stdoutR, err = c.Redact(ctx, out.String()); err != nil {
			return ExecResult{}, fmt.Errorf("redact stdout: %w", err)
		}
		if stderrR, err = c.Redact(ctx, errb.String()); err != nil {
			return ExecResult{}, fmt.Errorf("redact stderr: %w", err)
		}
	}
	return ExecResult{ExitCode: exitCode, StdoutRedacted: stdoutR, StderrRedacted: stderrR}, nil
}
