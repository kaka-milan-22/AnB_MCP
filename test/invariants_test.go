// Package test drives the real anb-mcp binary through a go-sdk MCP client and
// asserts the security invariants end-to-end. Using the client (CommandTransport)
// handles the JSON-RPC handshake and connection lifecycle for us — no manual
// framing or stdin-timing games.
package test

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// buildServer compiles the anb-mcp binary into a temp dir and returns its path.
func buildServer(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "anb-mcp")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Dir = ".." // repo root (this package lives in ./test)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("build anb-mcp: %v", err)
	}
	return bin
}

// connect starts the binary under a client session with the given extra env.
func connect(t *testing.T, bin string, env []string) (*mcp.ClientSession, context.Context) {
	t.Helper()
	ctx := context.Background()
	c := mcp.NewClient(&mcp.Implementation{Name: "anb-mcp-test", Version: "0"}, nil)
	cmd := exec.Command(bin)
	cmd.Env = append(os.Environ(), env...)
	sess, err := c.Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })
	return sess, ctx
}

// Invariant 1 & 2: the tool surface is exactly the safe, "use-don't-reveal" set.
// No tool returns a plaintext secret; no reveal/get/decrypt/shell tool exists.
// (tools/list needs no alice/Bob, so this runs anywhere.)
func TestToolSurfaceUseDontReveal(t *testing.T) {
	sess, ctx := connect(t, buildServer(t), nil)
	res, err := sess.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	got := map[string]bool{}
	for _, tl := range res.Tools {
		got[tl.Name] = true
	}
	want := []string{"anb_list", "anb_exec", "anb_status"}
	if len(got) != len(want) {
		t.Fatalf("tool set = %v, want exactly %v", keys(got), want)
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("missing expected tool %q", w)
		}
	}
	// Guard against anyone ever adding a plaintext-revealing tool.
	for _, bad := range []string{"get", "reveal", "decrypt", "shell", "show", "dump"} {
		for name := range got {
			if strings.Contains(name, bad) {
				t.Errorf("tool %q contains forbidden substring %q", name, bad)
			}
		}
	}
}

// Invariant 3: anb_exec is allowlist-gated (default-deny). A non-allowlisted
// command is denied with no secret; an mcp-scoped allowlisted command runs.
// A no-env exec never touches Bob, so this needs only `alice` on PATH.
func TestExecAllowlistGate(t *testing.T) {
	if _, err := exec.LookPath("alice"); err != nil {
		t.Skip("alice not on PATH; skipping exec allowlist gate test")
	}
	dir := t.TempDir()
	rules := "^/bin/echo hi$\t\t# test\tmcp\n" // one mcp-scoped rule
	if err := os.WriteFile(filepath.Join(dir, "exec-allowlist.rules"), []byte(rules), 0o600); err != nil {
		t.Fatal(err)
	}
	sess, ctx := connect(t, buildServer(t), []string{"ANB_MCP_ALICE_DIR=" + dir})

	allowed := callExec(t, sess, ctx, "/bin/echo", []string{"hi"})
	if allowed.ExitCode != 0 {
		t.Errorf("allowed exec exit = %d want 0 (stderr=%q)", allowed.ExitCode, allowed.StderrRedacted)
	}
	if !strings.Contains(allowed.StdoutRedacted, "hi") {
		t.Errorf("allowed exec stdout = %q want to contain 'hi'", allowed.StdoutRedacted)
	}

	denied := callExec(t, sess, ctx, "/bin/echo", []string{"not-allowlisted"})
	if denied.ExitCode == 0 {
		t.Errorf("denied exec should be non-zero; got 0 (stdout=%q)", denied.StdoutRedacted)
	}
	if !strings.Contains(denied.StderrRedacted, "not in allowlist") {
		t.Errorf("denied exec stderr should mention the allowlist; got %q", denied.StderrRedacted)
	}
}

type execOut struct {
	ExitCode       int    `json:"exit_code"`
	StdoutRedacted string `json:"stdout_redacted"`
	StderrRedacted string `json:"stderr_redacted"`
}

func callExec(t *testing.T, sess *mcp.ClientSession, ctx context.Context, command string, args []string) execOut {
	t.Helper()
	res, err := sess.CallTool(ctx, &mcp.CallToolParams{
		Name:      "anb_exec",
		Arguments: map[string]any{"command": command, "args": args},
	})
	if err != nil {
		t.Fatalf("CallTool anb_exec: %v", err)
	}
	var out execOut
	b, _ := json.Marshal(res.StructuredContent)
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("parse structuredContent: %v (raw: %s)", err, b)
	}
	return out
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
