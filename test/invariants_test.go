// Package test holds the security-invariant tests for anb-mcp. These are the
// guardrails that must stay green forever — they encode the product's promise.
package test

import (
	"context"
	"testing"

	"github.com/kaka-milan-22/AnB_MCP/internal/alice"
	"github.com/kaka-milan-22/AnB_MCP/internal/tools"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// allowedTools is the complete, intentional MCP tool surface. Adding anything
// that returns plaintext (anb_get / anb_reveal / anb_decrypt / shell) must fail
// TestToolSurfaceIsUseDontReveal.
var allowedTools = map[string]bool{
	"anb_list":   true,
	"anb_exec":   true,
	"anb_status": true,
}

var forbiddenSubstrings = []string{"get", "reveal", "decrypt", "shell", "show", "dump"}

// Invariant 1 & 2: the tool surface is "use-don't-reveal".
// No registered tool may return a plaintext secret, and the set must match the
// intentional allowlist. This guards against someone adding a reveal tool later.
func TestToolSurfaceIsUseDontReveal(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "anb-mcp", Version: "test"}, nil)
	tl := &tools.Tools{Alice: alice.New(alice.Config{Bin: "alice"})}
	mcp.AddTool(server, &mcp.Tool{Name: "anb_list"}, tl.List)
	mcp.AddTool(server, &mcp.Tool{Name: "anb_exec"}, tl.Exec)
	mcp.AddTool(server, &mcp.Tool{Name: "anb_status"}, tl.Status)

	// TODO: enumerate the server's registered tools (via the go-sdk server
	// introspection API) into `got`, then assert:
	//   1. every name in `got` is present in `allowedTools`
	//   2. no name in `got` contains any of `forbiddenSubstrings`
	// Pseudocode:
	//   for _, name := range registeredToolNames(server) {
	//       if !allowedTools[name] { t.Fatalf("unexpected tool %q", name) }
	//       for _, bad := range forbiddenSubstrings {
	//           if strings.Contains(name, bad) { t.Fatalf("forbidden tool %q", name) }
	//       }
	//   }
	_ = allowedTools
	_ = forbiddenSubstrings
	t.Skip("TODO: enumerate registered tools and assert use-don't-reveal invariant")
}

// Invariant 3: anb_exec is allowlist-gated (default-deny). A command with no
// matching scope=mcp rule must be denied, and the agent must receive no secret.
func TestExecDefaultDeny(t *testing.T) {
	_ = context.Background()
	// TODO(integration): spin up a test Bob + a dedicated MCP alice identity with
	// an empty/strict scope=mcp allowlist. Call Exec with a non-allowlisted
	// command and assert: (a) it returns an error, (b) no secret material appears
	// anywhere in the result.
	t.Skip("TODO(integration): assert exec of a non-allowlisted command is denied and leaks no secret")
}

// Invariant 4: every tool response is redacted before return. (Covered for
// exec by alice's redaction; assert here once an integration harness exists.)
func TestResponsesAreRedacted(t *testing.T) {
	t.Skip("TODO(integration): assert a known secret never appears verbatim in any tool response")
}
