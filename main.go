// Command anb-mcp is an MCP server front-end for AnB. It lets MCP-speaking
// agents USE secrets (call APIs, run allowlisted tools) without ever SEEING
// the plaintext: the raw secret stays behind the MCP-server <-> Bob boundary.
//
// Security model (see PLAN.md / README.md):
//   - The agent/LLM is UNTRUSTED (assume prompt injection).
//   - This server runs as a DEDICATED, narrowly-scoped AnB (alice) identity,
//     separate from the operator's CLI identity, so a compromised agent's blast
//     radius is limited to what Bob authorizes for this identity.
//   - The tool surface is "use, never reveal". No tool returns a plaintext
//     secret. Reveal/shell paths require a TTY, which this process does not
//     have, so `alice` refuses them automatically — the guarantee is structural.
package main

import (
	"context"
	"log"
	"os"
	"path/filepath"

	"github.com/kaka-milan-22/AnB_MCP/internal/alice"
	"github.com/kaka-milan-22/AnB_MCP/internal/tools"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	// Dedicated, narrowly-scoped MCP identity state (alice --dir) — NOT the
	// operator's ~/.anb/alice. The operator must enroll this identity with Bob
	// and grant it only the key prefixes the agent may use (decision #4).
	dir := os.Getenv("ANB_MCP_ALICE_DIR")
	if dir == "" {
		dir = os.ExpandEnv("$HOME/.anb/alice-mcp")
	}

	ac := alice.New(alice.Config{
		Bin:     envOr("ANB_ALICE_BIN", "alice"),
		Dir:     dir,
		Surface: "mcp", // alice applies only exec rules tagged scope=mcp (decision #2)
	})

	// anb_render_to_file writes are confined to this base dir (agent-supplied
	// paths are relative to it; absolute/traversal paths are rejected).
	renderDir := os.Getenv("ANB_MCP_RENDER_DIR")
	if renderDir == "" {
		renderDir = filepath.Join(dir, "renders")
	}

	t := &tools.Tools{Alice: ac, RenderDir: renderDir}

	server := mcp.NewServer(&mcp.Implementation{
		Name:    "anb-mcp",
		Version: "0.1.0",
	}, nil)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "anb_list",
		Description: "List the secret keys this identity may reference. Returns key names and metadata only — never values.",
	}, t.List)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "anb_exec",
		Description: "Run an operator-allowlisted command with named secrets injected into the child process's environment. Returns the exit code and redacted stdout/stderr. The raw secret is never returned to the caller.",
	}, t.Exec)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "anb_status",
		Description: "Health and authorization self-check: Bob reachability, this identity, the key prefixes it is authorized for, and the exec-rule count. Returns no secret values.",
	}, t.Status)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "anb_redact",
		Description: "Scrub text: replace known secret values and high-entropy tokens with <agent-vault:key> placeholders. Use before logging or returning anything that may contain a secret.",
	}, t.Redact)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "anb_render_to_file",
		Description: "Render a template containing <agent-vault:key> placeholders and write the resolved file (mode 0600) to a path under the render dir. Returns the path, never the resolved content — the caller never sees the secret values.",
	}, t.Render)

	// IMPORTANT: never register a tool that returns plaintext (no anb_get /
	// anb_reveal / anb_decrypt / shell). The invariant test guards this.

	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatalf("anb-mcp: %v", err)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
