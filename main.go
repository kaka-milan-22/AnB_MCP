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

	"github.com/kaka-milan-22/AnB_MCP/internal/alice"
	"github.com/kaka-milan-22/AnB_MCP/internal/tools"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	// Dedicated, narrowly-scoped MCP identity state — NOT the operator's
	// ~/.anb/alice. The operator must enroll this identity with Bob and grant
	// it only the key prefixes the agent is allowed to use (decision #4).
	stateDir := os.Getenv("ANB_MCP_ALICE_STATE")
	if stateDir == "" {
		stateDir = os.ExpandEnv("$HOME/.anb/alice-mcp")
	}

	ac := alice.New(alice.Config{
		Bin:      envOr("ANB_ALICE_BIN", "alice"),
		StateDir: stateDir,
		Surface:  "mcp", // alice applies only exec rules tagged scope=mcp (decision #2)
	})

	t := &tools.Tools{Alice: ac}

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
