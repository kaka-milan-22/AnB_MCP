// Package tools defines the MCP tool handlers for anb-mcp. Each handler is a
// thin adapter over the alice client. Input/output structs carry json +
// jsonschema tags; the go-sdk infers the tool schema from them.
//
// Invariant: NO handler here returns a plaintext secret. Tools either return
// metadata (list/status) or route secrets into a child process (exec),
// returning only redacted output.
package tools

import (
	"context"

	"github.com/kaka-milan-22/AnB_MCP/internal/alice"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Tools holds the dependencies shared by all handlers.
type Tools struct {
	Alice *alice.Client
}

// ---- anb_list -------------------------------------------------------------

type ListInput struct{}

type ListOutput struct {
	Keys []alice.KeyInfo `json:"keys" jsonschema:"secret key names and metadata this identity may reference; never values"`
}

func (t *Tools) List(ctx context.Context, _ *mcp.CallToolRequest, _ ListInput) (*mcp.CallToolResult, ListOutput, error) {
	keys, err := t.Alice.List(ctx)
	if err != nil {
		return nil, ListOutput{}, err
	}
	return nil, ListOutput{Keys: keys}, nil
}

// ---- anb_exec -------------------------------------------------------------

type ExecInput struct {
	Command string   `json:"command" jsonschema:"absolute path of the command to run; must match an allowlisted rule scoped to mcp"`
	Args    []string `json:"args,omitempty" jsonschema:"command arguments"`
	Env     []string `json:"env,omitempty" jsonschema:"child env entries, each in KEY=VALUE form; the VALUE may contain <agent-vault:key> placeholders that are resolved without ever returning the secret"`
}

type ExecOutput struct {
	ExitCode       int    `json:"exit_code"`
	StdoutRedacted string `json:"stdout_redacted" jsonschema:"command stdout with secrets redacted"`
	StderrRedacted string `json:"stderr_redacted" jsonschema:"command stderr with secrets redacted (includes an allowlist-denial message when the command was not permitted)"`
}

func (t *Tools) Exec(ctx context.Context, _ *mcp.CallToolRequest, in ExecInput) (*mcp.CallToolResult, ExecOutput, error) {
	r, err := t.Alice.Exec(ctx, in.Command, in.Args, in.Env)
	if err != nil {
		return nil, ExecOutput{}, err
	}
	return nil, ExecOutput{
		ExitCode:       r.ExitCode,
		StdoutRedacted: r.StdoutRedacted,
		StderrRedacted: r.StderrRedacted,
	}, nil
}

// ---- anb_status -----------------------------------------------------------

type StatusInput struct{}

// StatusOutput mirrors `alice status --json`.
type StatusOutput struct {
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

func (t *Tools) Status(ctx context.Context, _ *mcp.CallToolRequest, _ StatusInput) (*mcp.CallToolResult, StatusOutput, error) {
	s, err := t.Alice.Status(ctx)
	if err != nil {
		return nil, StatusOutput{}, err
	}
	return nil, StatusOutput(s), nil
}
