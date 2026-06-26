// Package tools defines the MCP tool handlers for anb-mcp. Each handler is a
// thin adapter over the alice client. Input/output structs carry json +
// jsonschema tags; the go-sdk infers the tool schema from them.
//
// Invariant: NO handler here returns a plaintext secret. Tools either return
// metadata (list/status) or route secrets into a child process / file (exec),
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
	Rule    string   `json:"rule,omitempty" jsonschema:"id of the operator-allowlisted exec rule to run"`
	Command string   `json:"command" jsonschema:"the command to run; must match an allowlisted rule (scope=mcp)"`
	Args    []string `json:"args,omitempty" jsonschema:"command arguments"`
	EnvKeys []string `json:"env_keys,omitempty" jsonschema:"secret key names to inject into the child process env; values are never returned"`
}

type ExecOutput struct {
	ExitCode       int    `json:"exit_code"`
	StdoutRedacted string `json:"stdout_redacted" jsonschema:"command stdout with secrets redacted"`
	StderrRedacted string `json:"stderr_redacted" jsonschema:"command stderr with secrets redacted"`
}

func (t *Tools) Exec(ctx context.Context, _ *mcp.CallToolRequest, in ExecInput) (*mcp.CallToolResult, ExecOutput, error) {
	r, err := t.Alice.Exec(ctx, in.Rule, in.Command, in.Args, in.EnvKeys)
	if err != nil {
		// Allowlist denial / failure surfaces as an error — the agent gets no secret.
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

type StatusOutput struct {
	BobReachable       bool     `json:"bob_reachable"`
	Identity           string   `json:"identity"`
	AuthorizedPrefixes []string `json:"authorized_prefixes"`
	ExecRulesN         int      `json:"exec_rules_n"`
}

func (t *Tools) Status(ctx context.Context, _ *mcp.CallToolRequest, _ StatusInput) (*mcp.CallToolResult, StatusOutput, error) {
	s, err := t.Alice.Status(ctx)
	if err != nil {
		return nil, StatusOutput{}, err
	}
	return nil, StatusOutput{
		BobReachable:       s.BobReachable,
		Identity:           s.Identity,
		AuthorizedPrefixes: s.AuthorizedPrefixes,
		ExecRulesN:         s.ExecRulesN,
	}, nil
}
