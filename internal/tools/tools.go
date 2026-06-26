// Package tools defines the MCP tool handlers for anb-mcp. Each handler is a
// thin adapter over the alice client. Input/output structs carry json +
// jsonschema tags; the go-sdk infers the tool schema from them.
//
// Invariant: NO handler returns a plaintext secret. Tools return metadata
// (list/status), route secrets into a child process (exec) or a file
// (render_to_file) and return only redacted/no content, or scrub text (redact).
package tools

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/kaka-milan-22/AnB_MCP/internal/alice"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Tools holds the dependencies shared by all handlers.
type Tools struct {
	Alice     *alice.Client
	RenderDir string // base dir that anb_render_to_file writes are confined to
}

// safeOutPath confines an agent-supplied relative path to base. It rejects
// absolute paths and any traversal that escapes base — an agent (even prompt-
// injected) cannot write outside the render dir or clobber arbitrary files.
func safeOutPath(base, rel string) (string, error) {
	if rel == "" {
		return "", fmt.Errorf("out_path is empty")
	}
	if filepath.IsAbs(rel) {
		return "", fmt.Errorf("out_path %q must be relative to the render dir", rel)
	}
	baseClean := filepath.Clean(base)
	clean := filepath.Clean(filepath.Join(baseClean, rel))
	if clean != baseClean && !strings.HasPrefix(clean, baseClean+string(filepath.Separator)) {
		return "", fmt.Errorf("out_path %q escapes the render dir", rel)
	}
	return clean, nil
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

// ---- anb_redact -----------------------------------------------------------

type RedactInput struct {
	Text string `json:"text" jsonschema:"text to scrub; known secret values and high-entropy tokens become <agent-vault:key> placeholders"`
}

type RedactOutput struct {
	Redacted string `json:"redacted" jsonschema:"the input with secrets replaced by placeholders"`
}

func (t *Tools) Redact(ctx context.Context, _ *mcp.CallToolRequest, in RedactInput) (*mcp.CallToolResult, RedactOutput, error) {
	r, err := t.Alice.Redact(ctx, in.Text)
	if err != nil {
		return nil, RedactOutput{}, err
	}
	return nil, RedactOutput{Redacted: r}, nil
}

// ---- anb_render_to_file ---------------------------------------------------

type RenderInput struct {
	Template string `json:"template" jsonschema:"file content with <agent-vault:key> placeholders; resolved values are written to disk (mode 0600), never returned to the caller"`
	OutPath  string `json:"out_path" jsonschema:"destination path RELATIVE to the render dir; absolute paths and path traversal are rejected"`
}

type RenderOutput struct {
	Written bool   `json:"written"`
	Path    string `json:"path" jsonschema:"the absolute path the rendered file was written to"`
}

func (t *Tools) Render(ctx context.Context, _ *mcp.CallToolRequest, in RenderInput) (*mcp.CallToolResult, RenderOutput, error) {
	abs, err := safeOutPath(t.RenderDir, in.OutPath)
	if err != nil {
		return nil, RenderOutput{}, err
	}
	if err := t.Alice.RenderToFile(ctx, in.Template, abs); err != nil {
		return nil, RenderOutput{}, err
	}
	return nil, RenderOutput{Written: true, Path: abs}, nil
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
