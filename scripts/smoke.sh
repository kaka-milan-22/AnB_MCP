#!/usr/bin/env bash
# Smoke test: start the anb-mcp server, run the initialize -> tools/list
# handshake, and print the tool names it serves. No AnB backend needed
# (alice/bob are only invoked at tool-CALL time, not for introspection).
set -euo pipefail
[ -x ./anb-mcp ] || go build -o anb-mcp .
{
  printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}'
  printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/initialized"}'
  printf '%s\n' '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
  sleep 1   # keep stdin open so the server can answer before EOF
} | ./anb-mcp 2>/dev/null \
  | jq -r 'select(.id==2) | "✓ anb-mcp serves \(.result.tools|length) tools (use, never reveal):", (.result.tools[] | "  • \(.name)")'
