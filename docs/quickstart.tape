# Render with:  vhs docs/quickstart.tape   (run from the repo root)
Output docs/quickstart.gif

Set Shell "bash"
Set FontSize 20
Set Width 1200
Set Height 560
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms
Set Padding 26
Set BorderRadius 8

# --- hidden setup: tools on PATH, clean binary, clean screen ---
Hide
Type 'export PATH="$HOME/.local/bin:/opt/homebrew/bin:$PATH"'
Enter
Type 'cd ~/claude/AnB_MCP && rm -f anb-mcp'
Enter
Type 'clear'
Enter
Show

# --- visible quickstart ---
Type "# AnB-MCP — let agents USE secrets without ever SEEING them"
Enter
Sleep 900ms
Type "go build -o anb-mcp ."
Enter
Sleep 4s
Type "# register in Claude Code (dedicated scoped identity):"
Enter
Type "#   claude mcp add anb -e ANB_MCP_ALICE_DIR=$HOME/.anb/alice-mcp -- ./anb-mcp"
Enter
Sleep 900ms
Type "# verify the use-don't-reveal tool surface (no backend needed):"
Enter
Type "./scripts/smoke.sh"
Enter
Sleep 4500ms
