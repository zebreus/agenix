#!/usr/bin/env bash
# Test: Setup hook for shell completions
# Tests that the setup hook correctly configures bash completions

source "$(dirname "$0")/common_setup.sh"

echo "=== Test: Setup hook for shell completions ==="

# Get the path to the agenix package
AGENIX_PATH=$(command -v agenix)
AGENIX_PKG=$(dirname "$(dirname "$AGENIX_PATH")")

# Test 1: Check that bash completion file exists
echo "--- Test 1: Bash completion file exists ---"
BASH_COMPLETION_FILE="$AGENIX_PKG/share/bash-completion/completions/agenix.bash"
if [[ -f "$BASH_COMPLETION_FILE" ]]; then
  echo "✓ Bash completion file exists at: $BASH_COMPLETION_FILE"
else
  echo "✗ Bash completion file not found at: $BASH_COMPLETION_FILE"
  exit 1
fi

# Test 2: Check that bash completion file has valid syntax
echo "--- Test 2: Bash completion file has valid syntax ---"
if bash -n "$BASH_COMPLETION_FILE" 2>/dev/null; then
  echo "✓ Bash completion file has valid syntax"
else
  echo "✗ Bash completion file has invalid syntax"
  exit 1
fi

# Test 3: Source bash completion and verify it registers the completion
echo "--- Test 3: Bash completion registers correctly ---"
# Source the completion file
source "$BASH_COMPLETION_FILE"
# Check if completion is registered for agenix command
if complete -p agenix 2>/dev/null | grep -q "agenix"; then
  echo "✓ Bash completion is registered for agenix"
else
  echo "✗ Bash completion not registered for agenix"
  exit 1
fi

# Test 4: Check that setup hook file exists
echo "--- Test 4: Setup hook file exists ---"
SETUP_HOOK="$AGENIX_PKG/nix-support/setup-hook"
if [[ -f "$SETUP_HOOK" ]]; then
  echo "✓ Setup hook file exists at: $SETUP_HOOK"
else
  echo "✗ Setup hook file not found at: $SETUP_HOOK"
  exit 1
fi

# Test 5: Setup hook contains bash completion sourcing logic
echo "--- Test 5: Setup hook contains bash logic ---"
if grep -q "BASH_VERSION" "$SETUP_HOOK" && grep -q "agenix.bash" "$SETUP_HOOK"; then
  echo "✓ Setup hook contains bash completion logic"
else
  echo "✗ Setup hook missing bash completion logic"
  exit 1
fi

# Test 6: Setup hook contains XDG_DATA_DIRS for fish
echo "--- Test 6: Setup hook contains XDG_DATA_DIRS logic for fish ---"
if grep -q "XDG_DATA_DIRS" "$SETUP_HOOK"; then
  echo "✓ Setup hook contains XDG_DATA_DIRS logic for fish"
else
  echo "✗ Setup hook missing XDG_DATA_DIRS logic"
  exit 1
fi

# Test 7: Check that fish completion file exists
echo "--- Test 7: Fish completion file exists ---"
FISH_COMPLETION_FILE="$AGENIX_PKG/share/fish/vendor_completions.d/agenix.fish"
if [[ -f "$FISH_COMPLETION_FILE" ]]; then
  echo "✓ Fish completion file exists at: $FISH_COMPLETION_FILE"
else
  echo "✗ Fish completion file not found at: $FISH_COMPLETION_FILE"
  exit 1
fi

# Test 8: Check that zsh completion file exists
echo "--- Test 8: Zsh completion file exists ---"
ZSH_COMPLETION_FILE="$AGENIX_PKG/share/zsh/site-functions/_agenix"
if [[ -f "$ZSH_COMPLETION_FILE" ]]; then
  echo "✓ Zsh completion file exists at: $ZSH_COMPLETION_FILE"
else
  echo "✗ Zsh completion file not found at: $ZSH_COMPLETION_FILE"
  exit 1
fi

# Test 9: Setup hook contains zsh fpath logic
echo "--- Test 9: Setup hook contains zsh fpath logic ---"
if grep -q "ZSH_VERSION" "$SETUP_HOOK" && grep -q "fpath" "$SETUP_HOOK"; then
  echo "✓ Setup hook contains zsh fpath logic"
else
  echo "✗ Setup hook missing zsh fpath logic"
  exit 1
fi

echo ""
echo "All setup hook tests passed!"
