#!/usr/bin/env bash
# Test: Completions command

source "$(dirname "$0")/common_setup.sh"

echo "=== Test: Completions command ==="

# Test 1: Bash completions
echo "--- Test 1: Bash completions ---"
bash_completions=$(agenix completions bash 2>&1)
if echo "$bash_completions" | grep -q "_agenix"; then
  echo "✓ Bash completions work"
else
  echo "✗ Bash completions failed"
  exit 1
fi

# Test 2: Zsh completions
echo "--- Test 2: Zsh completions ---"
zsh_completions=$(agenix completions zsh 2>&1)
if echo "$zsh_completions" | grep -q "agenix"; then
  echo "✓ Zsh completions work"
else
  echo "✗ Zsh completions failed"
  exit 1
fi

# Test 3: Fish completions
echo "--- Test 3: Fish completions ---"
fish_completions=$(agenix completions fish 2>&1)
if echo "$fish_completions" | grep -q "agenix"; then
  echo "✓ Fish completions work"
else
  echo "✗ Fish completions failed"
  exit 1
fi

echo ""
echo "All completions tests passed!"
