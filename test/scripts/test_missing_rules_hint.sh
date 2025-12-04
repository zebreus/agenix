#!/usr/bin/env bash
# Test: Missing secrets.nix hint
# Verifies that a helpful hint is shown when secrets.nix doesn't exist

source "$(dirname "$0")/common_setup.sh"

echo "=== Test: Missing secrets.nix hint ==="

# Test 1: Missing secrets.nix should show hint
echo "--- Test 1: Missing secrets.nix shows hint ---"
cd "$TMPDIR" || exit 1
ERROR_OUTPUT=$(agenix list 2>&1) || true

if echo "$ERROR_OUTPUT" | grep -q "secrets.nix not found"; then
  echo "✓ Error message mentions 'secrets.nix not found'"
else
  echo "✗ Error message should mention 'secrets.nix not found'"
  echo "  Got: $ERROR_OUTPUT"
  exit 1
fi

if echo "$ERROR_OUTPUT" | grep -q "Hint:"; then
  echo "✓ Error message contains hint"
else
  echo "✗ Error message should contain hint"
  echo "  Got: $ERROR_OUTPUT"
  exit 1
fi

if echo "$ERROR_OUTPUT" | grep -q "cd to a directory with secrets.nix"; then
  echo "✓ Hint suggests changing directory"
else
  echo "✗ Hint should suggest changing directory"
  echo "  Got: $ERROR_OUTPUT"
  exit 1
fi

if echo "$ERROR_OUTPUT" | grep -q "\-\-secrets-nix"; then
  echo "✓ Hint mentions --secrets-nix flag"
else
  echo "✗ Hint should mention --secrets-nix flag"
  echo "  Got: $ERROR_OUTPUT"
  exit 1
fi

# Test 2: Hint works with other commands too
echo "--- Test 2: Hint works with encrypt command ---"
ERROR_OUTPUT=$(echo "test" | agenix encrypt test 2>&1) || true

if echo "$ERROR_OUTPUT" | grep -q "secrets.nix not found"; then
  echo "✓ Encrypt command shows secrets.nix hint"
else
  echo "✗ Encrypt command should show secrets.nix hint"
  echo "  Got: $ERROR_OUTPUT"
  exit 1
fi

# Test 3: Completions command should NOT require secrets.nix
echo "--- Test 3: Completions works without secrets.nix ---"
if agenix completions bash >/dev/null 2>&1; then
  echo "✓ Completions command works without secrets.nix"
else
  echo "✗ Completions command should not require secrets.nix"
  exit 1
fi

echo ""
echo "All missing secrets.nix hint tests passed!"
