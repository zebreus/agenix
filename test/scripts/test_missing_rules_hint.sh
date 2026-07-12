#!/usr/bin/env bash
# Test: Missing secrets.nix hint
# Verifies that a helpful hint is shown when secrets.nix doesn't exist

source "$(dirname "$0")/common_setup.sh"

echo "=== Test: Missing secrets.nix hint ==="

# Test 1: Missing secrets.nix should show a helpful error
echo "--- Test 1: Missing secrets.nix shows hint ---"
cd "$TMPDIR" || exit 1
ERROR_OUTPUT=$(agenix list 2>&1) || true

if echo "$ERROR_OUTPUT" | grep -q "No rules file found"; then
  echo "✓ Error message mentions the missing rules file"
else
  echo "✗ Error message should mention the missing rules file"
  echo "  Got: $ERROR_OUTPUT"
  exit 1
fi

if echo "$ERROR_OUTPUT" | grep -q "Create a secrets.nix"; then
  echo "✓ Error suggests creating a secrets.nix"
else
  echo "✗ Error should suggest creating a secrets.nix"
  echo "  Got: $ERROR_OUTPUT"
  exit 1
fi

if echo "$ERROR_OUTPUT" | grep -q "\-\-secrets-nix"; then
  echo "✓ Error mentions --secrets-nix flag"
else
  echo "✗ Error should mention --secrets-nix flag"
  echo "  Got: $ERROR_OUTPUT"
  exit 1
fi

# Test 2: Hint works with other commands too
echo "--- Test 2: Hint works with encrypt command ---"
ERROR_OUTPUT=$(echo "test" | agenix encrypt test 2>&1) || true

if echo "$ERROR_OUTPUT" | grep -q "No rules file found"; then
  echo "✓ Encrypt command shows the missing rules file error"
else
  echo "✗ Encrypt command should show the missing rules file error"
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
