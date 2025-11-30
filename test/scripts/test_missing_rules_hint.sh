#!/usr/bin/env bash
# Test: Missing rules file hint
# Verifies that a helpful hint is shown when the rules file doesn't exist

source "$(dirname "$0")/common_setup.sh"

echo "=== Test: Missing rules file hint ==="

# Test 1: Missing rules file should show hint
echo "--- Test 1: Missing rules file shows hint ---"
cd "$TMPDIR" || exit 1
ERROR_OUTPUT=$(agenix list 2>&1) || true

if echo "$ERROR_OUTPUT" | grep -q "Rules file not found"; then
  echo "✓ Error message mentions 'Rules file not found'"
else
  echo "✗ Error message should mention 'Rules file not found'"
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

if echo "$ERROR_OUTPUT" | grep -q "\-r"; then
  echo "✓ Hint mentions -r flag"
else
  echo "✗ Hint should mention -r flag"
  echo "  Got: $ERROR_OUTPUT"
  exit 1
fi

# Test 2: Hint works with other commands too
echo "--- Test 2: Hint works with encrypt command ---"
ERROR_OUTPUT=$(echo "test" | agenix encrypt test.age 2>&1) || true

if echo "$ERROR_OUTPUT" | grep -q "Rules file not found"; then
  echo "✓ Encrypt command shows rules hint"
else
  echo "✗ Encrypt command should show rules hint"
  echo "  Got: $ERROR_OUTPUT"
  exit 1
fi

# Test 3: Completions command should NOT require rules file
echo "--- Test 3: Completions works without rules file ---"
if agenix completions bash >/dev/null 2>&1; then
  echo "✓ Completions command works without rules file"
else
  echo "✗ Completions command should not require rules file"
  exit 1
fi

echo ""
echo "All missing rules hint tests passed!"
