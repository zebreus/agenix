#!/usr/bin/env bash
# Test: Edit stdin behavior
# Issue #2: Edit command uses stdin directly for non-TTY when EDITOR is not set

source "$(dirname "$0")/common_setup.sh"

echo "=== Test: Edit stdin behavior ==="

# Test 1: Piped input without EDITOR should read from stdin
echo "--- Test 1: Piped input without EDITOR ---"
unset EDITOR
echo "stdin-edit-content-123" | agenix edit --force secret1.age 2>&1
decrypted=$(agenix decrypt secret1.age)
if [ "$decrypted" = "stdin-edit-content-123" ]; then
  echo "✓ Edit reads from stdin when piped without EDITOR"
else
  echo "✗ Edit should read from stdin when piped without EDITOR"
  echo "  Expected: 'stdin-edit-content-123', Got: '$decrypted'"
  exit 1
fi

# Test 2: EDITOR env var is respected when set
echo "--- Test 2: EDITOR env var respected ---"
export EDITOR="cat"
output=$(agenix edit secret1.age 2>&1)
if [[ "$output" == *"stdin-edit-content-123"* ]]; then
  echo "✓ EDITOR env var is respected"
else
  echo "✗ EDITOR env var should be respected"
  exit 1
fi
unset EDITOR

# Clean up
reset_secret1

echo ""
echo "All edit stdin tests passed!"
