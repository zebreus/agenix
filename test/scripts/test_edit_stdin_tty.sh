#!/usr/bin/env bash
# Test: Edit stdin behavior
# Issue #2: Edit command uses stdin directly for non-TTY when EDITOR is not set

source "$(dirname "$0")/common_setup.sh"

echo "=== Test: Edit stdin behavior ==="

# Test 1: Piped input without EDITOR should read from stdin
echo "--- Test 1: Piped input without EDITOR ---"
# Unset EDITOR to test default behavior
unset EDITOR
echo "stdin-edit-content-123" | agenix edit --force secret1.age 2>&1
decrypted=$(agenix decrypt secret1.age)
if [ "$decrypted" = "stdin-edit-content-123" ]; then
  echo "✓ Edit reads from stdin when piped without EDITOR"
else
  echo "✗ Edit should read from stdin when piped without EDITOR"
  echo "  Expected: 'stdin-edit-content-123'"
  echo "  Got: '$decrypted'"
  exit 1
fi

# Test 2: EDITOR env var is respected when set
echo "--- Test 2: EDITOR env var respected ---"
export EDITOR="cat"
# This will just cat the existing content and not change it
# The file should still have the previous content
output=$(agenix edit secret1.age 2>&1)
# Since EDITOR=cat just outputs and exits, file shouldn't change
if [[ "$output" == *"stdin-edit-content-123"* ]]; then
  echo "✓ EDITOR env var is respected"
else
  echo "✗ EDITOR env var should be respected"
  exit 1
fi
unset EDITOR

# Test 3: Explicit -e flag overrides default stdin behavior
echo "--- Test 3: Explicit -e flag overrides stdin ---"
echo "new-content-from-stdin" | agenix edit -e "cat" secret1.age 2>&1
# With EDITOR=cat, the file content is shown but not changed
# because cat just outputs the existing file
decrypted=$(agenix decrypt secret1.age)
if [ "$decrypted" = "stdin-edit-content-123" ]; then
  echo "✓ Explicit -e flag is used instead of stdin"
else
  echo "✗ Explicit -e flag should override stdin reading"
  echo "  Got: '$decrypted'"
  exit 1
fi

# Test 4: New file creation via stdin
echo "--- Test 4: New file via stdin ---"
# First ensure secret2 doesn't exist or remove it
rm -f secret2.age 2>/dev/null || true
unset EDITOR
echo "new-secret-content" | agenix edit secret2.age 2>&1
exit_code=$?
if [ $exit_code -eq 0 ]; then
  decrypted=$(agenix decrypt secret2.age)
  if [ "$decrypted" = "new-secret-content" ]; then
    echo "✓ New file created via stdin"
  else
    echo "✗ New file content incorrect"
    exit 1
  fi
else
  echo "✗ Failed to create new file via stdin"
  exit 1
fi

# Clean up
reset_secret1
rm -f secret2.age 2>/dev/null || true

echo ""
echo "All edit stdin tests passed!"
