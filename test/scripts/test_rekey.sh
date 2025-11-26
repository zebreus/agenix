#!/usr/bin/env bash
# Test 6: Rekey preserves content

source "$(dirname "$0")/common_setup.sh"

echo "=== Test 6: Rekey preserves content ==="

# Skip on Darwin due to tty issues
if [[ "$OSTYPE" == "darwin"* ]]; then
  echo "Skipping rekey test on Darwin due to tty issues."
  exit 0
fi

# First, reset secret1.age to a known state
echo "rekey-test-content" | agenix encrypt --force secret1.age

# Verify it was set correctly
before_decrypt=$(agenix decrypt secret1.age)
if [ "$before_decrypt" != "rekey-test-content" ]; then
  echo "✗ Failed to set up secret1.age: got '$before_decrypt'"
  exit 1
fi

# Get hash before rekey
before_hash=$(sha256sum secret1.age | cut -d' ' -f1)

# Define faketty function
faketty() {
  script -qefc "$(printf "%q " "$@")" /dev/null
}

# Rekey only seems to work properly in a tty, so we use script to fake one
faketty agenix rekey

# Get hash after rekey
after_hash=$(sha256sum secret1.age | cut -d' ' -f1)
if [ "$before_hash" != "$after_hash" ]; then
  echo "✓ Rekey changes file hash"
else
  echo "✗ Rekey did not change file hash"
  exit 1
fi

# Verify content is preserved after rekey
after_decrypt=$(agenix decrypt secret1.age)
if [ "$after_decrypt" = "rekey-test-content" ]; then
  echo "✓ Content preserved after rekey"
else
  echo "✗ Content not preserved after rekey: expected 'rekey-test-content', got '$after_decrypt'"
  exit 1
fi
