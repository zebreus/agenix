#!/usr/bin/env bash
# Test: Verbose and quiet flags

source "$(dirname "$0")/common_setup.sh"

echo "=== Test: Verbose and quiet flags ==="

# Test 1: Quiet flag
echo "--- Test 1: Quiet flag ---"
if output=$(agenix -q list 2>&1); then
  echo "✓ Quiet flag accepted"
else
  echo "✗ Quiet flag rejected: $output"
  exit 1
fi

# Test 2: Verbose flag shows rules file path
echo "--- Test 2: Verbose shows rules file ---"
output=$(agenix -v list 2>&1)
if [[ "$output" == *"Using rules file:"* ]]; then
  echo "✓ Verbose shows rules file"
else
  echo "✗ Verbose should show rules file"
  exit 1
fi

# Test 3: Quiet and verbose conflict
echo "--- Test 3: Quiet and verbose conflict ---"
if agenix -q -v list 2>/dev/null; then
  echo "✗ Should have rejected quiet and verbose together"
  exit 1
else
  echo "✓ Quiet and verbose conflict detected"
fi

# Test 4: Quiet flag with decrypt
echo "--- Test 4: Quiet flag with decrypt ---"
reset_secret1
output=$(agenix -q decrypt secret1.age 2>&1)
if [ "$output" = "hello" ]; then
  echo "✓ Quiet flag with decrypt works"
else
  echo "✗ Quiet flag with decrypt unexpected output: '$output'"
  exit 1
fi

# Test 5: Verbose flag with decrypt
echo "--- Test 5: Verbose flag with decrypt ---"
output=$(agenix -v decrypt secret1.age 2>&1)
if [[ "$output" == *"Decrypting secret:"* ]]; then
  echo "✓ Verbose flag with decrypt shows info"
else
  echo "✗ Verbose should show decryption info"
  exit 1
fi

echo ""
echo "All verbose/quiet tests passed!"
