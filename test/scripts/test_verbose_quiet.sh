#!/usr/bin/env bash
# Test: Verbose and quiet flags
# Tests for the global verbose and quiet flags

source "$(dirname "$0")/common_setup.sh"

echo "=== Test: Verbose and quiet flags ==="

# Test 1: Quiet flag suppresses warnings
echo "--- Test 1: Quiet flag basic ---"
output=$(agenix -q list 2>&1)
exit_code=$?
if [ $exit_code -eq 0 ]; then
  echo "✓ Quiet flag accepted"
else
  echo "✗ Quiet flag rejected: $output"
  exit 1
fi

# Test 2: Long quiet flag
echo "--- Test 2: Long quiet flag ---"
output=$(agenix --quiet list 2>&1)
exit_code=$?
if [ $exit_code -eq 0 ]; then
  echo "✓ Long quiet flag accepted"
else
  echo "✗ Long quiet flag rejected: $output"
  exit 1
fi

# Test 3: Verbose flag
echo "--- Test 3: Verbose flag basic ---"
output=$(agenix -v list 2>&1)
exit_code=$?
if [ $exit_code -eq 0 ]; then
  echo "✓ Verbose flag accepted"
else
  echo "✗ Verbose flag rejected: $output"
  exit 1
fi

# Test 4: Long verbose flag
echo "--- Test 4: Long verbose flag ---"
output=$(agenix --verbose list 2>&1)
exit_code=$?
if [ $exit_code -eq 0 ]; then
  echo "✓ Long verbose flag accepted"
else
  echo "✗ Long verbose flag rejected: $output"
  exit 1
fi

# Test 5: Verbose shows secrets.nix path
echo "--- Test 5: Verbose shows secrets.nix ---"
output=$(agenix -v list 2>&1)
if [[ "$output" == *"Using secrets.nix:"* ]]; then
  echo "✓ Verbose shows secrets.nix"
else
  echo "✗ Verbose should show secrets.nix"
  exit 1
fi

# Test 6: Quiet and verbose conflict
echo "--- Test 6: Quiet and verbose conflict ---"
if agenix -q -v list 2>/dev/null; then
  echo "✗ Should have rejected quiet and verbose together"
  exit 1
else
  echo "✓ Quiet and verbose conflict detected"
fi

# Test 7: Quiet flag with decrypt
echo "--- Test 7: Quiet flag with decrypt ---"
reset_secret1
output=$(agenix -q decrypt secret1 2>&1)
# Should only output the decrypted content, no warnings
if [ "$output" = "hello" ]; then
  echo "✓ Quiet flag with decrypt works"
else
  echo "✗ Quiet flag with decrypt unexpected output: '$output'"
  exit 1
fi

# Test 8: Verbose flag with decrypt
echo "--- Test 8: Verbose flag with decrypt ---"
output=$(agenix -v decrypt secret1 2>&1)
if [[ "$output" == *"Decrypting secret:"* ]]; then
  echo "✓ Verbose flag with decrypt shows info"
else
  echo "✗ Verbose should show decryption info"
  exit 1
fi

# Test 9: Quiet flag with check
echo "--- Test 9: Quiet flag with check ---"
output=$(agenix -q check secret1 2>&1)
exit_code=$?
if [ $exit_code -eq 0 ]; then
  echo "✓ Quiet flag with check works"
else
  echo "✗ Quiet flag with check failed"
  exit 1
fi

# Test 10: Quiet after subcommand
echo "--- Test 10: Quiet after subcommand ---"
output=$(agenix list -q 2>&1)
exit_code=$?
if [ $exit_code -eq 0 ]; then
  echo "✓ Quiet after subcommand works"
else
  echo "✗ Quiet after subcommand failed"
  exit 1
fi

echo ""
echo "All verbose/quiet tests passed!"
