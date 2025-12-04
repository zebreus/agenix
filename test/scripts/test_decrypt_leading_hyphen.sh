#!/usr/bin/env bash
# Test 8: Decrypt file with leading hyphen in name

source "$(dirname "$0")/common_setup.sh"

echo "=== Test 8: Decrypt file with leading hyphen in name ==="
# The decrypt command uses allow_hyphen_values to support filenames starting with hyphen
decrypted=$(agenix decrypt -leading-hyphen-filename)
expected="filename started with hyphen"
if [ "$decrypted" = "$expected" ]; then
  echo "✓ Decrypt file with leading hyphen works"
else
  echo "✗ Decrypt file with leading hyphen failed"
  exit 1
fi
