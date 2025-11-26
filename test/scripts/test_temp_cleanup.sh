#!/usr/bin/env bash
# Test 12: Ensure temporary files are cleaned up

source "$(dirname "$0")/common_setup.sh"

echo "=== Test 12: Ensure temporary files are cleaned up ==="
echo "secret-temp-test" | agenix encrypt --force secret1.age
if grep -r "secret-temp-test" "$TMPDIR" 2>/dev/null; then
  echo "✗ Temporary files not cleaned up"
  exit 1
else
  echo "✓ Temporary files properly cleaned up"
fi
