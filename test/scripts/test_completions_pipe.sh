#!/usr/bin/env bash
# Test: Completions broken pipe fix
# Issue #3: Fish completions panic on pipe

source "$(dirname "$0")/common_setup.sh"

echo "=== Test: Completions broken pipe fix ==="

# Test 1: Fish completions piped to head (was broken)
echo "--- Test 1: Fish completions piped to head ---"
disable_pipefail
output=$(agenix completions fish 2>&1 | head -5)
enable_pipefail
if [[ "$output" == *"panicked"* ]]; then
  echo "✗ Fish completions panicked on pipe: $output"
  exit 1
else
  echo "✓ Fish completions handle broken pipe"
fi

# Test 2: Full fish completions still work
echo "--- Test 2: Full fish completions ---"
output=$(agenix completions fish 2>&1)
if [[ "$output" == *"agenix"* ]]; then
  echo "✓ Full fish completions work"
else
  echo "✗ Full fish completions failed"
  exit 1
fi

echo ""
echo "All completions broken pipe tests passed!"
