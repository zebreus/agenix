#!/usr/bin/env bash
# Test: List command

source "$(dirname "$0")/common_setup.sh"

echo "=== Test: List command ==="

# Test 1: Basic list
echo "--- Test 1: Basic list ---"
list_output=$(agenix list 2>&1)
if echo "$list_output" | grep -q "secret1"; then
  echo "✓ List shows secrets"
else
  echo "✗ List failed to show secrets"
  exit 1
fi

# Test 2: List with summary
if echo "$list_output" | grep -q "Total:"; then
  echo "✓ List shows summary"
else
  echo "✗ List failed to show summary"
  exit 1
fi

# Test 3: Detailed list
echo "--- Test 2: Detailed list ---"
detailed_output=$(agenix list --detailed 2>&1)
if echo "$detailed_output" | grep -q "GENERATOR"; then
  echo "✓ Detailed list shows header"
else
  echo "✗ Detailed list failed to show header"
  exit 1
fi

# Test 4: List shows status correctly
echo "--- Test 3: List shows status ---"
if echo "$list_output" | grep -q "✓"; then
  echo "✓ List shows OK status"
else
  echo "✗ List failed to show OK status"
  exit 1
fi

# Test 5: Short alias 'l' works
echo "--- Test 4: Short alias 'l' ---"
alias_output=$(agenix l 2>&1)
if echo "$alias_output" | grep -q "secret1"; then
  echo "✓ Short alias 'l' works"
else
  echo "✗ Short alias 'l' failed"
  exit 1
fi

echo ""
echo "All list tests passed!"
