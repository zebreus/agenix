#!/usr/bin/env bash
# Test: Check command

source "$(dirname "$0")/common_setup.sh"

echo "=== Test: Check command ==="

# Test 1: Check all secrets
echo "--- Test 1: Check all secrets ---"
check_output=$(agenix check 2>&1)
exit_code=$?
if [ $exit_code -eq 0 ] && echo "$check_output" | grep -q "verified successfully"; then
  echo "✓ Check command verifies secrets"
else
  echo "✗ Check command failed"
  exit 1
fi

# Test 2: Check specific secret
echo "--- Test 2: Check specific secret ---"
check_specific=$(agenix check secret1 2>&1)
if echo "$check_specific" | grep -q "secret1"; then
  echo "✓ Check specific secret works"
else
  echo "✗ Check specific secret failed"
  exit 1
fi

# Test 3: Check multiple secrets
echo "--- Test 3: Check multiple secrets ---"
check_multi=$(agenix check secret1 secret2 2>&1)
if echo "$check_multi" | grep -q "secret1" && echo "$check_multi" | grep -q "secret2"; then
  echo "✓ Check multiple secrets works"
else
  echo "✗ Check multiple secrets failed"
  exit 1
fi

# Test 4: Short alias 'v' works
echo "--- Test 4: Short alias 'v' ---"
alias_output=$(agenix v secret1 2>&1)
if echo "$alias_output" | grep -q "secret1"; then
  echo "✓ Short alias 'v' works"
else
  echo "✗ Short alias 'v' failed"
  exit 1
fi

# Test 5: Check invalid secret fails
echo "--- Test 5: Check invalid secret ---"
TEMP_RULES="$TMPDIR/temp-check.nix"
INVALID_SECRET="$TMPDIR/invalid-check.age"
cat > "$TEMP_RULES" << EOF
{
  "$INVALID_SECRET" = {
    publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
  };
}
EOF

echo "not-valid-age-content" > "$INVALID_SECRET"

if agenix check -r "$TEMP_RULES" 2>/dev/null; then
  echo "✗ Check should fail on invalid secret"
  exit 1
else
  echo "✓ Check correctly fails on invalid secret"
fi

echo ""
echo "All check tests passed!"
