#!/usr/bin/env bash
# Test: Check command - Extensive tests

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
INVALID_SECRET_NAME="$TMPDIR/invalid-check"
INVALID_SECRET="$TMPDIR/invalid-check.age"
cat > "$TEMP_RULES" << EOF
{
  "$INVALID_SECRET_NAME" = {
    publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
  };
}
EOF

echo "not-valid-age-content" > "$INVALID_SECRET"

if agenix check --secrets-nix "$TEMP_RULES" 2>/dev/null; then
  echo "✗ Check should fail on invalid secret"
  exit 1
else
  echo "✓ Check correctly fails on invalid secret"
fi

# Test 6: Check nonexistent rules file fails with error
echo "--- Test 6: Nonexistent rules file ---"
if agenix check --secrets-nix "/nonexistent/path/rules.nix" 2>/dev/null; then
  echo "✗ Check should fail on nonexistent rules file"
  exit 1
else
  echo "✓ Check correctly fails on nonexistent rules file"
fi

# Test 7: Check with invalid nix syntax fails
echo "--- Test 7: Invalid nix syntax ---"
INVALID_RULES="$TMPDIR/invalid-check-rules.nix"
echo "{ invalid nix syntax !!!" > "$INVALID_RULES"
if agenix check --secrets-nix "$INVALID_RULES" 2>/dev/null; then
  echo "✗ Check should fail on invalid nix syntax"
  exit 1
else
  echo "✓ Check correctly fails on invalid nix syntax"
fi

# Test 8: Check returns non-zero exit code on failure
echo "--- Test 8: Exit code on failure ---"
FAIL_RULES="$TMPDIR/fail-check-rules.nix"
FAIL_SECRET_NAME="$TMPDIR/fail-secret"
FAIL_SECRET="$TMPDIR/fail-secret.age"
cat > "$FAIL_RULES" << EOF
{
  "$FAIL_SECRET_NAME" = {
    publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
  };
}
EOF
echo "invalid" > "$FAIL_SECRET"
if ! agenix check --secrets-nix "$FAIL_RULES" 2>/dev/null; then
  echo "✓ Check returns non-zero exit code on failure"
else
  echo "✗ Check should return non-zero exit code on failure"
  exit 1
fi

# Test 9: Check returns zero exit code on success
echo "--- Test 9: Exit code on success ---"
if agenix check secret1 2>/dev/null; then
  echo "✓ Check returns zero exit code on success"
else
  echo "✗ Check should return zero exit code on success"
  exit 1
fi

# Test 10: Check rejects .age suffix in argument
echo "--- Test 10: Check rejects .age suffix ---"
if ! check_suffix=$(agenix check secret1.age 2>&1); then
  if echo "$check_suffix" | grep -q "ends with '.age'"; then
    echo "✓ Check correctly rejects .age suffix"
  else
    echo "✗ Check failed with unexpected error: $check_suffix"
    exit 1
  fi
else
  echo "✗ Check should have rejected .age suffix"
  exit 1
fi

# Test 11: Check nonexistent secret name fails with helpful error
echo "--- Test 11: Nonexistent secret name ---"
if ! agenix check nonexistent-secret 2>/dev/null; then
  echo "✓ Check fails for nonexistent secret name"
else
  echo "✗ Check should fail for nonexistent secret name"
  exit 1
fi

# Test 12: Check empty rules shows appropriate message
echo "--- Test 12: Empty rules file ---"
EMPTY_RULES="$TMPDIR/empty-check-rules.nix"
echo "{ }" > "$EMPTY_RULES"
empty_output=$(agenix check --secrets-nix "$EMPTY_RULES" 2>&1)
if echo "$empty_output" | grep -q "No secrets defined"; then
  echo "✓ Check shows message for empty rules"
else
  echo "✗ Check failed to handle empty rules"
  exit 1
fi

# Test 13: Check multiple invalid secrets shows count
echo "--- Test 13: Multiple invalid secrets count ---"
MULTI_RULES="$TMPDIR/multi-check-rules.nix"
MULTI_SECRET1="$TMPDIR/multi-invalid1.age"
MULTI_SECRET2="$TMPDIR/multi-invalid2.age"
cat > "$MULTI_RULES" << EOF
{
  "$MULTI_SECRET1" = {
    publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
  };
  "$MULTI_SECRET2" = {
    publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
  };
}
EOF
echo "invalid1" > "$MULTI_SECRET1"
echo "invalid2" > "$MULTI_SECRET2"
multi_output=$(agenix check --secrets-nix "$MULTI_RULES" 2>&1 || true)
if echo "$multi_output" | grep -q "2 of 2"; then
  echo "✓ Check shows correct count for multiple failures"
else
  echo "✗ Check failed to show correct count"
  exit 1
fi

# Test 14: Check shows OK for valid secrets
echo "--- Test 14: OK for valid secrets ---"
if echo "$check_output" | grep -q "OK"; then
  echo "Test passed: Check shows OK for valid secrets"
else
  echo "Test failed: Check did not show OK"
  exit 1
fi

echo ""
echo "All check tests passed!"
