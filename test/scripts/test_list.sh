#!/usr/bin/env bash
# Test: List command - Extensive tests

source "$(dirname "$0")/common_setup.sh"

echo "=== Test: List command ==="

# Test 1: Basic list - just outputs secret names (no status by default)
echo "--- Test 1: Basic list ---"
list_output=$(agenix list 2>&1)
if echo "$list_output" | grep -q "secret1"; then
  echo "✓ List shows secrets"
else
  echo "✗ List failed to show secrets"
  exit 1
fi

# Test 2: Basic list should NOT show summary (new behavior)
echo "--- Test 2: Basic list without summary ---"
if echo "$list_output" | grep -q "Total:"; then
  echo "✗ Basic list should not show summary by default"
  exit 1
else
  echo "✓ Basic list does not show summary"
fi

# Test 3: List with --status shows summary
echo "--- Test 3: List with --status shows summary ---"
status_output=$(agenix list --status 2>&1)
if echo "$status_output" | grep -q "Total:"; then
  echo "✓ List --status shows summary"
else
  echo "✗ List --status failed to show summary"
  exit 1
fi

# Test 4: Short alias 'l' works
echo "--- Test 4: Short alias 'l' ---"
alias_output=$(agenix l 2>&1)
if echo "$alias_output" | grep -q "secret1"; then
  echo "✓ Short alias 'l' works"
else
  echo "✗ Short alias 'l' failed"
  exit 1
fi

# Test 5: List with custom secrets.nix
echo "--- Test 5: Custom secrets.nix ---"
TEMP_RULES="$TMPDIR/custom-secrets.nix"
cat > "$TEMP_RULES" << EOF
{
  "$TMPDIR/custom-secret.age" = {
    publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
  };
}
EOF
custom_output=$(agenix list --secrets-nix "$TEMP_RULES" 2>&1)
if echo "$custom_output" | grep -q "custom-secret"; then
  echo "✓ List works with custom secrets.nix"
else
  echo "✗ List with custom secrets.nix failed"
  exit 1
fi

# Test 6: List --status shows MISSING status for nonexistent file
echo "--- Test 6: Missing file status ---"
custom_status=$(agenix list --status --secrets-nix "$TEMP_RULES" 2>&1)
if echo "$custom_status" | grep -q "MISSING"; then
  echo "✓ List --status shows MISSING status for nonexistent file"
else
  echo "✗ List --status failed to show MISSING status"
  exit 1
fi

# Test 7: List nonexistent secrets.nix fails with helpful error
echo "--- Test 7: Nonexistent secrets.nix ---"
if ! agenix list --secrets-nix "/nonexistent/path/secrets.nix" 2>/dev/null; then
  echo "✓ List fails on nonexistent secrets.nix"
else
  echo "✗ List should fail on nonexistent secrets.nix"
  exit 1
fi

# Test 8: List with invalid nix syntax fails
echo "--- Test 8: Invalid nix syntax ---"
INVALID_RULES="$TMPDIR/invalid-secrets.nix"
echo "{ invalid nix syntax !!!" > "$INVALID_RULES"
if agenix list --secrets-nix "$INVALID_RULES" 2>/dev/null; then
  echo "✗ List should fail on invalid nix syntax"
  exit 1
else
  echo "✓ List correctly fails on invalid nix syntax"
fi

# Test 9: Short flag -s for status
echo "--- Test 9: Short flag -s for status ---"
short_status_output=$(agenix list -s 2>&1)
if echo "$short_status_output" | grep -q "Total:"; then
  echo "✓ Short flag -s works for status"
else
  echo "✗ Short flag -s failed"
  exit 1
fi

# Test 10: List empty secrets.nix
echo "--- Test 10: Empty secrets.nix ---"
EMPTY_RULES="$TMPDIR/empty-secrets.nix"
echo "{ }" > "$EMPTY_RULES"
empty_output=$(agenix list --secrets-nix "$EMPTY_RULES" 2>&1)
if echo "$empty_output" | grep -q "No secrets defined"; then
  echo "✓ List shows message for empty secrets.nix"
else
  echo "✗ List failed to handle empty secrets.nix"
  exit 1
fi

# Test 11: List --status with corrupted secret shows NO_DECRYPT
echo "--- Test 11: Corrupted secret status ---"
CORRUPT_RULES="$TMPDIR/corrupt-secrets.nix"
CORRUPT_SECRET="$TMPDIR/corrupt-secret.age"
cat > "$CORRUPT_RULES" << EOF
{
  "$CORRUPT_SECRET" = {
    publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
  };
}
EOF
echo "not-valid-age-content" > "$CORRUPT_SECRET"
corrupt_output=$(agenix list --status --secrets-nix "$CORRUPT_RULES" 2>&1)
if echo "$corrupt_output" | grep -q "NO_DECRYPT"; then
  echo "✓ List --status shows NO_DECRYPT status for corrupted file"
else
  echo "✗ List --status failed to show NO_DECRYPT status"
  exit 1
fi

# Test 12: Basic list output is script-friendly (one secret per line)
# The test/example/secrets.nix file contains exactly 6 secrets:
#   secret1.age, secret2.age, passwordfile-user1.age, -leading-hyphen-filename.age, armored-secret.age, secret-with-public.age
echo "--- Test 12: Script-friendly output ---"
expected_count=6
count=$(agenix list | wc -l)
if [ "$count" -eq "$expected_count" ]; then
  echo "✓ Basic list outputs one secret per line ($expected_count secrets from test/example)"
else
  echo "✗ Basic list output format unexpected (expected $expected_count lines from test/example, got $count)"
  exit 1
fi

echo ""
echo "All list tests passed!"
