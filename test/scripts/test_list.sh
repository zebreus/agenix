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

# Test 4: Detailed list shows header
echo "--- Test 4: Detailed list ---"
detailed_output=$(agenix list --detailed 2>&1)
if echo "$detailed_output" | grep -q "GENERATOR"; then
  echo "✓ Detailed list shows header"
else
  echo "✗ Detailed list failed to show header"
  exit 1
fi

# Test 5: List --status shows status codes (OK, MISSING, ERROR)
echo "--- Test 5: List shows status correctly ---"
if echo "$status_output" | grep -q "OK"; then
  echo "✓ List --status shows OK status"
else
  echo "✗ List --status failed to show OK status"
  exit 1
fi

# Test 6: Short alias 'l' works
echo "--- Test 6: Short alias 'l' ---"
alias_output=$(agenix l 2>&1)
if echo "$alias_output" | grep -q "secret1"; then
  echo "✓ Short alias 'l' works"
else
  echo "✗ Short alias 'l' failed"
  exit 1
fi

# Test 7: List with custom rules file
echo "--- Test 7: Custom rules file ---"
TEMP_RULES="$TMPDIR/custom-rules.nix"
cat > "$TEMP_RULES" << EOF
{
  "$TMPDIR/custom-secret.age" = {
    publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
  };
}
EOF
custom_output=$(agenix list -r "$TEMP_RULES" 2>&1)
if echo "$custom_output" | grep -q "custom-secret"; then
  echo "✓ List works with custom rules file"
else
  echo "✗ List with custom rules file failed"
  exit 1
fi

# Test 8: List --status shows MISSING status for nonexistent file
echo "--- Test 8: Missing file status ---"
custom_status=$(agenix list --status -r "$TEMP_RULES" 2>&1)
if echo "$custom_status" | grep -q "MISSING"; then
  echo "✓ List --status shows MISSING status for nonexistent file"
else
  echo "✗ List --status failed to show MISSING status"
  exit 1
fi

# Test 9: List nonexistent rules file fails with helpful error
echo "--- Test 9: Nonexistent rules file ---"
if ! agenix list -r "/nonexistent/path/rules.nix" 2>/dev/null; then
  echo "✓ List fails on nonexistent rules file"
else
  echo "✗ List should fail on nonexistent rules file"
  exit 1
fi

# Test 10: List with invalid nix syntax fails
echo "--- Test 10: Invalid nix syntax ---"
INVALID_RULES="$TMPDIR/invalid-rules.nix"
echo "{ invalid nix syntax !!!" > "$INVALID_RULES"
if agenix list -r "$INVALID_RULES" 2>/dev/null; then
  echo "✗ List should fail on invalid nix syntax"
  exit 1
else
  echo "✓ List correctly fails on invalid nix syntax"
fi

# Test 11: Detailed list shows ARMOR column
echo "--- Test 11: ARMOR column in detailed view ---"
ARMOR_RULES="$TMPDIR/armor-rules.nix"
cat > "$ARMOR_RULES" << EOF
{
  "$TMPDIR/armored.age" = {
    publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
    armor = true;
  };
}
EOF
armor_output=$(agenix list -r "$ARMOR_RULES" --detailed 2>&1)
if echo "$armor_output" | grep -q "ARMOR"; then
  echo "✓ Detailed list shows ARMOR column"
else
  echo "✗ Detailed list failed to show ARMOR column"
  exit 1
fi

# Test 12: Detailed list shows RECIPS (recipient count) column  
echo "--- Test 12: RECIPS column in detailed view ---"
if echo "$detailed_output" | grep -q "RECIPS"; then
  echo "✓ Detailed list shows RECIPS column"
else
  echo "✗ Detailed list failed to show RECIPS column"
  exit 1
fi

# Test 13: Detailed list shows PUBKEY column
echo "--- Test 13: PUBKEY column in detailed view ---"
if echo "$detailed_output" | grep -q "PUBKEY"; then
  echo "✓ Detailed list shows PUBKEY column"
else
  echo "✗ Detailed list failed to show PUBKEY column"
  exit 1
fi

# Test 14: Short flag -d for detailed
echo "--- Test 14: Short flag -d for detailed ---"
short_detailed_output=$(agenix list -d 2>&1)
if echo "$short_detailed_output" | grep -q "GENERATOR"; then
  echo "✓ Short flag -d works for detailed"
else
  echo "✗ Short flag -d failed"
  exit 1
fi

# Test 15: Short flag -s for status
echo "--- Test 15: Short flag -s for status ---"
short_status_output=$(agenix list -s 2>&1)
if echo "$short_status_output" | grep -q "OK"; then
  echo "✓ Short flag -s works for status"
else
  echo "✗ Short flag -s failed"
  exit 1
fi

# Test 16: List empty rules file
echo "--- Test 16: Empty rules file ---"
EMPTY_RULES="$TMPDIR/empty-rules.nix"
echo "{ }" > "$EMPTY_RULES"
empty_output=$(agenix list -r "$EMPTY_RULES" 2>&1)
if echo "$empty_output" | grep -q "No secrets defined"; then
  echo "✓ List shows message for empty rules"
else
  echo "✗ List failed to handle empty rules"
  exit 1
fi

# Test 17: List --status with corrupted secret shows ERROR
echo "--- Test 17: Corrupted secret status ---"
CORRUPT_RULES="$TMPDIR/corrupt-rules.nix"
CORRUPT_SECRET="$TMPDIR/corrupt-secret.age"
cat > "$CORRUPT_RULES" << EOF
{
  "$CORRUPT_SECRET" = {
    publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
  };
}
EOF
echo "not-valid-age-content" > "$CORRUPT_SECRET"
corrupt_output=$(agenix list --status -r "$CORRUPT_RULES" 2>&1)
if echo "$corrupt_output" | grep -q "ERROR"; then
  echo "✓ List --status shows ERROR status for corrupted file"
else
  echo "✗ List --status failed to show ERROR status"
  exit 1
fi

# Test 18: Basic list output is script-friendly (one secret per line)
echo "--- Test 18: Script-friendly output ---"
count=$(agenix list | wc -l)
if [ "$count" -eq 5 ]; then
  echo "✓ Basic list outputs one secret per line"
else
  echo "✗ Basic list output format unexpected (expected 5 lines, got $count)"
  exit 1
fi

echo ""
echo "All list tests passed!"
