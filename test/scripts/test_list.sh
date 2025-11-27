#!/usr/bin/env bash
# Test: List command - Extensive tests

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
echo "--- Test 2: List with summary ---"
if echo "$list_output" | grep -q "Total:"; then
  echo "✓ List shows summary"
else
  echo "✗ List failed to show summary"
  exit 1
fi

# Test 3: Detailed list
echo "--- Test 3: Detailed list ---"
detailed_output=$(agenix list --detailed 2>&1)
if echo "$detailed_output" | grep -q "GENERATOR"; then
  echo "✓ Detailed list shows header"
else
  echo "✗ Detailed list failed to show header"
  exit 1
fi

# Test 4: List shows status correctly
echo "--- Test 4: List shows status ---"
if echo "$list_output" | grep -q "✓"; then
  echo "✓ List shows OK status"
else
  echo "✗ List failed to show OK status"
  exit 1
fi

# Test 5: Short alias 'l' works
echo "--- Test 5: Short alias 'l' ---"
alias_output=$(agenix l 2>&1)
if echo "$alias_output" | grep -q "secret1"; then
  echo "✓ Short alias 'l' works"
else
  echo "✗ Short alias 'l' failed"
  exit 1
fi

# Test 6: List with custom rules file
echo "--- Test 6: Custom rules file ---"
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

# Test 7: List shows missing status for nonexistent file
echo "--- Test 7: Missing file status ---"
if echo "$custom_output" | grep -q "○"; then
  echo "✓ List shows missing status for nonexistent file"
else
  echo "✗ List failed to show missing status"
  exit 1
fi

# Test 8: List nonexistent rules file fails with helpful error
echo "--- Test 8: Nonexistent rules file ---"
if ! agenix list -r "/nonexistent/path/rules.nix" 2>/dev/null; then
  echo "✓ List fails on nonexistent rules file"
else
  echo "✗ List should fail on nonexistent rules file"
  exit 1
fi

# Test 9: List with invalid nix syntax fails
echo "--- Test 9: Invalid nix syntax ---"
INVALID_RULES="$TMPDIR/invalid-rules.nix"
echo "{ invalid nix syntax !!!" > "$INVALID_RULES"
if agenix list -r "$INVALID_RULES" 2>/dev/null; then
  echo "✗ List should fail on invalid nix syntax"
  exit 1
else
  echo "✓ List correctly fails on invalid nix syntax"
fi

# Test 10: Detailed list shows ARMOR column
echo "--- Test 10: ARMOR column in detailed view ---"
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

# Test 11: Detailed list shows RECIPS (recipient count) column  
echo "--- Test 11: RECIPS column in detailed view ---"
if echo "$detailed_output" | grep -q "RECIPS"; then
  echo "✓ Detailed list shows RECIPS column"
else
  echo "✗ Detailed list failed to show RECIPS column"
  exit 1
fi

# Test 12: Detailed list shows PUBKEY column
echo "--- Test 12: PUBKEY column in detailed view ---"
if echo "$detailed_output" | grep -q "PUBKEY"; then
  echo "✓ Detailed list shows PUBKEY column"
else
  echo "✗ Detailed list failed to show PUBKEY column"
  exit 1
fi

# Test 13: Short flag -d for detailed
echo "--- Test 13: Short flag -d for detailed ---"
short_detailed_output=$(agenix list -d 2>&1)
if echo "$short_detailed_output" | grep -q "GENERATOR"; then
  echo "✓ Short flag -d works for detailed"
else
  echo "✗ Short flag -d failed"
  exit 1
fi

# Test 14: List empty rules file
echo "--- Test 14: Empty rules file ---"
EMPTY_RULES="$TMPDIR/empty-rules.nix"
echo "{ }" > "$EMPTY_RULES"
empty_output=$(agenix list -r "$EMPTY_RULES" 2>&1)
if echo "$empty_output" | grep -q "No secrets defined"; then
  echo "✓ List shows message for empty rules"
else
  echo "✗ List failed to handle empty rules"
  exit 1
fi

# Test 15: List with corrupted secret shows cannot decrypt
echo "--- Test 15: Corrupted secret status ---"
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
corrupt_output=$(agenix list -r "$CORRUPT_RULES" 2>&1)
if echo "$corrupt_output" | grep -q "✗"; then
  echo "✓ List shows cannot decrypt status for corrupted file"
else
  echo "✗ List failed to show cannot decrypt status"
  exit 1
fi

echo ""
echo "All list tests passed!"
