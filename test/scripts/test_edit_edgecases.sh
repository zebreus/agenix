#!/usr/bin/env bash
# Test: Edit command edge cases

source "$(dirname "$0")/common_setup.sh"

echo "=== Test: Edit command edge cases ==="

# Setup test directory where secrets will be created
EDIT_EDGE_TEST_DIR="$TMPDIR/edit-edge-test"
mkdir -p "$EDIT_EDGE_TEST_DIR"
cd "$EDIT_EDGE_TEST_DIR"

# Create a temporary rules file
TEMP_RULES="$EDIT_EDGE_TEST_DIR/temp-secrets.nix"

# Test 1: Edit with --force on undecryptable file should start with empty content
echo "--- Test 1: Edit --force on undecryptable file ---"
FORCE_SECRET="force-edit"

cat > "$TEMP_RULES" << EOF
{
  "$FORCE_SECRET" = {
    publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
  };
}
EOF

# First create a valid secret
echo "original-content" | agenix encrypt --secrets-nix "$TEMP_RULES" "$FORCE_SECRET"

# Now corrupt it (write garbage)
echo "not-valid-age-format" > "${FORCE_SECRET}.age"

# Try to edit without --force (should fail)
if EDITOR="echo 'new-content' >" agenix edit --secrets-nix "$TEMP_RULES" "$FORCE_SECRET" 2>/dev/null; then
  echo "✗ Edit should fail on corrupted file without --force"
  exit 1
else
  echo "✓ Edit correctly fails on corrupted file without --force"
fi

# Try with --force (should succeed, starting fresh)
EDITOR="echo 'force-content' >" agenix edit --secrets-nix "$TEMP_RULES" --force "$FORCE_SECRET"
decrypted=$(agenix decrypt --secrets-nix "$TEMP_RULES" "$FORCE_SECRET")
if [ "$decrypted" = "force-content" ]; then
  echo "✓ Edit --force works on corrupted file"
else
  echo "✗ Edit --force failed: got '$decrypted'"
  exit 1
fi

# Test 2: Edit creates new file when it doesn't exist
echo "--- Test 2: Edit creates new file ---"
NEW_EDIT_SECRET="new-edit"
cat > "$TEMP_RULES" << EOF
{
  "$NEW_EDIT_SECRET" = {
    publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
  };
}
EOF

# Ensure file doesn't exist
rm -f "${NEW_EDIT_SECRET}.age"

EDITOR="echo 'created-by-edit' >" agenix edit --secrets-nix "$TEMP_RULES" "$NEW_EDIT_SECRET"

if [ -f "${NEW_EDIT_SECRET}.age" ]; then
  decrypted=$(agenix decrypt --secrets-nix "$TEMP_RULES" "$NEW_EDIT_SECRET")
  if [ "$decrypted" = "created-by-edit" ]; then
    echo "✓ Edit creates new file"
  else
    echo "✗ Edit created file with wrong content: '$decrypted'"
    exit 1
  fi
else
  echo "✗ Edit did not create new file"
  exit 1
fi

# Test 3: Edit preserves content when editor makes no changes
echo "--- Test 3: Edit skips re-encryption when unchanged ---"
UNCHANGED_SECRET="unchanged"
cat > "$TEMP_RULES" << EOF
{
  "$UNCHANGED_SECRET" = {
    publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
  };
}
EOF

echo "original" | agenix encrypt --secrets-nix "$TEMP_RULES" "$UNCHANGED_SECRET"
original_hash=$(sha256sum "${UNCHANGED_SECRET}.age" | cut -d' ' -f1)

# Use cat as editor (makes no changes)
EDITOR="cat" agenix edit --secrets-nix "$TEMP_RULES" "$UNCHANGED_SECRET" 2>&1 | grep -q "wasn't changed"
if [ $? -eq 0 ]; then
  echo "✓ Edit detects unchanged content"
else
  echo "✗ Edit did not detect unchanged content"
  exit 1
fi

# Test 4: Edit short alias 'e' works
echo "--- Test 4: Short alias 'e' ---"
ALIAS_SECRET="alias-edit"
cat > "$TEMP_RULES" << EOF
{
  "$ALIAS_SECRET" = {
    publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
  };
}
EOF

EDITOR="echo 'alias-test' >" agenix e --secrets-nix "$TEMP_RULES" "$ALIAS_SECRET"
decrypted=$(agenix decrypt --secrets-nix "$TEMP_RULES" "$ALIAS_SECRET")
if [ "$decrypted" = "alias-test" ]; then
  echo "✓ Short alias 'e' works"
else
  echo "✗ Short alias 'e' failed"
  exit 1
fi

# Test 5: Edit with file not in rules should fail
echo "--- Test 5: File not in rules ---"
cat > "$TEMP_RULES" << EOF
{
  "some-other-secret" = {
    publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
  };
}
EOF

if EDITOR="echo test >" agenix edit --secrets-nix "$TEMP_RULES" "not-in-rules" 2>/dev/null; then
  echo "✗ Edit should fail for file not in rules"
  exit 1
else
  echo "✓ Edit correctly fails for file not in rules"
fi

# Test 6: Edit with failing editor should not modify file
echo "--- Test 6: Failing editor ---"
FAILING_SECRET="failing-edit"
cat > "$TEMP_RULES" << EOF
{
  "$FAILING_SECRET" = {
    publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
  };
}
EOF

echo "original" | agenix encrypt --secrets-nix "$TEMP_RULES" "$FAILING_SECRET"
original_content=$(agenix decrypt --secrets-nix "$TEMP_RULES" "$FAILING_SECRET")

# Use an editor that exits with error
if EDITOR="false" agenix edit --secrets-nix "$TEMP_RULES" "$FAILING_SECRET" 2>/dev/null; then
  echo "✗ Edit should fail when editor exits with error"
  exit 1
fi

# Verify content unchanged
current_content=$(agenix decrypt --secrets-nix "$TEMP_RULES" "$FAILING_SECRET")
if [ "$current_content" = "$original_content" ]; then
  echo "✓ Edit preserves content when editor fails"
else
  echo "✗ Edit modified content despite editor failure"
  exit 1
fi

echo ""
echo "All edit edge case tests passed!"

cd "$HOME/secrets"
