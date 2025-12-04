#!/usr/bin/env bash
# Test: Encrypt command edge cases

source "$(dirname "$0")/common_setup.sh"

echo "=== Test: Encrypt command edge cases ==="

# Setup test directory where secrets will be created
EDGE_TEST_DIR="$TMPDIR/encrypt-edge-test"
mkdir -p "$EDGE_TEST_DIR"
cd "$EDGE_TEST_DIR"

# Setup temporary rules file
TEMP_RULES="$EDGE_TEST_DIR/temp-secrets.nix"

# Test 1: Encrypt with empty stdin should succeed
echo "--- Test 1: Empty stdin should succeed ---"
NEW_SECRET="empty-stdin"
cat > "$TEMP_RULES" << EOF
{
  "$NEW_SECRET" = {
    publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
  };
}
EOF

if echo -n "" | agenix encrypt --secrets-nix "$TEMP_RULES" "$NEW_SECRET" 2>/dev/null; then
  # Verify that decryption also produces empty output
  decrypted=$(agenix decrypt --secrets-nix "$TEMP_RULES" "$NEW_SECRET")
  if [ -z "$decrypted" ]; then
    echo "✓ Encrypt and decrypt work with empty content"
  else
    echo "✗ Decrypted content should be empty but got: '$decrypted'"
    exit 1
  fi
else
  echo "✗ Encrypt should succeed with empty stdin"
  exit 1
fi

# Test 2: Encrypt preserves newlines
echo "--- Test 2: Preserve newlines ---"
NEWLINE_SECRET="newline-secret"
cat > "$TEMP_RULES" << EOF
{
  "$NEWLINE_SECRET" = {
    publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
  };
}
EOF

printf "line1\nline2\nline3\n" | agenix encrypt --secrets-nix "$TEMP_RULES" "$NEWLINE_SECRET"
decrypted=$(agenix decrypt --secrets-nix "$TEMP_RULES" "$NEWLINE_SECRET")
expected=$(printf "line1\nline2\nline3\n")
if [ "$decrypted" = "$expected" ]; then
  echo "✓ Encrypt preserves newlines"
else
  echo "✗ Encrypt did not preserve newlines"
  echo "  Expected: $(echo "$expected" | cat -A)"
  echo "  Got: $(echo "$decrypted" | cat -A)"
  exit 1
fi

# Test 3: Encrypt with special characters
echo "--- Test 3: Special characters ---"
SPECIAL_SECRET="special-secret"
cat > "$TEMP_RULES" << EOF
{
  "$SPECIAL_SECRET" = {
    publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
  };
}
EOF

SPECIAL_CONTENT='!@#$%^&*()_+-=[]{}|;:'"'"'",.<>?/\`~'
echo "$SPECIAL_CONTENT" | agenix encrypt --secrets-nix "$TEMP_RULES" "$SPECIAL_SECRET"
decrypted=$(agenix decrypt --secrets-nix "$TEMP_RULES" "$SPECIAL_SECRET")
if [ "$decrypted" = "$SPECIAL_CONTENT" ]; then
  echo "✓ Encrypt handles special characters"
else
  echo "✗ Encrypt failed with special characters"
  exit 1
fi

# Test 4: Encrypt with unicode
echo "--- Test 4: Unicode content ---"
UNICODE_SECRET="unicode-secret"
cat > "$TEMP_RULES" << EOF
{
  "$UNICODE_SECRET" = {
    publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
  };
}
EOF

UNICODE_CONTENT="Hello 世界 🌍 Привет مرحبا"
echo "$UNICODE_CONTENT" | agenix encrypt --secrets-nix "$TEMP_RULES" "$UNICODE_SECRET"
decrypted=$(agenix decrypt --secrets-nix "$TEMP_RULES" "$UNICODE_SECRET")
if [ "$decrypted" = "$UNICODE_CONTENT" ]; then
  echo "✓ Encrypt handles unicode"
else
  echo "✗ Encrypt failed with unicode"
  exit 1
fi

# Test 5: Encrypt with file not in rules should fail
echo "--- Test 5: File not in rules ---"
cat > "$TEMP_RULES" << EOF
{
  "some-other-secret" = {
    publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
  };
}
EOF

if echo "test" | agenix encrypt --secrets-nix "$TEMP_RULES" "not-in-rules" 2>/dev/null; then
  echo "✗ Encrypt should fail for file not in rules"
  exit 1
else
  echo "✓ Encrypt correctly fails for file not in rules"
fi

# Test 6: Short alias 'c' works
echo "--- Test 6: Short alias 'c' ---"
ALIAS_SECRET="alias-secret"
cat > "$TEMP_RULES" << EOF
{
  "$ALIAS_SECRET" = {
    publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
  };
}
EOF

echo "alias-test" | agenix c --secrets-nix "$TEMP_RULES" "$ALIAS_SECRET"
decrypted=$(agenix decrypt --secrets-nix "$TEMP_RULES" "$ALIAS_SECRET")
if [ "$decrypted" = "alias-test" ]; then
  echo "✓ Short alias 'c' works"
else
  echo "✗ Short alias 'c' failed"
  exit 1
fi

# Test 7: Large content
echo "--- Test 7: Large content ---"
LARGE_SECRET="large-secret"
cat > "$TEMP_RULES" << EOF
{
  "$LARGE_SECRET" = {
    publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
  };
}
EOF

# Generate 100KB of random data
LARGE_CONTENT=$(head -c 102400 /dev/urandom | base64)
echo "$LARGE_CONTENT" | agenix encrypt --secrets-nix "$TEMP_RULES" "$LARGE_SECRET"
decrypted=$(agenix decrypt --secrets-nix "$TEMP_RULES" "$LARGE_SECRET")
if [ "$decrypted" = "$LARGE_CONTENT" ]; then
  echo "✓ Encrypt handles large content"
else
  echo "✗ Encrypt failed with large content"
  exit 1
fi

echo ""
echo "All encrypt edge case tests passed!"

cd "$HOME/secrets"
