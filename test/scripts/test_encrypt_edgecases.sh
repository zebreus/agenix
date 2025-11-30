#!/usr/bin/env bash
# Test: Encrypt command edge cases

source "$(dirname "$0")/common_setup.sh"

echo "=== Test: Encrypt command edge cases ==="

# Setup temporary rules file
TEMP_RULES="$TMPDIR/temp-secrets.nix"

# Test 1: Encrypt with empty stdin should fail
echo "--- Test 1: Empty stdin should fail ---"
NEW_SECRET="$TMPDIR/empty-stdin.age"
cat > "$TEMP_RULES" << EOF
{
  "$NEW_SECRET" = {
    publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
  };
}
EOF

if echo -n "" | agenix encrypt --secrets-nix "$TEMP_RULES" "$NEW_SECRET" 2>/dev/null; then
  echo "✗ Encrypt should fail with empty stdin"
  exit 1
else
  echo "✓ Encrypt correctly fails with empty stdin"
fi

# Test 2: Encrypt preserves newlines
echo "--- Test 2: Preserve newlines ---"
NEWLINE_SECRET="$TMPDIR/newline-secret.age"
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
SPECIAL_SECRET="$TMPDIR/special-secret.age"
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
UNICODE_SECRET="$TMPDIR/unicode-secret.age"
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

# Test 5: Encrypt to nonexistent directory should fail gracefully
echo "--- Test 5: Nonexistent directory ---"
cat > "$TEMP_RULES" << EOF
{
  "/nonexistent/directory/secret.age" = {
    publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
  };
}
EOF

if echo "test" | agenix encrypt --secrets-nix "$TEMP_RULES" "/nonexistent/directory/secret.age" 2>/dev/null; then
  echo "✗ Encrypt should fail for nonexistent directory"
  exit 1
else
  echo "✓ Encrypt correctly fails for nonexistent directory"
fi

# Test 6: Encrypt with file not in rules should fail
echo "--- Test 6: File not in rules ---"
cat > "$TEMP_RULES" << EOF
{
  "/some/other/secret.age" = {
    publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
  };
}
EOF

if echo "test" | agenix encrypt --secrets-nix "$TEMP_RULES" "$TMPDIR/not-in-rules.age" 2>/dev/null; then
  echo "✗ Encrypt should fail for file not in rules"
  exit 1
else
  echo "✓ Encrypt correctly fails for file not in rules"
fi

# Test 7: Short alias 'c' works
echo "--- Test 7: Short alias 'c' ---"
ALIAS_SECRET="$TMPDIR/alias-secret.age"
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

# Test 8: Large content
echo "--- Test 8: Large content ---"
LARGE_SECRET="$TMPDIR/large-secret.age"
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
