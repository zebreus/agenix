#!/usr/bin/env bash
# Test: Generator dependency edge cases
# Tests error handling when dependencies don't provide expected outputs

source "$(dirname "$0")/common_setup.sh"

echo "=== Test: Generator dependency edge cases ==="

# Create a temporary directory for this test
mkdir -p "$TMPDIR/dep-edge-cases"
cd "$TMPDIR/dep-edge-cases"

# Test 1: Dependency needs secret but generator only provides public
echo "--- Test 1: Dependency needs secret but only public available ---"
cat > "public-only-dep.nix" << 'EOF'
{
  "base.age" = {
    publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
    generator = {}: { public = "base-public-only"; };
  };
  "derived.age" = {
    publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
    dependencies = [ "base" ];
    generator = { secrets }: "needs-" + secrets."base";
  };
}
EOF

set +e
output=$(agenix generate --secrets-nix "$TMPDIR/dep-edge-cases/public-only-dep.nix" 2>&1)
exit_code=$?
set -e

if [ $exit_code -ne 0 ]; then
  echo "✓ Test 1: Correctly failed when dependency only provides public but secret needed"
  if echo "$output" | grep -qi "base\|secret"; then
    echo "✓ Test 1: Error message mentions relevant dependency"
  else
    echo "  Note: Error message: $output"
  fi
else
  echo "✗ Test 1: Should have failed but succeeded"
  exit 1
fi

# Test 2: Dependency needs public but generator only provides secret
echo "--- Test 2: Dependency needs public but only secret available ---"

# Clean up any leftover files from previous tests
rm -f "$TMPDIR/dep-edge-cases/"*.age "$TMPDIR/dep-edge-cases/"*.pub

cat > "secret-only-dep.nix" << 'EOF'
{
  "base.age" = {
    publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
    generator = {}: { secret = "base-secret-only"; };
  };
  "derived.age" = {
    publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
    dependencies = [ "base" ];
    generator = { publics }: "needs-" + publics."base";
  };
}
EOF

set +e
output=$(agenix generate --secrets-nix "$TMPDIR/dep-edge-cases/secret-only-dep.nix" 2>&1)
exit_code=$?
set -e

if [ $exit_code -ne 0 ]; then
  echo "✓ Test 2: Correctly failed when dependency only provides secret but public needed"
  if echo "$output" | grep -qi "base\|public"; then
    echo "✓ Test 2: Error message mentions relevant dependency"
  else
    echo "  Note: Error message: $output"
  fi
else
  echo "✗ Test 2: Should have failed but succeeded"
  exit 1
fi

# Test 3: Empty attrset generator fails
echo "--- Test 3: Empty attrset generator fails ---"

# Clean up any leftover files from previous tests
rm -f "$TMPDIR/dep-edge-cases/"*.age "$TMPDIR/dep-edge-cases/"*.pub

cat > "empty-attrset.nix" << 'EOF'
{
  "empty.age" = {
    publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
    generator = {}: { };
  };
}
EOF

set +e
output=$(agenix generate --secrets-nix "$TMPDIR/dep-edge-cases/empty-attrset.nix" 2>&1)
exit_code=$?
set -e

if [ $exit_code -ne 0 ]; then
  echo "✓ Test 3: Empty attrset correctly fails"
  if echo "$output" | grep -qi "secret\|public"; then
    echo "✓ Test 3: Error message mentions required keys"
  else
    echo "  Note: Error message: $output"
  fi
else
  echo "✗ Test 3: Empty attrset should have failed but succeeded"
  exit 1
fi

# Test 4: Unknown key only fails
echo "--- Test 4: Unknown key only fails ---"

# Clean up any leftover files from previous tests
rm -f "$TMPDIR/dep-edge-cases/"*.age "$TMPDIR/dep-edge-cases/"*.pub

cat > "unknown-key.nix" << 'EOF'
{
  "unknown.age" = {
    publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
    generator = {}: { unknown_key = "some-value"; };
  };
}
EOF

set +e
output=$(agenix generate --secrets-nix "$TMPDIR/dep-edge-cases/unknown-key.nix" 2>&1)
exit_code=$?
set -e

if [ $exit_code -ne 0 ]; then
  echo "✓ Test 4: Unknown key only correctly fails"
  if echo "$output" | grep -qi "secret\|public"; then
    echo "✓ Test 4: Error message mentions required keys"
  else
    echo "  Note: Error message: $output"
  fi
else
  echo "✗ Test 4: Unknown key only should have failed but succeeded"
  exit 1
fi

# Test 5: Valid public-only with dependent succeeds
echo "--- Test 5: Valid public-only chain succeeds ---"

# Clean up any leftover files from previous tests
rm -f "$TMPDIR/dep-edge-cases/"*.age "$TMPDIR/dep-edge-cases/"*.pub

cat > "valid-public-chain.nix" << 'EOF'
{
  "meta.age" = {
    publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
    generator = {}: { public = "metadata-v1"; };
  };
  "config.age" = {
    publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
    dependencies = [ "meta" ];
    generator = { publics }: { secret = "config-" + publics."meta"; public = "config-pub"; };
  };
}
EOF

set +e
output=$(agenix generate --secrets-nix "$TMPDIR/dep-edge-cases/valid-public-chain.nix" 2>&1)
exit_code=$?
set -e

if [ $exit_code -eq 0 ]; then
  echo "✓ Test 5: Valid public-only chain succeeds"
  if [ -f "meta.age.pub" ] && [ ! -f "meta.age" ]; then
    echo "✓ Test 5: meta has only .pub file"
  else
    echo "✗ Test 5: meta file state incorrect"
    exit 1
  fi
  if [ -f "config.age" ] && [ -f "config.age.pub" ]; then
    echo "✓ Test 5: config has both files"
  else
    echo "✗ Test 5: config file state incorrect"
    exit 1
  fi
else
  echo "✗ Test 5: Valid chain should have succeeded: $output"
  exit 1
fi

echo "=== All generator dependency edge case tests passed ==="
cd "$HOME/secrets"
