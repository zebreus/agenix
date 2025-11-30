#!/usr/bin/env bash
# Test: secrets.nix path resolution
# Issue #7: secrets.nix path without ./ prefix should work

source "$(dirname "$0")/common_setup.sh"

echo "=== Test: secrets.nix path resolution ==="

# Test 1: secrets.nix with ./ prefix (should work)
echo "--- Test 1: secrets.nix with ./ prefix ---"
if agenix --secrets-nix ./secrets.nix list >/dev/null 2>&1; then
  echo "✓ secrets.nix with ./ prefix works"
else
  echo "✗ secrets.nix with ./ prefix failed"
  exit 1
fi

# Test 2: secrets.nix without ./ prefix (was broken, should now work)
echo "--- Test 2: secrets.nix without ./ prefix ---"
if agenix --secrets-nix secrets.nix list >/dev/null 2>&1; then
  echo "✓ secrets.nix without ./ prefix works"
else
  echo "✗ secrets.nix without ./ prefix failed"
  exit 1
fi

# Test 3: secrets.nix with absolute path
echo "--- Test 3: secrets.nix with absolute path ---"
ABSOLUTE_PATH="$(pwd)/secrets.nix"
if agenix --secrets-nix "$ABSOLUTE_PATH" list >/dev/null 2>&1; then
  echo "✓ secrets.nix with absolute path works"
else
  echo "✗ secrets.nix with absolute path failed"
  exit 1
fi

# Test 4: secrets.nix with ../ prefix
echo "--- Test 4: secrets.nix with ../ prefix ---"
PARENT_DIR=$(dirname "$(pwd)")
BASE_DIR=$(basename "$(pwd)")
cd "$PARENT_DIR" || exit 1
if agenix --secrets-nix "./$BASE_DIR/secrets.nix" list >/dev/null 2>&1; then
  echo "✓ secrets.nix with parent directory reference works"
  cd - >/dev/null || exit 1
else
  echo "✗ secrets.nix with parent directory reference failed"
  cd - >/dev/null || exit 1
  exit 1
fi

# Test 5: SECRETS_NIX env var without ./ prefix
echo "--- Test 5: SECRETS_NIX env var without ./ prefix ---"
if SECRETS_NIX=secrets.nix agenix list >/dev/null 2>&1; then
  echo "✓ SECRETS_NIX env var without ./ prefix works"
else
  echo "✗ SECRETS_NIX env var without ./ prefix failed"
  exit 1
fi

echo ""
echo "All secrets.nix path tests passed!"
