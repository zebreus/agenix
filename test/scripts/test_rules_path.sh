#!/usr/bin/env bash
# Test: Rules file path resolution
# Issue #7: Rules file path without ./ prefix should work

source "$(dirname "$0")/common_setup.sh"

echo "=== Test: Rules path resolution ==="

# Test 1: Rules file with ./ prefix (should work)
echo "--- Test 1: Rules with ./ prefix ---"
if agenix -r ./secrets.nix list >/dev/null 2>&1; then
  echo "✓ Rules with ./ prefix works"
else
  echo "✗ Rules with ./ prefix failed"
  exit 1
fi

# Test 2: Rules file without ./ prefix (was broken, should now work)
echo "--- Test 2: Rules without ./ prefix ---"
if agenix -r secrets.nix list >/dev/null 2>&1; then
  echo "✓ Rules without ./ prefix works"
else
  echo "✗ Rules without ./ prefix failed"
  exit 1
fi

# Test 3: Rules with absolute path
echo "--- Test 3: Rules with absolute path ---"
ABSOLUTE_PATH="$(pwd)/secrets.nix"
if agenix -r "$ABSOLUTE_PATH" list >/dev/null 2>&1; then
  echo "✓ Rules with absolute path works"
else
  echo "✗ Rules with absolute path failed"
  exit 1
fi

# Test 4: Rules with ../ prefix
echo "--- Test 4: Rules with ../ prefix ---"
PARENT_DIR=$(dirname "$(pwd)")
BASE_DIR=$(basename "$(pwd)")
cd "$PARENT_DIR" || exit 1
if agenix -r "./$BASE_DIR/secrets.nix" list >/dev/null 2>&1; then
  echo "✓ Rules with parent directory reference works"
  cd - >/dev/null || exit 1
else
  echo "✗ Rules with parent directory reference failed"
  cd - >/dev/null || exit 1
  exit 1
fi

# Test 5: RULES env var without ./ prefix
echo "--- Test 5: RULES env var without ./ prefix ---"
if RULES=secrets.nix agenix list >/dev/null 2>&1; then
  echo "✓ RULES env var without ./ prefix works"
else
  echo "✗ RULES env var without ./ prefix failed"
  exit 1
fi

echo ""
echo "All rules path tests passed!"
