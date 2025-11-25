#!/usr/bin/env bash
# Test: Global identity option with different commands

source "$(dirname "$0")/common_setup.sh"

echo "=== Test: Global identity option with different commands ==="

# Reset secret1.age to known content first (other tests may have modified it)
echo "hello" | agenix edit secret1.age

# Test with decrypt command
decrypted=$(agenix -i "$HOME/.ssh/id_ed25519" --no-system-identities decrypt secret1.age)
if [ "$decrypted" = "hello" ]; then
  echo "✓ Global identity with decrypt works"
else
  echo "✗ Global identity with decrypt failed"
  exit 1
fi

# Test with edit command via stdin
echo "global-identity-test" | agenix -i "$HOME/.ssh/id_ed25519" --no-system-identities edit secret1.age
decrypted=$(agenix -i "$HOME/.ssh/id_ed25519" --no-system-identities decrypt secret1.age)
if [ "$decrypted" = "global-identity-test" ]; then
  echo "✓ Global identity with edit works"
else
  echo "✗ Global identity with edit failed"
  exit 1
fi

# Reset secret1.age back to original state
echo "hello" | agenix edit secret1.age

echo "✓ All global identity tests passed"
