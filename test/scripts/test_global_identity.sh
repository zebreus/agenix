#!/usr/bin/env bash
# Test: Global identity option with different commands

source "$(dirname "$0")/common_setup.sh"

echo "=== Test: Global identity option with different commands ==="

# Reset secret1.age to known content first (other tests may have modified it)
reset_secret1

# Test with decrypt command
decrypted=$(agenix -i "$HOME/.ssh/id_ed25519" --no-system-identities decrypt secret1)
if [ "$decrypted" = "hello" ]; then
  echo "✓ Global identity with decrypt works"
else
  echo "✗ Global identity with decrypt failed"
  exit 1
fi

# Test with encrypt command via stdin
echo "global-identity-test" | agenix -i "$HOME/.ssh/id_ed25519" --no-system-identities encrypt --force secret1
decrypted=$(agenix -i "$HOME/.ssh/id_ed25519" --no-system-identities decrypt secret1)
if [ "$decrypted" = "global-identity-test" ]; then
  echo "✓ Global identity with encrypt works"
else
  echo "✗ Global identity with encrypt failed"
  exit 1
fi

# Reset secret1.age back to original state
reset_secret1

echo "✓ All global identity tests passed"
