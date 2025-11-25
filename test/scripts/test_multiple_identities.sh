#!/usr/bin/env bash
# Test: Multiple identities with -i flag

source "$(dirname "$0")/common_setup.sh"

echo "=== Test: Multiple identities with -i flag ==="

# Test that -i flag works with the known identity
decrypted=$(agenix decrypt secret1.age -i "$HOME/.ssh/id_ed25519" --no-system-identities)
if [ "$decrypted" = "hello" ]; then
  echo "✓ Single identity with --no-system-identities works"
else
  echo "✗ Single identity with --no-system-identities failed"
  exit 1
fi

# Test that the same identity specified multiple times works (deduplication)
decrypted=$(agenix decrypt secret1.age -i "$HOME/.ssh/id_ed25519" -i "$HOME/.ssh/id_ed25519" --no-system-identities)
if [ "$decrypted" = "hello" ]; then
  echo "✓ Same identity specified multiple times works"
else
  echo "✗ Same identity specified multiple times failed"
  exit 1
fi

# Test that -i works after subcommand
decrypted=$(agenix decrypt -i "$HOME/.ssh/id_ed25519" --no-system-identities secret1.age)
if [ "$decrypted" = "hello" ]; then
  echo "✓ Identity flag after subcommand works"
else
  echo "✗ Identity flag after subcommand failed"
  exit 1
fi

echo "✓ All multiple identities tests passed"
