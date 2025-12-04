#!/usr/bin/env bash
# Test: --no-system-identities flag

source "$(dirname "$0")/common_setup.sh"

echo "=== Test: --no-system-identities flag ==="

# Reset secret1.age to known content first (other tests may have modified it)
reset_secret1

# With --no-system-identities and no explicit identity, decryption should fail
if agenix decrypt secret1 --no-system-identities 2>/dev/null; then
  echo "✗ Decrypt without any identity should have failed"
  exit 1
else
  echo "✓ Decrypt without any identity correctly failed"
fi

# With --no-system-identities and explicit identity, decryption should succeed
decrypted=$(agenix decrypt secret1 -i "$HOME/.ssh/id_ed25519" --no-system-identities)
if [ "$decrypted" = "hello" ]; then
  echo "✓ Decrypt with explicit identity and --no-system-identities works"
else
  echo "✗ Decrypt with explicit identity and --no-system-identities failed"
  exit 1
fi

echo "✓ All --no-system-identities tests passed"
