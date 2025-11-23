#!/usr/bin/env bash
# Test 1: Help command

source "$(dirname "$0")/common_setup.sh"

echo "=== Test 1: Help command ==="
# Temporarily disable pipefail for help command which can trigger SIGPIPE
disable_pipefail
help_output=$(agenix --help 2>&1)
enable_pipefail
if echo "$help_output" | grep -q "edit and rekey age secret files"; then
  echo "✓ Help command works"
else
  echo "✗ Help command failed"
  exit 1
fi
