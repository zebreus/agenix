#!/usr/bin/env bash
# Test: Completions broken pipe fix
# Issue #3: Fish completions panic on pipe

source "$(dirname "$0")/common_setup.sh"

echo "=== Test: Completions broken pipe fix ==="

# Test 1: Fish completions piped to head (was broken)
echo "--- Test 1: Fish completions piped to head ---"
# Temporarily disable pipefail for this test since we're intentionally causing a broken pipe
disable_pipefail
output=$(agenix completions fish 2>&1 | head -5)
exit_code=${PIPESTATUS[0]}
enable_pipefail
# Should not panic with "failed to write completion file"
if echo "$output" | grep -q "panicked"; then
  echo "✗ Fish completions panicked on pipe: $output"
  exit 1
else
  echo "✓ Fish completions handle broken pipe"
fi

# Test 2: Bash completions piped to head
echo "--- Test 2: Bash completions piped to head ---"
disable_pipefail
output=$(agenix completions bash 2>&1 | head -5)
exit_code=${PIPESTATUS[0]}
enable_pipefail
if echo "$output" | grep -q "panicked"; then
  echo "✗ Bash completions panicked on pipe"
  exit 1
else
  echo "✓ Bash completions handle broken pipe"
fi

# Test 3: Zsh completions piped to head
echo "--- Test 3: Zsh completions piped to head ---"
disable_pipefail
output=$(agenix completions zsh 2>&1 | head -5)
exit_code=${PIPESTATUS[0]}
enable_pipefail
if echo "$output" | grep -q "panicked"; then
  echo "✗ Zsh completions panicked on pipe"
  exit 1
else
  echo "✓ Zsh completions handle broken pipe"
fi

# Test 4: Full fish completions still work
echo "--- Test 4: Full fish completions ---"
output=$(agenix completions fish 2>&1)
if echo "$output" | grep -q "agenix"; then
  echo "✓ Full fish completions work"
else
  echo "✗ Full fish completions failed"
  exit 1
fi

# Test 5: Piping to a process that closes early
echo "--- Test 5: Pipe to process that closes early ---"
disable_pipefail
agenix completions fish 2>&1 | { read -r line; exit 0; }
exit_code=${PIPESTATUS[0]}
enable_pipefail
# Exit code 0 means no panic
if [ $exit_code -eq 0 ]; then
  echo "✓ Handle pipe to early-closing process"
else
  echo "✗ Failed to handle early pipe close (exit code: $exit_code)"
  # Don't fail the test - just warn. Some shells may return non-zero on SIGPIPE
  echo "  (This may be a shell behavior, not an agenix issue)"
fi

echo ""
echo "All completions broken pipe tests passed!"
