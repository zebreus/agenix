#!/usr/bin/env bash
# Test: Completions command - Extensive tests

source "$(dirname "$0")/common_setup.sh"

echo "=== Test: Completions command ==="

# Test 1: Bash completions
echo "--- Test 1: Bash completions ---"
bash_completions=$(agenix completions bash 2>&1)
if echo "$bash_completions" | grep -q "_agenix"; then
  echo "✓ Bash completions work"
else
  echo "✗ Bash completions failed"
  exit 1
fi

# Test 2: Zsh completions
echo "--- Test 2: Zsh completions ---"
zsh_completions=$(agenix completions zsh 2>&1)
if echo "$zsh_completions" | grep -q "agenix"; then
  echo "✓ Zsh completions work"
else
  echo "✗ Zsh completions failed"
  exit 1
fi

# Test 3: Fish completions
echo "--- Test 3: Fish completions ---"
fish_completions=$(agenix completions fish 2>&1)
if echo "$fish_completions" | grep -q "agenix"; then
  echo "✓ Fish completions work"
else
  echo "✗ Fish completions failed"
  exit 1
fi

# Test 4: Elvish completions
echo "--- Test 4: Elvish completions ---"
elvish_completions=$(agenix completions elvish 2>&1)
if echo "$elvish_completions" | grep -q "agenix"; then
  echo "✓ Elvish completions work"
else
  echo "✗ Elvish completions failed"
  exit 1
fi

# Test 5: Powershell completions
echo "--- Test 5: Powershell completions ---"
pwsh_completions=$(agenix completions powershell 2>&1)
if echo "$pwsh_completions" | grep -q "agenix"; then
  echo "✓ Powershell completions work"
else
  echo "✗ Powershell completions failed"
  exit 1
fi

# Test 6: Invalid shell name fails
echo "--- Test 6: Invalid shell name ---"
if agenix completions invalidshell 2>/dev/null; then
  echo "✗ Should fail for invalid shell name"
  exit 1
else
  echo "✓ Correctly fails for invalid shell name"
fi

# Test 7: Missing shell argument fails
echo "--- Test 7: Missing shell argument ---"
if agenix completions 2>/dev/null; then
  echo "✗ Should fail when shell argument is missing"
  exit 1
else
  echo "✓ Correctly fails when shell argument is missing"
fi

# Test 8: Bash completions include subcommands
echo "--- Test 8: Bash completions include subcommands ---"
if echo "$bash_completions" | grep -q "edit"; then
  echo "✓ Bash completions include edit subcommand"
else
  echo "✗ Bash completions missing edit subcommand"
  exit 1
fi

# Test 9: Bash completions include list subcommand
echo "--- Test 9: Bash completions include list ---"
if echo "$bash_completions" | grep -q "list"; then
  echo "✓ Bash completions include list subcommand"
else
  echo "✗ Bash completions missing list subcommand"
  exit 1
fi

# Test 10: Bash completions include check subcommand
echo "--- Test 10: Bash completions include check ---"
if echo "$bash_completions" | grep -q "check"; then
  echo "✓ Bash completions include check subcommand"
else
  echo "✗ Bash completions missing check subcommand"
  exit 1
fi

# Test 11: Zsh completions include subcommands
echo "--- Test 11: Zsh completions include subcommands ---"
if echo "$zsh_completions" | grep -q "edit"; then
  echo "✓ Zsh completions include edit subcommand"
else
  echo "✗ Zsh completions missing edit subcommand"
  exit 1
fi

# Test 12: Fish completions include subcommands
echo "--- Test 12: Fish completions include subcommands ---"
if echo "$fish_completions" | grep -q "edit"; then
  echo "✓ Fish completions include edit subcommand"
else
  echo "✗ Fish completions missing edit subcommand"
  exit 1
fi

# Test 13: Completions can be written to file
echo "--- Test 13: Completions to file ---"
COMP_FILE="$TMPDIR/completions.bash"
agenix completions bash > "$COMP_FILE"
if [ -s "$COMP_FILE" ]; then
  echo "✓ Completions can be written to file"
else
  echo "✗ Failed to write completions to file"
  exit 1
fi

# Test 14: Bash completions are valid bash syntax
echo "--- Test 14: Valid bash syntax ---"
if bash -n "$COMP_FILE" 2>/dev/null; then
  echo "✓ Bash completions have valid syntax"
else
  echo "✗ Bash completions have invalid syntax"
  exit 1
fi

# Test 15: Completions include global flags
echo "--- Test 15: Global flags in completions ---"
if echo "$bash_completions" | grep -q "\-\-rules"; then
  echo "✓ Completions include --rules flag"
else
  echo "✗ Completions missing --rules flag"
  exit 1
fi

echo ""
echo "All completions tests passed!"
