#!/usr/bin/env bash
# Test 11.75: Automatic generator selection based on secret endings

source "$(dirname "$0")/common_setup.sh"

echo "=== Test 11.75: Automatic generator selection based on secret endings ==="
# Create a temporary directory for auto-generated secrets
mkdir -p "$TMPDIR/auto-generate-test"
cd "$TMPDIR/auto-generate-test"

# Create a rules file without explicit generators
cat > "auto-generate-secrets.nix" << 'EOF'
{
  "server-ed25519.age" = {
    publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
  };
  "deploy-ssh.age" = {
    publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
  };
  "id_ssh_key.age" = {
    publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
  };
  "identity-x25519.age" = {
    publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
  };
  "database-password.age" = {
    publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
  };
  "backup-passphrase.age" = {
    publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
  };
  "random-secret.age" = {
    publicKeys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH" ];
  };
}
EOF

# Run generate command
agenix generate --secrets-nix "$TMPDIR/auto-generate-test/auto-generate-secrets.nix"

# Check that SSH key files were created with .pub files
if [ -f "server-ed25519.age" ] && [ -f "server-ed25519.age.pub" ]; then
  echo "✓ server-ed25519.age generated with public key"
else
  echo "✗ server-ed25519.age or its public key not generated"
  exit 1
fi

if [ -f "deploy-ssh.age" ] && [ -f "deploy-ssh.age.pub" ]; then
  echo "✓ deploy-ssh.age generated with public key"
else
  echo "✗ deploy-ssh.age or its public key not generated"
  exit 1
fi

if [ -f "id_ssh_key.age" ] && [ -f "id_ssh_key.age.pub" ]; then
  echo "✓ id_ssh_key.age generated with public key"
else
  echo "✗ id_ssh_key.age or its public key not generated"
  exit 1
fi

if [ -f "identity-x25519.age" ] && [ -f "identity-x25519.age.pub" ]; then
  echo "✓ identity-x25519.age generated with public key"
else
  echo "✗ identity-x25519.age or its public key not generated"
  exit 1
fi

# Check that password files were created without .pub files
if [ -f "database-password.age" ] && [ ! -f "database-password.age.pub" ]; then
  echo "✓ database-password.age generated without public key"
else
  echo "✗ database-password.age incorrectly generated"
  exit 1
fi

if [ -f "backup-passphrase.age" ] && [ ! -f "backup-passphrase.age.pub" ]; then
  echo "✓ backup-passphrase.age generated without public key"
else
  echo "✗ backup-passphrase.age incorrectly generated"
  exit 1
fi

# Check that file without matching ending was not created
if [ ! -f "random-secret.age" ]; then
  echo "✓ random-secret.age correctly not auto-generated"
else
  echo "✗ random-secret.age was incorrectly auto-generated"
  exit 1
fi

# Verify SSH keys have correct format
ssh_pub=$(cat "server-ed25519.age.pub")
if echo "$ssh_pub" | grep -q "^ssh-ed25519 "; then
  echo "✓ SSH public key has correct format"
else
  echo "✗ SSH public key format incorrect: got '$ssh_pub'"
  exit 1
fi

# Verify age x25519 key has correct format
age_pub=$(cat "identity-x25519.age.pub")
if echo "$age_pub" | grep -q "^age1"; then
  echo "✓ age x25519 public key has correct format"
else
  echo "✗ age x25519 public key format incorrect: got '$age_pub'"
  exit 1
fi

# Verify we can decrypt the auto-generated secrets
# Use TEST_USER_KEY environment variable provided by the test runner
decrypted_ssh=$(agenix decrypt server-ed25519.age --secrets-nix "$TMPDIR/auto-generate-test/auto-generate-secrets.nix" -i "$TEST_USER_KEY" --no-system-identities)
if echo "$decrypted_ssh" | grep -q "BEGIN PRIVATE KEY"; then
  echo "✓ Auto-generated SSH key decrypts correctly"
else
  echo "✗ Auto-generated SSH key decryption failed"
  exit 1
fi

decrypted_x25519=$(agenix decrypt identity-x25519.age --secrets-nix "$TMPDIR/auto-generate-test/auto-generate-secrets.nix" -i "$TEST_USER_KEY" --no-system-identities)
if echo "$decrypted_x25519" | grep -q "^AGE-SECRET-KEY-"; then
  echo "✓ Auto-generated x25519 key decrypts correctly"
else
  echo "✗ Auto-generated x25519 key decryption failed"
  exit 1
fi

decrypted_password=$(agenix decrypt database-password.age --secrets-nix "$TMPDIR/auto-generate-test/auto-generate-secrets.nix" -i "$TEST_USER_KEY" --no-system-identities)
password_len=${#decrypted_password}
if [ "$password_len" = "32" ]; then
  echo "✓ Auto-generated password has correct length (32 chars)"
else
  echo "✗ Auto-generated password has wrong length: got $password_len chars"
  exit 1
fi

cd "$HOME/secrets"
