# This is the secrets configuration file for the UX test
# It defines which public keys can decrypt which secrets
let
  # In a real scenario, these would be the actual public keys
  # For testing, we use the test keys from the example_keys directory
  system1 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPJDyIr/FSz1cJdcoW69R+NrWzwGK/+3gJpqD1t8L2zE";
  user1 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH";
  allKeys = [
    system1
    user1
  ];
in
{
  # Scenario 1: Gitea self-hosted application
  "gitea-db-password.age".publicKeys = allKeys;
  "gitea-admin-password.age".publicKeys = allKeys;
  "gitea-secret-key.age".publicKeys = allKeys;

  # Scenario 2: SSH deployment keys
  "deploy-ssh-key.age".publicKeys = allKeys;

  # Scenario 3: Shared secrets
  "shared-api-token.age".publicKeys = allKeys;
  "shared-db-password.age".publicKeys = allKeys;

  # Scenario 4: User-level secrets
  "user-github-token.age".publicKeys = [ user1 ];
  "user-ssh-key.age".publicKeys = [ user1 ];
}
