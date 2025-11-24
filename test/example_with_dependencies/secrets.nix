let
  user1 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH";
  system1 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPJDyIr/FSz1cJdcoW69R+NrWzwGK/+3gJpqD1t8L2zE";
in
{
  # Generate an SSH keypair for deployment
  "deploy-key.age" = {
    publicKeys = [
      user1
      system1
    ];
    # This generates an SSH Ed25519 keypair automatically based on the filename
    # It creates both a secret (private key) and public (public key) output
  };

  # Generate a database password
  "db-password.age" = {
    publicKeys = [
      user1
      system1
    ];
    # Automatically generates a 32-character random password based on filename
  };

  # Create an SSH authorized_keys file that includes the deploy key's public key
  "ssh-authorized-keys.age" = {
    publicKeys = [
      user1
      system1
    ];
    generator =
      { publics, ... }:
      # Reference the deploy-key's public output
      # The 'publics' attrset contains public outputs from other secrets
      let
        deployPub = publics."deploy-key" or "# Deploy key not yet generated";
      in
      ''
        # SSH Authorized Keys
        ${deployPub}
      '';
  };

  # Create a config file that uses the database password
  "app-config.age" = {
    publicKeys = [
      user1
      system1
    ];
    generator =
      { secrets, publics, ... }:
      # Reference both secrets and publics from other secrets
      # The 'secrets' attrset contains secret content from other secrets
      let
        dbPass = secrets."db-password" or "MISSING";
        deployPub = publics."deploy-key" or "MISSING";
      in
      ''
        # Application Configuration
        database.password = "${dbPass}"
        deployment.ssh_key = "${deployPub}"
      '';
  };

  # Example with fallback for missing dependencies
  "optional-config.age" = {
    publicKeys = [
      user1
      system1
    ];
    generator =
      { secrets, publics, ... }:
      let
        # Use 'or' to provide defaults if secrets haven't been generated yet
        apiKey = secrets."api-key" or "default-api-key";
        sshKey = publics."deploy-key" or "";
      in
      ''
        api_key=${apiKey}
        ${if sshKey != "" then "ssh_key=${sshKey}" else "# No SSH key configured"}
      '';
  };
}
