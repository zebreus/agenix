let
  user1 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH";
  system1 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPJDyIr/FSz1cJdcoW69R+NrWzwGK/+3gJpqD1t8L2zE";
in
{
  # Generate a simple password first
  "db-password.age" = {
    publicKeys = [
      user1
      system1
    ];
    generator = context: builtins.randomString 32;
  };

  # Generate an SSH key
  "deploy-key.age" = {
    publicKeys = [
      user1
      system1
    ];
    generator = context: builtins.sshKey { };
  };

  # Use the password from the first secret in this secret
  "config.age" = {
    publicKeys = [
      user1
      system1
    ];
    generator =
      context: ''
        database_url=postgres://user:${context.secrets."db-password.age"}@localhost/db
        deploy_key_public=${context.publics."deploy-key.age"}
      '';
  };

  # Demonstrate accessing both secrets and publics
  "summary.age" = {
    publicKeys = [
      user1
      system1
    ];
    generator = context: {
      secret = "DB Password: ${context.secrets."db-password.age"}";
      public = "Deploy Key: ${context.publics."deploy-key.age"}";
    };
  };
}
