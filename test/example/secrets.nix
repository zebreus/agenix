let
  user1 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH";
  system1 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPJDyIr/FSz1cJdcoW69R+NrWzwGK/+3gJpqD1t8L2zE";
in
{
  "secret1".publicKeys = [
    user1
    system1
  ];
  "secret2".publicKeys = [ user1 ];
  "passwordfile-user1".publicKeys = [
    user1
    system1
  ];
  "-leading-hyphen-filename".publicKeys = [
    user1
    system1
  ];
  "armored-secret" = {
    publicKeys = [ user1 ];
    armor = true;
  };
  "secret-with-public" = {
    publicKeys = [
      user1
      system1
    ];
    generator =
      { }:
      {
        secret = "my-secret-private-key";
        public = "my-public-key-content";
      };
  };
}
