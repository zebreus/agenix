# Test suite for lib.nix helper functions
{
  pkgs ? import <nixpkgs> { },
  system ? builtins.currentSystem,
}:

let
  lib = import ../lib.nix;

  # Test cases
  testPublicKeyOf = {
    # Test publicKeyOf with attrset containing public key
    test1 =
      lib.publicKeyOf {
        secret = "private-data";
        public = "public-data";
      } == "public-data";

    # Test publicKeyOf with missing public key - should throw
    test2 =
      builtins.tryEval (lib.publicKeyOf { secret = "only-secret"; }) == {
        success = false;
        value = false;
      };

    # Test publicKeyOf with non-attrset - should throw
    test3 =
      builtins.tryEval (lib.publicKeyOf "not-an-attrset") == {
        success = false;
        value = false;
      };
  };

  testSecretOf = {
    # Test secretOf with attrset
    test1 =
      lib.secretOf {
        secret = "secret-value";
        public = "public-value";
      } == "secret-value";

    # Test secretOf with plain string
    test2 = lib.secretOf "plain-string-secret" == "plain-string-secret";

    # Test secretOf with missing secret key - should throw
    test3 =
      builtins.tryEval (lib.secretOf { public = "only-public"; }) == {
        success = false;
        value = false;
      };
  };

  # Realistic usage scenario
  testRealisticUsage =
    let
      # Simulate what builtins.sshKey {} returns
      mockKeyPair = {
        private = "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----\n";
        public = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMockPublicKey";
      };
      adminKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAdminKey";

      keys = [
        adminKey
        (lib.publicKeyOf mockKeyPair)
      ];
    in
    {
      test1 = builtins.length keys == 2;
      test2 = builtins.elemAt keys 1 == "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMockPublicKey";
    };

  # Collect all test results
  allTests = testPublicKeyOf // testSecretOf // testRealisticUsage;

  # Check if all tests passed
  allTestsPassed = builtins.all (x: x) (builtins.attrValues allTests);

in

pkgs.runCommand "test-agenix-lib" { } ''
  ${
    if allTestsPassed then
      ''
        echo "All lib.nix tests passed!"
        touch $out
      ''
    else
      ''
        echo "Some lib.nix tests failed:"
        ${builtins.concatStringsSep "\n" (
          builtins.map (name: ''echo "  ${name}: ${if allTests.${name} then "PASS" else "FAIL"}"'') (
            builtins.attrNames allTests
          )
        )}
        exit 1
      ''
  }
''
