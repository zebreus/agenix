# CLI Test Suite for agenix
#
# This test suite treats the agenix CLI as a blackbox, testing only the
# binary interface (commands and outputs). It can be used to verify any
# implementation of the agenix CLI, not just the default one.
#
# To use with an alternative implementation:
#   import ./test/cli.nix {
#     inherit nixpkgs;
#     pkgs = import nixpkgs { };
#     system = "x86_64-linux";
#     agenixPkg = myAlternativeAgenixImplementation;
#   }
#
{
  pkgs ? import <nixpkgs> {
    inherit system;
    config = { };
  },
  system ? builtins.currentSystem,
  # Accept any package that provides an 'agenix' binary
  # This makes the test work with any CLI implementation
  agenixPkg ? pkgs.callPackage ../pkgs/agenix.nix { },
}:
let
  # List of test scripts to run
  testScripts = [
    "test_help.sh"
    "test_decrypt.sh"
    "test_decrypt_explicit_identity.sh"
    "test_decrypt_secret2.sh"
    "test_edit_stdin.sh"
    "test_rekey.sh"
    "test_decrypt_armored.sh"
    "test_decrypt_leading_hyphen.sh"
    "test_explicit_identity_with_bogus.sh"
    "test_age_interop.sh"
    "test_generate_secrets.sh"
    "test_generate_public.sh"
    "test_auto_generate.sh"
    "test_temp_cleanup.sh"
  ];

  # Create a script that runs all tests
  runAllTests = pkgs.writeShellScript "run-all-cli-tests" ''
    set -euo pipefail
    
    # Test setup - create home directory and SSH keys
    export HOME="$TMPDIR/home"
    export TMPDIR="$TMPDIR/agenix-cli-test-tmp"
    mkdir -p $TMPDIR
    mkdir -p "$HOME/.ssh"
    cp ${./example_keys/user1.pub} "$HOME/.ssh/id_ed25519.pub"
    cp ${./example_keys/user1} "$HOME/.ssh/id_ed25519"
    chmod 644 "$HOME/.ssh/id_ed25519.pub"
    chmod 600 "$HOME/.ssh/id_ed25519"

    # Copy example secrets for testing
    cp -r ${./example} "$HOME/secrets"
    chmod -R u+rw "$HOME/secrets"

    # Export the path to test user key for scripts that need it
    export TEST_USER_KEY="${./example_keys/user1}"
    
    cd "$HOME/secrets"

    # Run each test script
    ${builtins.concatStringsSep "\n    " (map (script: ''
      bash ${./scripts}/${script}
    '') testScripts)}

    echo ""
    echo "All CLI tests passed!"
  '';
in
pkgs.runCommand "agenix-cli-test"
  {
    nativeBuildInputs = [
      agenixPkg
      pkgs.age
      pkgs.diffutils
      pkgs.coreutils
    ] ++ pkgs.lib.optionals (!pkgs.stdenv.isDarwin) [
      # unixtools.script is needed for the rekey test on non-Darwin systems
      pkgs.unixtools.script
    ];
  }
  ''
    ${runAllTests}
    touch "$out"
  ''
