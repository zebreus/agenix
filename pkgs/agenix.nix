{
  lib,
  rustPlatform,
  installShellFiles,
  asciidoctor,
}:
let
  bin = "${placeholder "out"}/bin/agenix";
in
rustPlatform.buildRustPackage rec {
  pname = "agenix";
  version = "0.1.0";
  src = lib.cleanSource ./.;
  cargoLock = {
    lockFile = ./Cargo.lock;
    outputHashes = {
      "snix-eval-0.1.0" = "sha256-Y/nbqO7LbQA83K/FD093D6MdVuAk/9JqiccPImNWumw=";
    };
  };

  nativeBuildInputs = [
    installShellFiles
    asciidoctor
  ];

  postInstall = ''
    # Generate and install shell completions
    installShellCompletion --cmd agenix \
      --bash <($out/bin/agenix completions bash) \
      --zsh <($out/bin/agenix completions zsh) \
      --fish <($out/bin/agenix completions fish)

    # Generate and install manpage
    asciidoctor -b manpage -o agenix.1 ./readme.adoc
    installManPage agenix.1
  '';

  doInstallCheck = true;

  postInstallCheck = ''
    ${bin} -h | grep ${version}

    test_tmp=$(mktemp -d 2>/dev/null || mktemp -d -t 'mytmpdir')
    export HOME="$test_tmp/home"
    export NIX_STORE_DIR="$test_tmp/nix/store"
    export NIX_STATE_DIR="$test_tmp/nix/var"
    mkdir -p "$HOME" "$NIX_STORE_DIR" "$NIX_STATE_DIR"
    function cleanup {
      rm -rf "$test_tmp"
    }
    trap "cleanup" 0 2 3 15

    mkdir -p $HOME/.ssh
    cp -r "${../test/example}" $HOME/secrets
    chmod -R u+rw $HOME/secrets
    (
    umask u=rw,g=r,o=r
    cp ${../test/example_keys/user1.pub} $HOME/.ssh/id_ed25519.pub
    chown $UID $HOME/.ssh/id_ed25519.pub
    )
    (
    umask u=rw,g=,o=
    cp ${../test/example_keys/user1} $HOME/.ssh/id_ed25519
    chown $UID $HOME/.ssh/id_ed25519
    )

    cd $HOME/secrets
    test "$(${bin} decrypt secret1.age)" = "hello"
  '';

  meta.description = "age-encrypted secrets for NixOS";
}
