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

    # Create a setup hook for shells to source completions
    # This helps shells find completions when using nix develop
    mkdir -p $out/nix-support
    cat > $out/nix-support/setup-hook <<EOF
    # Add package share directory to XDG_DATA_DIRS for fish completions
    # Fish looks in \$XDG_DATA_DIRS/fish/vendor_completions.d for completions
    if [[ -d "$out/share" ]]; then
      export XDG_DATA_DIRS="$out/share\''${XDG_DATA_DIRS:+:}\''${XDG_DATA_DIRS-}"
    fi

    if [[ -n "\''${ZSH_VERSION-}" ]]; then
      # Add zsh completions to fpath if not already present
      if [[ -d "$out/share/zsh/site-functions" ]]; then
        fpath=("$out/share/zsh/site-functions" \$fpath)
      fi
    fi
    # Only source bash completions in interactive shells where complete is available
    if [[ -n "\''${BASH_VERSION-}" ]] && [[ "\$-" == *i* ]] && type complete &>/dev/null; then
      # Source bash completions
      if [[ -f "$out/share/bash-completion/completions/agenix.bash" ]]; then
        source "$out/share/bash-completion/completions/agenix.bash"
      fi
    fi
    EOF
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
