{
  lib,
  rustPlatform,
  nix,
  age,
  makeWrapper,
}:

rustPlatform.buildRustPackage rec {
  pname = "agenix";
  version = "0.15.0";
  
  src = ./.;

  cargoLock = {
    lockFile = ./Cargo.lock;
  };

  nativeBuildInputs = [ makeWrapper ];
  
  buildInputs = [ ];

  # The Rust binary calls nix-instantiate at runtime
  # We need to make sure it's available in PATH
  postInstall = ''
    wrapProgram $out/bin/agenix \
      --prefix PATH : ${lib.makeBinPath [ nix ]}
  '';

  doCheck = true;

  checkPhase = ''
    cargo test --release
  '';

  doInstallCheck = true;
  
  installCheckPhase = ''
    $out/bin/agenix --help | grep ${version}
    $out/bin/agenix --version | grep ${version}

    # Test decrypt functionality with example files
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
    cp -r "${../example}" $HOME/secrets
    chmod -R u+rw $HOME/secrets
    (
    umask u=rw,g=r,o=r
    cp ${../example_keys/user1.pub} $HOME/.ssh/id_ed25519.pub
    chown $UID $HOME/.ssh/id_ed25519.pub
    )
    (
    umask u=rw,g=,o=
    cp ${../example_keys/user1} $HOME/.ssh/id_ed25519
    chown $UID $HOME/.ssh/id_ed25519
    )

    cd $HOME/secrets
    test $($out/bin/agenix -d secret1.age) = "hello"
  '';

  meta = {
    description = "age-encrypted secrets for NixOS";
    homepage = "https://github.com/ryantm/agenix";
    license = lib.licenses.mit;
    maintainers = with lib.maintainers; [ ryantm ];
  };
}
