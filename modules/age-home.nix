{
  config,
  options,
  lib,
  pkgs,
  ...
}:
with lib;
let
  cfg = config.age;

  ageBin = lib.getExe config.age.package;

  newGeneration = ''
    _agenix_generation="$(basename "$(readlink "${cfg.secretsDir}")" || echo 0)"
    (( ++_agenix_generation ))
    echo "[agenix] creating new generation in ${cfg.secretsMountPoint}/$_agenix_generation"
    mkdir -p "${cfg.secretsMountPoint}"
    chmod 0751 "${cfg.secretsMountPoint}"
    mkdir -p "${cfg.secretsMountPoint}/$_agenix_generation"
    chmod 0751 "${cfg.secretsMountPoint}/$_agenix_generation"
  '';

  setTruePath = secretType: ''
    ${
      if secretType.symlink then
        ''
          _truePath="${cfg.secretsMountPoint}/$_agenix_generation/${secretType.name}"
        ''
      else
        ''
          _truePath="${secretType.path}"
        ''
    }
  '';

  installSecret = secretType: ''
    ${setTruePath secretType}
    echo "decrypting '${secretType.file}' to '$_truePath'..."
    TMP_FILE="$_truePath.tmp"

    IDENTITIES=()
    # shellcheck disable=2043
    for identity in ${toString cfg.identityPaths}; do
      test -r "$identity" || continue
      IDENTITIES+=(-i)
      IDENTITIES+=("$identity")
    done

    test "''${#IDENTITIES[@]}" -eq 0 && echo "[agenix] WARNING: no readable identities found!"

    mkdir -p "$(dirname "$_truePath")"
    # shellcheck disable=SC2193,SC2050
    [ "${secretType.path}" != "${cfg.secretsDir}/${secretType.name}" ] && mkdir -p "$(dirname "${secretType.path}")"
    (
      umask u=r,g=,o=
      test -f "${secretType.file}" || echo '[agenix] WARNING: encrypted file ${secretType.file} does not exist!'
      test -d "$(dirname "$TMP_FILE")" || echo "[agenix] WARNING: $(dirname "$TMP_FILE") does not exist!"
      LANG=${
        config.i18n.defaultLocale or "C"
      } ${ageBin} --decrypt "''${IDENTITIES[@]}" -o "$TMP_FILE" "${secretType.file}"
    )
    chmod ${secretType.mode} "$TMP_FILE"
    mv -f "$TMP_FILE" "$_truePath"

    ${optionalString secretType.symlink ''
      # shellcheck disable=SC2193,SC2050
      [ "${secretType.path}" != "${cfg.secretsDir}/${secretType.name}" ] && ln -sfT "${cfg.secretsDir}/${secretType.name}" "${secretType.path}"
    ''}
  '';

  testIdentities = map (path: ''
    test -f ${path} || echo '[agenix] WARNING: config.age.identityPaths entry ${path} not present!'
  '') cfg.identityPaths;

  cleanupAndLink = ''
    _agenix_generation="$(basename "$(readlink "${cfg.secretsDir}")" || echo 0)"
    (( ++_agenix_generation ))
    echo "[agenix] symlinking new secrets to ${cfg.secretsDir} (generation $_agenix_generation)..."
    ln -sfT "${cfg.secretsMountPoint}/$_agenix_generation" "${cfg.secretsDir}"

    (( _agenix_generation > 1 )) && {
    echo "[agenix] removing old secrets (generation $(( _agenix_generation - 1 )))..."
    rm -rf "${cfg.secretsMountPoint}/$(( _agenix_generation - 1 ))"
    }
  '';

  installSecrets = builtins.concatStringsSep "\n" (
    [ "echo '[agenix] decrypting secrets...'" ]
    ++ testIdentities
    ++ (map installSecret (builtins.attrValues cfg.secrets))
    ++ [ cleanupAndLink ]
  );

  # Filter secrets that have public files with installPath set
  secretsWithPublicInstall = builtins.filter (
    s: s.public.file != null && s.public.installPath != null
  ) (builtins.attrValues cfg.secrets);

  # Create public keys directory
  createPublicKeysDir = ''
    echo "[agenix] creating public keys directory..."
    mkdir -p "${cfg.publicKeysDir}"
    chmod 0755 "${cfg.publicKeysDir}"
  '';

  # Install a single public file
  installPublicFile = secretType: ''
    echo "installing public file '${toString secretType.public.file}' to '${secretType.public.installPath}'..."
    ${
      if secretType.public.symlink then
        ''
          mkdir -p "$(dirname "${secretType.public.installPath}")"
          ln -sfT "${secretType.public.file}" "${secretType.public.installPath}"
        ''
      else
        ''
          mkdir -p "$(dirname "${secretType.public.installPath}")"
          install -m "${secretType.public.mode}" "${secretType.public.file}" "${secretType.public.installPath}"
        ''
    }
    ${optionalString secretType.public.symlink ''
      chmod ${secretType.public.mode} "${secretType.public.installPath}"
    ''}
  '';

  # Install all public files
  installPublicFiles = builtins.concatStringsSep "\n" (
    [ createPublicKeysDir ]
    ++ [ "echo '[agenix] installing public files...'" ]
    ++ (map installPublicFile secretsWithPublicInstall)
  );

  secretType = types.submodule (
    {
      config,
      name,
      ...
    }:
    {
      options = {
        name = mkOption {
          type = types.str;
          default = name;
          description = ''
            Name of the file used in ''${cfg.secretsDir}
          '';
        };
        file = mkOption {
          type = types.path;
          description = ''
            Age file the secret is loaded from.
          '';
        };
        path = mkOption {
          type = types.str;
          default = "${cfg.secretsDir}/${config.name}";
          description = ''
            Path where the decrypted secret is installed.
          '';
        };
        public = {
          file = mkOption {
            type = types.nullOr types.path;
            default =
              let
                pubFile = "${toString config.file}.pub";
              in
              if builtins.pathExists pubFile then pubFile else null;
            defaultText = literalExpression ''
              if builtins.pathExists "''${config.file}.pub" then "''${config.file}.pub" else null
            '';
            description = ''
              Path to the public file associated with this secret, if it exists.
              This file is created when the generator function returns an attrset
              with both `secret` and `public` keys. This is the source file path
              (in the Nix store).
            '';
          };
          # Kept for backwards compatibility
          path = mkOption {
            type = types.nullOr types.str;
            default = config.public.file;
            defaultText = literalExpression ''
              config.public.file
            '';
            description = ''
              Deprecated: Use `public.file` instead. Path to the public file
              associated with this secret in the Nix store.
            '';
          };
          content = mkOption {
            type = types.nullOr types.str;
            default = if config.public.file != null then builtins.readFile config.public.file else null;
            defaultText = literalExpression ''
              if config.public.file != null then builtins.readFile config.public.file else null
            '';
            description = ''
              Content of the public file associated with this secret, if it exists.
              This is the content of the `.pub` file created when the generator
              function returns an attrset with both `secret` and `public` keys.
            '';
          };
          installPath = mkOption {
            type = types.nullOr types.str;
            default = null;
            defaultText = literalExpression "null";
            description = ''
              Path where the public file should be installed (symlinked or copied).
              If null, the public file is not installed on the system.
              If set, the public file will be installed at this path.
            '';
          };
          name = mkOption {
            type = types.str;
            default = "${name}.pub";
            defaultText = literalExpression ''"''${name}.pub"'';
            description = ''
              Name of the public file used in {option}`age.publicKeysDir`
            '';
          };
          mode = mkOption {
            type = types.str;
            default = "0444";
            description = ''
              Permissions mode of the installed public file in a format understood by chmod.
              Public files are typically world-readable by default.
            '';
          };
          symlink = mkEnableOption "symlinking public files to their destination" // {
            default = true;
          };
        };
        mode = mkOption {
          type = types.str;
          default = "0400";
          description = ''
            Permissions mode of the decrypted secret in a format understood by chmod.
          '';
        };
        symlink = mkEnableOption "symlinking secrets to their destination" // {
          default = true;
        };
      };
    }
  );

  mountingScript =
    let
      app = pkgs.writeShellApplication {
        name = "agenix-home-manager-mount-secrets";
        runtimeInputs = with pkgs; [ coreutils ];
        text = ''
          ${newGeneration}
          ${installSecrets}
          ${installPublicFiles}
          exit 0
        '';
      };
    in
    lib.getExe app;

  userDirectory =
    dir:
    let
      inherit (pkgs.stdenv.hostPlatform) isDarwin;
      baseDir =
        if isDarwin then "$(${lib.getExe pkgs.getconf} DARWIN_USER_TEMP_DIR)" else "\${XDG_RUNTIME_DIR}";
    in
    "${baseDir}/${dir}";

  userDirectoryDescription =
    dir:
    literalExpression ''
      "''${XDG_RUNTIME_DIR}"/''${dir} on linux or "$(getconf DARWIN_USER_TEMP_DIR)"/''${dir} on darwin.
    '';
in
{
  options.age = {
    package = mkPackageOption pkgs "age" { };

    secrets = mkOption {
      type = types.attrsOf secretType;
      default = { };
      description = ''
        Attrset of secrets.
      '';
    };

    identityPaths = mkOption {
      type = types.listOf types.path;
      default = [
        "${config.home.homeDirectory}/.ssh/id_ed25519"
        "${config.home.homeDirectory}/.ssh/id_rsa"
      ];
      defaultText = literalExpression ''
        [
          "''${config.home.homeDirectory}/.ssh/id_ed25519"
          "''${config.home.homeDirectory}/.ssh/id_rsa"
        ]
      '';
      description = ''
        Path to SSH keys to be used as identities in age decryption.
      '';
    };

    secretsDir = mkOption {
      type = types.str;
      default = userDirectory "agenix";
      defaultText = userDirectoryDescription "agenix";
      description = ''
        Folder where secrets are symlinked to
      '';
    };

    publicKeysDir = mkOption {
      type = types.str;
      default = userDirectory "agenix-public";
      defaultText = userDirectoryDescription "agenix-public";
      description = ''
        Folder where public keys are symlinked to
      '';
    };

    secretsMountPoint = mkOption {
      default = userDirectory "agenix.d";
      defaultText = userDirectoryDescription "agenix.d";
      description = ''
        Where secrets are created before they are symlinked to ''${cfg.secretsDir}
      '';
    };
  };

  config = mkIf (cfg.secrets != { }) {
    assertions = [
      {
        assertion = cfg.identityPaths != [ ];
        message = "age.identityPaths must be set.";
      }
    ];

    systemd.user.services.agenix = lib.mkIf pkgs.stdenv.hostPlatform.isLinux {
      Unit = {
        Description = "agenix activation";
      };
      Service = {
        Type = "oneshot";
        ExecStart = mountingScript;
      };
      Install.WantedBy = [ "default.target" ];
    };

    launchd.agents.activate-agenix = {
      enable = true;
      config = {
        ProgramArguments = [ mountingScript ];
        KeepAlive = {
          Crashed = false;
          SuccessfulExit = false;
        };
        RunAtLoad = true;
        ProcessType = "Background";
        StandardOutPath = "${config.home.homeDirectory}/Library/Logs/agenix/stdout";
        StandardErrorPath = "${config.home.homeDirectory}/Library/Logs/agenix/stderr";
      };
    };
  };
}
