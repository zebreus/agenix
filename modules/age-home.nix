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

  # Filter publics that have installPath set
  publicsWithInstall = builtins.filter (p: p.installPath != null) (builtins.attrValues cfg.publics);

  # Create public keys directory
  createPublicKeysDir = ''
    echo "[agenix] creating public keys directory..."
    mkdir -p "${cfg.publicKeysDir}"
    chmod 0755 "${cfg.publicKeysDir}"
  '';

  # Install a single public file
  installPublicFile = publicType: ''
    echo "installing public file '${publicType.file}' to '${publicType.installPath}'..."
    ${
      if publicType.symlink then
        ''
          mkdir -p "$(dirname "${publicType.installPath}")"
          ln -sfT "${publicType.file}" "${publicType.installPath}"
        ''
      else
        ''
          mkdir -p "$(dirname "${publicType.installPath}")"
          install -m "${publicType.mode}" "${publicType.file}" "${publicType.installPath}"
        ''
    }
  '';

  # Install all public files
  installPublicFiles = builtins.concatStringsSep "\n" (
    [ createPublicKeysDir ]
    ++ [ "echo '[agenix] installing public files...'" ]
    ++ (map installPublicFile publicsWithInstall)
  );

  publicType = types.submodule (
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
            Name of the public key (matches the secret name).
          '';
        };
        file = mkOption {
          type = types.nullOr types.path;
          default =
            let
              # Try to find corresponding secret's file
              secretFile = cfg.secrets.${config.name}.file or null;
              # Remove .age suffix if present, then add .pub
              basePath = if secretFile != null then toString secretFile else null;
              baseWithoutAge =
                if basePath != null && lib.hasSuffix ".age" basePath then
                  lib.removeSuffix ".age" basePath
                else
                  basePath;
              pubFile = if baseWithoutAge != null then "${baseWithoutAge}.pub" else null;
            in
            if pubFile != null && builtins.pathExists pubFile then pubFile else null;
          defaultText = literalExpression ''
            let
              secretFile = cfg.secrets.''${config.name}.file or null;
              basePath = if secretFile != null then toString secretFile else null;
              baseWithoutAge = if basePath != null && lib.hasSuffix ".age" basePath then
                lib.removeSuffix ".age" basePath
              else
                basePath;
              pubFile = if baseWithoutAge != null then "''${baseWithoutAge}.pub" else null;
            in
            if pubFile != null && builtins.pathExists pubFile then pubFile else null
          '';
          description = ''
            Path to the public file. Defaults to the corresponding secret's file
            with .age replaced by .pub.
          '';
        };
        content = mkOption {
          type = types.nullOr types.str;
          default = if config.file != null then builtins.readFile config.file else null;
          defaultText = literalExpression ''
            if config.file != null then builtins.readFile config.file else null
          '';
          description = ''
            Content of the public file.
          '';
        };
        installPath = mkOption {
          type = types.nullOr types.str;
          default = null;
          defaultText = literalExpression "null";
          description = ''
            Path where the public file should be installed (symlinked or copied).
            If null, the public file is not installed on the system.
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
    }
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
          type = types.nullOr types.path;
          default =
            let
              # If secretsPath is set, construct path from secret name
              secretPath =
                if cfg.secretsPath != null then "${toString cfg.secretsPath}/${config.name}.age" else null;
            in
            if secretPath != null && builtins.pathExists secretPath then secretPath else null;
          defaultText = literalExpression ''
            if cfg.secretsPath != null then
              "''${cfg.secretsPath}/''${config.name}.age"
            else
              null
          '';
          description = ''
            Age file the secret is loaded from.

            If not specified and {option}`age.secretsPath` is set, defaults to
            `''${age.secretsPath}/''${name}.age` where `name` is the attribute name
            in `age.secrets`.

            For example, with `age.secretsPath = ./secrets` and
            `age.secrets.cool_key_ed25519 = {}`{, the secret file will be
            `./secrets/cool_key_ed25519.age`.
          '';
        };
        path = mkOption {
          type = types.str;
          default = "${cfg.secretsDir}/${config.name}";
          description = ''
            Path where the decrypted secret is installed.
          '';
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

    secretsPath = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = ''
        Path to the directory containing secrets.nix and the encrypted secret files.

        When set, the `file` option for each secret defaults to
        `''${secretsPath}/''${name}.age`, where `name` is the attribute name.

        This allows you to simply reference secrets by name without specifying
        the file path explicitly:

        ```nix
        age.secretsPath = ./secrets;
        age.secrets.cool_key_ed25519 = {
          # file defaults to ./secrets/cool_key_ed25519.age
        };
        ```

        All secret files (`.age`) and public files (`.pub`) are expected to be in
        this directory, matching the format used by the agenix CLI tool.
      '';
    };

    secrets = mkOption {
      type = types.attrsOf secretType;
      default = { };
      description = ''
        Attrset of secrets.
      '';
    };

    publics = mkOption {
      type = types.attrsOf publicType;
      default = { };
      description = ''
        Attrset of public keys associated with secrets.

        Public keys are accessible via `config.age.publics.<name>` instead of
        `config.age.secrets.<name>.public`.

        Example:
          age.publics.my_key.installPath = "''${config.home.homeDirectory}/.ssh/authorized_keys.d/my_key";
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
    ]
    ++ (map (secret: {
      assertion = secret.file != null;
      message = ''
        age.secrets.${secret.name}: Either specify the `file` option explicitly
        or set `age.secretsPath` to enable automatic file path resolution.

        When `age.secretsPath` is set, the file defaults to:
          ''${age.secretsPath}/${secret.name}.age

        Example:
          age.secretsPath = ./secrets;
          age.secrets.${secret.name} = {};  # file = ./secrets/${secret.name}.age
      '';
    }) (builtins.attrValues cfg.secrets));

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
