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

  isDarwin = lib.attrsets.hasAttrByPath [ "environment" "darwinConfig" ] options;

  ageBin = config.age.ageBin;

  users = config.users.users;

  sysusersEnabled =
    if isDarwin then
      false
    else
      options.systemd ? sysusers && (config.systemd.sysusers.enable || config.services.userborn.enable);

  mountCommand =
    if isDarwin then
      ''
        if ! diskutil info "${cfg.secretsMountPoint}" &> /dev/null; then
            num_sectors=1048576
            dev=$(hdiutil attach -nomount ram://"$num_sectors" | sed 's/[[:space:]]*$//')
            newfs_hfs -v agenix "$dev"
            mount -t hfs -o nobrowse,nodev,nosuid,-m=0751 "$dev" "${cfg.secretsMountPoint}"
        fi
      ''
    else
      ''
        grep -q "${cfg.secretsMountPoint} ramfs" /proc/mounts ||
          mount -t ramfs none "${cfg.secretsMountPoint}" -o nodev,nosuid,mode=0751
      '';
  newGeneration = ''
    _agenix_generation="$(basename "$(readlink ${cfg.secretsDir})" || echo 0)"
    (( ++_agenix_generation ))
    echo "[agenix] creating new generation in ${cfg.secretsMountPoint}/$_agenix_generation"
    mkdir -p "${cfg.secretsMountPoint}"
    chmod 0751 "${cfg.secretsMountPoint}"
    ${mountCommand}
    mkdir -p "${cfg.secretsMountPoint}/$_agenix_generation"
    chmod 0751 "${cfg.secretsMountPoint}/$_agenix_generation"
  '';

  chownGroup = if isDarwin then "admin" else "keys";
  # chown the secrets mountpoint and the current generation to the keys group
  # instead of leaving it root:root.
  chownMountPoint = ''
    chown :${chownGroup} "${cfg.secretsMountPoint}" "${cfg.secretsMountPoint}/$_agenix_generation"
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
    for identity in ${toString cfg.identityPaths}; do
      test -r "$identity" || continue
      test -s "$identity" || continue
      IDENTITIES+=(-i)
      IDENTITIES+=("$identity")
    done

    test "''${#IDENTITIES[@]}" -eq 0 && echo "[agenix] WARNING: no readable identities found!"

    mkdir -p "$(dirname "$_truePath")"
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
      [ "${secretType.path}" != "${cfg.secretsDir}/${secretType.name}" ] && ln -sfT "${cfg.secretsDir}/${secretType.name}" "${secretType.path}"
    ''}
  '';

  testIdentities = map (path: ''
    test -f ${path} || echo '[agenix] WARNING: config.age.identityPaths entry ${path} not present!'
  '') cfg.identityPaths;

  cleanupAndLink = ''
    _agenix_generation="$(basename "$(readlink ${cfg.secretsDir})" || echo 0)"
    (( ++_agenix_generation ))
    echo "[agenix] symlinking new secrets to ${cfg.secretsDir} (generation $_agenix_generation)..."
    ln -sfT "${cfg.secretsMountPoint}/$_agenix_generation" ${cfg.secretsDir}

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

  chownSecret = secretType: ''
    ${setTruePath secretType}
    chown ${secretType.owner}:${secretType.group} "$_truePath"
  '';

  chownSecrets = builtins.concatStringsSep "\n" (
    [ "echo '[agenix] chowning...'" ]
    ++ [ chownMountPoint ]
    ++ (map chownSecret (builtins.attrValues cfg.secrets))
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

  # Chown a single public file
  # Note: For symlinks pointing to the Nix store, chown doesn't change ownership
  # of the symlink (only the target), and chmod cannot be used on symlinks directly.
  # We skip these operations for symlinks.
  chownPublicFile = publicType: ''
    ${optionalString (!publicType.symlink) ''
      chown '${publicType.owner}':'${publicType.group}' "${publicType.installPath}"
    ''}
  '';

  # Chown all public files
  chownPublicFiles = builtins.concatStringsSep "\n" (
    [ "echo '[agenix] chowning public files...'" ] ++ (map chownPublicFile publicsWithInstall)
  );

  publicType = types.submodule (
    { config, name, ... }:
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
          type = types.path;
          internal = true;
          default = cfg.secretsPath + "/${config.name}.pub";
          description = ''
            Public key file corresponding to the secret.

            This is automatically derived from `age.secretsPath` and resolves to
            `''${age.secretsPath}/''${name}.pub` where `name` is the attribute name.
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
        owner = mkOption {
          type = types.str;
          default = "root";
          description = ''
            User of the installed public file.
          '';
        };
        group = mkOption {
          type = types.str;
          default = users.${config.owner}.group or "keys";
          defaultText = literalExpression ''
            users.''${config.owner}.group or "keys"
          '';
          description = ''
            Group of the installed public file.
          '';
        };
        symlink = mkEnableOption "symlinking public files to their destination" // {
          default = true;
        };
      };
    }
  );

  secretType = types.submodule (
    { config, ... }:
    {
      options = {
        name = mkOption {
          type = types.str;
          default = config._module.args.name;
          defaultText = literalExpression "config._module.args.name";
          description = ''
            Name of the file used in {option}`age.secretsDir`
          '';
        };
        file = mkOption {
          type = types.path;
          internal = true;
          default = cfg.secretsPath + "/${config.name}.age";
          description = ''
            Age file the secret is loaded from.

            This is automatically derived from `age.secretsPath` and cannot be set manually.
            It resolves to `''${age.secretsPath}/''${name}.age` where `name` is the 
            attribute name in `age.secrets`.
          '';
        };
        path = mkOption {
          type = types.str;
          default = "${cfg.secretsDir}/${config.name}";
          defaultText = literalExpression ''
            "''${cfg.secretsDir}/''${config.name}"
          '';
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
        owner = mkOption {
          type = types.str;
          default = "0";
          description = ''
            User of the decrypted secret.
          '';
        };
        group = mkOption {
          type = types.str;
          default = users.${config.owner}.group or "0";
          defaultText = literalExpression ''
            users.''${config.owner}.group or "0"
          '';
          description = ''
            Group of the decrypted secret.
          '';
        };
        symlink = mkEnableOption "symlinking secrets to their destination" // {
          default = true;
        };
      };
    }
  );
in
{
  imports = [
    (mkRenamedOptionModule [ "age" "sshKeyPaths" ] [ "age" "identityPaths" ])
  ];

  options.age = {
    ageBin = mkOption {
      type = types.str;
      default = "${pkgs.age}/bin/age";
      defaultText = literalExpression ''
        "''${pkgs.age}/bin/age"
      '';
      description = ''
        The age executable to use.
      '';
    };
    secretsPath = mkOption {
      type = types.path;
      description = ''
        Path to the directory containing secrets.nix and the encrypted secret files.

        Secret files are automatically resolved as `''${secretsPath}/''${name}.age`, 
        where `name` is the attribute name in `age.secrets`.

        This allows you to simply reference secrets by name:

        ```nix
        age.secretsPath = ./secrets;
        age.secrets.cool_key_ed25519 = {
          # file is automatically ./secrets/cool_key_ed25519.age
        };
        ```

        All secret files (`.age`) and public files (`.pub`) must be in
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
          age.publics.my_key.installPath = "/etc/ssh/authorized_keys.d/my_key";
      '';
    };
    secretsDir = mkOption {
      type = types.path;
      default = "/run/agenix";
      description = ''
        Folder where secrets are symlinked to
      '';
    };
    publicKeysDir = mkOption {
      type = types.path;
      default = "/run/agenix-public";
      description = ''
        Folder where public keys are symlinked to
      '';
    };
    secretsMountPoint = mkOption {
      type =
        types.addCheck types.str (
          s:
          (builtins.match "[ \t\n]*" s) == null # non-empty
          && (builtins.match ".+/" s) == null
        ) # without trailing slash
        // {
          description = "${types.str.description} (with check: non-empty without trailing slash)";
        };
      default = "/run/agenix.d";
      description = ''
        Where secrets are created before they are symlinked to {option}`age.secretsDir`
      '';
    };
    identityPaths = mkOption {
      type = types.listOf types.path;
      default =
        if isDarwin then
          [
            "/etc/ssh/ssh_host_ed25519_key"
            "/etc/ssh/ssh_host_rsa_key"
          ]
        else if (config.services.openssh.enable or false) then
          map (e: e.path) (
            lib.filter (e: e.type == "rsa" || e.type == "ed25519") config.services.openssh.hostKeys
          )
        else
          [ ];
      defaultText = literalExpression ''
        if isDarwin
        then [
          "/etc/ssh/ssh_host_ed25519_key"
          "/etc/ssh/ssh_host_rsa_key"
        ]
        else if (config.services.openssh.enable or false)
        then map (e: e.path) (lib.filter (e: e.type == "rsa" || e.type == "ed25519") config.services.openssh.hostKeys)
        else [];
      '';
      description = ''
        Path to SSH keys to be used as identities in age decryption.
      '';
    };
  };

  config = mkIf (cfg.secrets != { }) (mkMerge [
    {
      assertions = [
        {
          assertion = cfg.identityPaths != [ ];
          message = "age.identityPaths must be set, for example by enabling openssh.";
        }
      ];
    }
    (optionalAttrs (!isDarwin) {
      # When using sysusers we no longer be started as an activation script
      # because those are started in initrd while sysusers is started later.
      systemd.services.agenix-install-secrets = mkIf sysusersEnabled {
        wantedBy = [ "sysinit.target" ];
        after = [ "systemd-sysusers.service" ];
        unitConfig.DefaultDependencies = "no";

        path = [ pkgs.mount ];
        serviceConfig = {
          Type = "oneshot";
          ExecStart = pkgs.writeShellScript "agenix-install" (concatLines [
            newGeneration
            installSecrets
            installPublicFiles
            chownSecrets
            chownPublicFiles
          ]);
          RemainAfterExit = true;
        };
      };

      # Create a new directory full of secrets for symlinking (this helps
      # ensure removed secrets are actually removed, or at least become
      # invalid symlinks).
      system.activationScripts = mkIf (!sysusersEnabled) {
        agenixNewGeneration = {
          text = newGeneration;
          deps = [
            "specialfs"
          ];
        };

        agenixInstall = {
          text = installSecrets;
          deps = [
            "agenixNewGeneration"
            "specialfs"
          ];
        };

        agenixInstallPublic = {
          text = installPublicFiles;
          deps = [
            "specialfs"
          ];
        };

        # So user passwords can be encrypted.
        users.deps = [ "agenixInstall" ];

        # Change ownership and group after users and groups are made.
        agenixChown = {
          text = chownSecrets;
          deps = [
            "users"
            "groups"
          ];
        };

        agenixChownPublic = {
          text = chownPublicFiles;
          deps = [
            "agenixInstallPublic"
            "users"
            "groups"
          ];
        };

        # So other activation scripts can depend on agenix being done.
        agenix = {
          text = "";
          deps = [
            "agenixChown"
            "agenixChownPublic"
          ];
        };
      };
    })

    (optionalAttrs isDarwin {
      launchd.daemons.activate-agenix = {
        script = ''
          set -e
          set -o pipefail
          export PATH="${pkgs.gnugrep}/bin:${pkgs.coreutils}/bin:@out@/sw/bin:/usr/bin:/bin:/usr/sbin:/sbin"
          ${newGeneration}
          ${installSecrets}
          ${installPublicFiles}
          ${chownSecrets}
          ${chownPublicFiles}
          exit 0
        '';
        serviceConfig = {
          RunAtLoad = true;
          KeepAlive.SuccessfulExit = false;
        };
      };
    })
  ]);
}
