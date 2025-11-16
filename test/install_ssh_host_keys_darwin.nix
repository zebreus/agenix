# Do not copy this! It is insecure. This is only okay because we are testing.
{ config, ... }:
{
  system.activationScripts.homemanager-test-activation.text = ''
    echo "Installing system SSH host key"
    sudo -u root cp ${./example_keys/system1.pub} /etc/ssh/ssh_host_ed25519_key.pub
    sudo -u root cp ${./example_keys/system1} /etc/ssh/ssh_host_ed25519_key
    sudo -u root chmod 644 /etc/ssh/ssh_host_ed25519_key.pub
    sudo -u root chmod 600 /etc/ssh/ssh_host_ed25519_key

    echo "Installing user SSH host key"
    sudo -u ${config.system.primaryUser} mkdir -p "${config.system.primaryUserHome}/.ssh"
    sudo -u ${config.system.primaryUser} cp ${./example_keys/user1.pub} "${config.system.primaryUserHome}/.ssh/id_ed25519.pub"
    sudo -u ${config.system.primaryUser} cp ${./example_keys/user1} "${config.system.primaryUserHome}/.ssh/id_ed25519"
    sudo -u ${config.system.primaryUser} chmod 644 "${config.system.primaryUserHome}/.ssh/id_ed25519.pub"
    sudo -u ${config.system.primaryUser} chmod 600 "${config.system.primaryUserHome}/.ssh/id_ed25519"
  '';
}
