#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum PublicKeyString {
    /// A direct public key string
    /// The string is the string representation of the public key
    Direct(String),
    /// A reference to another secret's public output
    /// The string is the secret name
    Reference(String),
}

/// Check if a string looks like an actual public key (not a secret reference)
/// SSH keys have format: "ssh-TYPE BASE64DATA" or "sk-ssh-... ..."
/// Age keys start with "age1" and are Bech32 encoded (no spaces)
fn is_actual_public_key(key_str: &str) -> bool {
    // Age public keys: start with "age1" and contain no spaces
    if key_str.starts_with("age1") && !key_str.contains(' ') {
        return true;
    }

    // SSH public keys: must have a space (format: "ssh-type base64data [comment]")
    // Also handle sk- prefixed keys (security key)
    if (key_str.starts_with("ssh-")
        || key_str.starts_with("sk-ssh-")
        || key_str.starts_with("sk-ecdsa-"))
        && key_str.contains(' ')
    {
        return true;
    }

    false
}

impl From<String> for PublicKeyString {
    fn from(key: String) -> Self {
        if is_actual_public_key(&key) {
            PublicKeyString::Direct(key)
        } else {
            PublicKeyString::Reference(key)
        }
    }
}
