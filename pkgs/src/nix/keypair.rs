use anyhow::Result;

/// Generate an Ed25519 SSH keypair
pub fn generate_ed25519_keypair() -> Result<(String, String)> {
    use base64::{Engine as _, engine::general_purpose};
    use ed25519_dalek::ed25519::signature::rand_core::OsRng;
    use ed25519_dalek::pkcs8;
    use ed25519_dalek::pkcs8::EncodePrivateKey;
    use ed25519_dalek::{SigningKey, VerifyingKey};

    let mut csprng = OsRng;
    let signing_key: SigningKey = SigningKey::generate(&mut csprng);
    let verifying_key: VerifyingKey = signing_key.verifying_key();

    // Generate private key in PEM format
    let private_key_pem = signing_key.to_pkcs8_pem(pkcs8::spki::der::pem::LineEnding::LF)?;

    // Generate public key in SSH format (ssh-ed25519 AAAAC3Nza...)
    // SSH ed25519 public key format includes algorithm identifier + key data
    let mut ssh_key_data = Vec::new();

    // SSH wire format: length(algorithm) + algorithm + length(public_key) + public_key
    let algorithm = b"ssh-ed25519";
    ssh_key_data.extend_from_slice(&(algorithm.len() as u32).to_be_bytes());
    ssh_key_data.extend_from_slice(algorithm);

    let public_key_bytes = verifying_key.as_bytes();
    ssh_key_data.extend_from_slice(&(public_key_bytes.len() as u32).to_be_bytes());
    ssh_key_data.extend_from_slice(public_key_bytes);

    // Base64 encoding using the base64 crate
    let base64_encoded = general_purpose::STANDARD.encode(&ssh_key_data);
    let public_key_ssh = format!("ssh-ed25519 {}", base64_encoded);

    Ok((private_key_pem.to_string(), public_key_ssh))
}

/// Generate an Age x25519 keypair
pub fn generate_age_x25519_keypair() -> Result<(String, String)> {
    use age::secrecy::ExposeSecret;

    // Generate age x25519 keypair
    let secret_key = age::x25519::Identity::generate();
    let public_key = secret_key.to_public();

    // Convert to strings
    let private_key = secret_key.to_string().expose_secret().to_string();
    let public_key = public_key.to_string();

    Ok((private_key, public_key))
}
