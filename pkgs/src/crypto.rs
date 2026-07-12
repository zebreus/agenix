//! Age encryption and decryption on in-memory data.
//!
//! The resolution engine is the only component doing file IO, so this module
//! works purely on bytes: ciphertext in, plaintext out, and vice versa.
//! Supports age x25519 and SSH identities/recipients, armored and binary.

use age::{Decryptor, Encryptor, Identity, IdentityFile, Recipient, armor};
use rootcause::prelude::*;
use rootcause::{Report, report};
use std::io::{Read, Write};
use std::path::Path;
use std::str::FromStr;

/// Decrypt age ciphertext (armored or binary) with the given identities.
///
/// Identities are file paths; explicit identities are tried first, then the
/// system default SSH keys unless `no_system_identities` is set.
pub fn decrypt(
    ciphertext: &[u8],
    identities: &[String],
    no_system_identities: bool,
) -> Result<Vec<u8>, Report> {
    let ciphertext = unarmor(ciphertext)?;
    let identities = collect_identities(identities, no_system_identities)?;

    let decryptor = Decryptor::new(ciphertext.as_slice()).context("Failed to parse age file")?;
    let mut reader = decryptor
        .decrypt(identities.iter().map(|i| i.as_ref() as &dyn Identity))
        .context("No identity matched the ciphertext")?;

    let mut plaintext = vec![];
    reader
        .read_to_end(&mut plaintext)
        .context("Failed to read decrypted plaintext")?;
    Ok(plaintext)
}

/// Encrypt plaintext for the given recipients.
///
/// Recipients may be age recipient strings (`age1...`), SSH public key
/// strings, or paths to identity files.
pub fn encrypt(plaintext: &[u8], recipients: &[String], armored: bool) -> Result<Vec<u8>, Report> {
    if recipients.is_empty() {
        return Err(report!("Cannot encrypt without recipients"));
    }
    let recipients = recipients
        .iter()
        .map(|r| parse_recipient(r))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();

    let encryptor =
        Encryptor::with_recipients(recipients.iter().map(|r| r.as_ref() as &dyn Recipient))
            .context("Failed to build encryptor with recipients")?;

    let mut ciphertext = vec![];
    if armored {
        let armor_writer =
            armor::ArmoredWriter::wrap_output(&mut ciphertext, armor::Format::AsciiArmor)
                .context("Failed to create armored writer")?;
        let mut writer = encryptor.wrap_output(armor_writer)?;
        writer.write_all(plaintext)?;
        let armor_writer = writer.finish().context("Failed to finish encryption")?;
        armor_writer.finish().context("Failed to finish armor")?;
    } else {
        let mut writer = encryptor.wrap_output(&mut ciphertext)?;
        writer.write_all(plaintext)?;
        writer.finish().context("Failed to finish encryption")?;
    }
    Ok(ciphertext)
}

/// Decode armored age content; binary content passes through unchanged.
fn unarmor(ciphertext: &[u8]) -> Result<Vec<u8>, Report> {
    if !ciphertext.starts_with(b"-----BEGIN AGE ENCRYPTED FILE-----") {
        return Ok(ciphertext.to_vec());
    }
    let mut decoded = vec![];
    armor::ArmoredReader::new(std::io::Cursor::new(ciphertext))
        .read_to_end(&mut decoded)
        .context("Failed to decode armored content")?;
    Ok(decoded)
}

/// Load identities in order: explicit ones first, then system defaults
/// (unless disabled).
fn collect_identities(
    explicit: &[String],
    no_system_identities: bool,
) -> Result<Vec<Box<dyn Identity>>, Report> {
    let system = if no_system_identities {
        vec![]
    } else {
        get_default_identities()
    };
    let mut identities = vec![];
    for path in explicit.iter().chain(system.iter()) {
        identities.extend(
            load_identities_from_file(path)
                .context(format!("Failed to load identity from {path}"))?,
        );
    }
    Ok(identities)
}

/// Load identities from a file holding either an SSH private key or an age
/// identity file.
fn load_identities_from_file(path: &str) -> Result<Vec<Box<dyn Identity>>, Report> {
    let content = std::fs::read_to_string(path)
        .context(format!("Failed to read identity file {path}"))?;

    if content.contains("PRIVATE KEY-----") {
        let identity =
            age::ssh::Identity::from_buffer(std::io::Cursor::new(content), Some(path.to_string()))
                .context(format!("Failed to parse SSH identity from {path}"))?;
        return Ok(vec![Box::new(identity)]);
    }

    Ok(IdentityFile::from_file(path.to_string())
        .context(format!("Failed to parse identity file {path}"))?
        .into_identities()
        .context("Failed to convert identity file into identities")?)
}

/// Parse a recipient string (age or SSH public key) or identity file path.
fn parse_recipient(recipient: &str) -> Result<Vec<Box<dyn Recipient + Send>>, Report> {
    if let Ok(id_file) = IdentityFile::from_file(recipient.to_string()) {
        return Ok(id_file
            .to_recipients()
            .context(format!("Failed to parse recipients from file: {recipient}"))?);
    }
    if let Ok(recipient) = age::ssh::Recipient::from_str(recipient) {
        return Ok(vec![Box::new(recipient)]);
    }
    if let Ok(recipient) = age::x25519::Recipient::from_str(recipient) {
        return Ok(vec![Box::new(recipient)]);
    }
    Err(report!("Invalid recipient: {recipient}"))
}

/// Default SSH identity files that exist on this system.
pub fn get_default_identities() -> Vec<String> {
    std::env::var("HOME")
        .map(|home| {
            ["id_rsa", "id_ed25519"]
                .iter()
                .map(|key| format!("{home}/.ssh/{key}"))
                .filter(|path| Path::new(path).exists())
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use age::secrecy::ExposeSecret;
    use std::io::Write;

    /// Generate an age keypair and write the identity to a temp file.
    /// Returns (identity file, public key string).
    fn test_identity() -> (tempfile::NamedTempFile, String) {
        let identity = age::x25519::Identity::generate();
        let public = identity.to_public().to_string();
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file, "{}", identity.to_string().expose_secret()).unwrap();
        (file, public)
    }

    #[test]
    fn test_roundtrip_binary() {
        let (identity, public) = test_identity();
        let ciphertext = encrypt(b"hello secret", &[public], false).unwrap();
        assert!(!ciphertext.starts_with(b"-----BEGIN AGE ENCRYPTED FILE-----"));
        let identity_path = identity.path().to_str().unwrap().to_string();
        let plaintext = decrypt(&ciphertext, &[identity_path], true).unwrap();
        assert_eq!(plaintext, b"hello secret");
    }

    #[test]
    fn test_roundtrip_armored() {
        let (identity, public) = test_identity();
        let ciphertext = encrypt(b"hello armor", &[public], true).unwrap();
        assert!(ciphertext.starts_with(b"-----BEGIN AGE ENCRYPTED FILE-----"));
        let identity_path = identity.path().to_str().unwrap().to_string();
        let plaintext = decrypt(&ciphertext, &[identity_path], true).unwrap();
        assert_eq!(plaintext, b"hello armor");
    }

    #[test]
    fn test_roundtrip_binary_data() {
        let (identity, public) = test_identity();
        let data: Vec<u8> = (0..=255).collect();
        let ciphertext = encrypt(&data, &[public], false).unwrap();
        let identity_path = identity.path().to_str().unwrap().to_string();
        assert_eq!(decrypt(&ciphertext, &[identity_path], true).unwrap(), data);
    }

    #[test]
    fn test_multiple_recipients() {
        let (identity1, public1) = test_identity();
        let (identity2, public2) = test_identity();
        let ciphertext = encrypt(b"shared", &[public1, public2], false).unwrap();
        for identity in [&identity1, &identity2] {
            let path = identity.path().to_str().unwrap().to_string();
            assert_eq!(decrypt(&ciphertext, &[path], true).unwrap(), b"shared");
        }
    }

    #[test]
    fn test_wrong_identity_fails() {
        let (_, public) = test_identity();
        let (other_identity, _) = test_identity();
        let ciphertext = encrypt(b"secret", &[public], false).unwrap();
        let path = other_identity.path().to_str().unwrap().to_string();
        assert!(decrypt(&ciphertext, &[path], true).is_err());
    }

    #[test]
    fn test_empty_plaintext_roundtrip() {
        let (identity, public) = test_identity();
        let ciphertext = encrypt(b"", &[public], false).unwrap();
        let identity_path = identity.path().to_str().unwrap().to_string();
        assert_eq!(decrypt(&ciphertext, &[identity_path], true).unwrap(), b"");
    }

    #[test]
    fn test_invalid_recipient() {
        assert!(encrypt(b"x", &["not-a-key".to_string()], false).is_err());
    }

    #[test]
    fn test_no_recipients() {
        assert!(encrypt(b"x", &[], false).is_err());
    }

    #[test]
    fn test_get_default_identities() {
        // Should return 0-2 identities depending on the system
        assert!(get_default_identities().len() <= 2);
    }
}
