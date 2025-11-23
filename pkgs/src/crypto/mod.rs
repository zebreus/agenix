mod identity;

pub use identity::get_default_identities;
use identity::load_identities_from_file;

use age::{Decryptor, Encryptor, Identity, IdentityFile, Recipient, armor};
use anyhow::{Context, Result};
use itertools::Itertools;
use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use std::str::FromStr;

/// Decrypt a file to another file
pub fn decrypt_to_file<P: AsRef<Path>>(
    input_file: &str,
    output_file: P,
    identity: Option<&str>,
) -> Result<()> {
    // Read ciphertext
    let mut ciphertext = vec![];
    fs::File::open(input_file)
        .with_context(|| format!("Failed to open ciphertext file {input_file}"))?
        .read_to_end(&mut ciphertext)
        .with_context(|| format!("Failed to read ciphertext file {input_file}"))?;

    // Parse decryptor (auto-detect armored)
    // Check if content is armored and decode it if necessary
    let ciphertext_bytes = if ciphertext.starts_with(b"-----BEGIN AGE ENCRYPTED FILE-----") {
        // Armored content - decode it first
        let mut reader = std::io::Cursor::new(&ciphertext);
        let mut decoder = armor::ArmoredReader::new(&mut reader);
        let mut ciphertext_bytes = Vec::new();
        decoder
            .read_to_end(&mut ciphertext_bytes)
            .context("Failed to decode armored content")?;
        ciphertext_bytes
    } else {
        // Binary content - use as is
        ciphertext
    };

    let decryptor = Decryptor::new(&ciphertext_bytes[..]).context("Failed to parse age file")?;

    // Collect identities
    let identities: Vec<Box<dyn Identity>> = if let Some(id_path) = identity {
        load_identities_from_file(id_path)?
    } else {
        // Load default identities, failing if any key file is corrupted
        get_default_identities()
            .iter()
            .map(|path| {
                load_identities_from_file(path)
                    .with_context(|| format!("Failed to load identity from {path}"))
            })
            .flatten_ok()
            .collect::<Result<Vec<_>>>()?
    };

    let mut reader = decryptor
        .decrypt(identities.iter().map(|i| i.as_ref() as &dyn Identity))
        .map_err(|e| anyhow::anyhow!("Failed to decrypt {input_file}: {e}"))?;

    let mut plaintext = vec![];
    reader
        .read_to_end(&mut plaintext)
        .context("Failed to read decrypted plaintext")?;

    fs::write(&output_file, &plaintext).with_context(|| {
        format!(
            "Failed to write decrypted file {}",
            output_file.as_ref().display()
        )
    })?;

    Ok(())
}

// TODO: document what recipient is
fn parse_recipient(recipient_file: &str) -> Result<Vec<Box<dyn Recipient + Send>>> {
    let Ok(id_file) = IdentityFile::from_file(recipient_file.to_string()) else {
        // Fallback: treat as single recipient string (e.g., age1.. or ssh-ed25519 AAAA...)
        let Ok(recipient) = age::ssh::Recipient::from_str(recipient_file) else {
            // Try as x25519 recipient
            let Ok(recipient) = age::x25519::Recipient::from_str(recipient_file) else {
                return Err(anyhow::anyhow!("Invalid recipient: {recipient_file}"));
            };
            return Ok(vec![Box::new(recipient)]);
        };
        return Ok(vec![Box::new(recipient)]);
    };

    id_file
        .to_recipients()
        .with_context(|| format!("Failed to parse recipients from file: {recipient_file}"))
}

/// Encrypt from a file to another file
pub fn encrypt_from_file(
    input_file: &str,
    output_file: &str,
    recipients: &[String],
    armor: bool,
) -> Result<()> {
    // Parse recipients using a helper to keep this function small
    let parsed_recipients = recipients
        .iter()
        .map(|r| parse_recipient(r))
        .flatten_ok()
        .collect::<Result<Vec<_>>>()?;

    let encryptor = Encryptor::with_recipients(
        parsed_recipients
            .iter()
            .map(|r| r.as_ref() as &dyn Recipient),
    )
    .context("Failed to build encryptor with recipients")?;

    let mut input = vec![];
    fs::File::open(input_file)
        .with_context(|| format!("Failed to open input file {input_file}"))?
        .read_to_end(&mut input)
        .with_context(|| format!("Failed to read input file {input_file}"))?;

    let mut output_buf = vec![];
    if armor {
        let armor_writer =
            armor::ArmoredWriter::wrap_output(&mut output_buf, armor::Format::AsciiArmor)
                .context("Failed to create armored writer")?;
        let mut writer = encryptor.wrap_output(armor_writer)?;
        writer
            .write_all(&input)
            .context("Failed to write plaintext")?;
        // Finish returns the inner writer (ArmoredWriter), so we need to call finish on it too
        let armor_writer = writer.finish().context("Failed to finish encryption")?;
        armor_writer.finish().context("Failed to finish armor")?;
    } else {
        let mut writer = encryptor.wrap_output(&mut output_buf)?;
        writer
            .write_all(&input)
            .context("Failed to write plaintext")?;
        writer.finish().context("Failed to finish encryption")?;
    }

    fs::write(output_file, &output_buf)
        .with_context(|| format!("Failed to write encrypted file {output_file}"))?;

    Ok(())
}

/// Check if two files have the same content
pub fn files_equal(file1: &str, file2: &str) -> Result<bool> {
    if !Path::new(file1).exists() || !Path::new(file2).exists() {
        return Ok(false);
    }

    let content1 = fs::read(file1).context("Failed to read first file")?;
    let content2 = fs::read(file2).context("Failed to read second file")?;
    Ok(content1 == content2)
}

#[cfg(test)]
mod tests;
