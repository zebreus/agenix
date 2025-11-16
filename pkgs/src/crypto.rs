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

    eprintln!("Ciphertext size: {} bytes", ciphertext.len());
    eprintln!("Cipertext content: {:?}", &ciphertext[..]);
    // Parse decryptor (auto-detect armored)
    let decryptor = Decryptor::new(&ciphertext[..]).context("Failed to parse age file")?;

    // Collect identities
    let identities: Vec<Box<dyn Identity>> = if let Some(id_path) = identity {
        load_identities_from_file(id_path)?
    } else {
        get_default_identities()
            .into_iter()
            .flat_map(|path| load_identities_from_file(&path).unwrap_or_default())
            .collect()
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

/// Decrypt a file to stdout
pub fn decrypt_to_stdout(input_file: &str, identity: Option<&str>) -> Result<()> {
    let mut ciphertext = vec![];
    fs::File::open(input_file)
        .with_context(|| format!("Failed to open ciphertext file {input_file}"))?
        .read_to_end(&mut ciphertext)
        .with_context(|| format!("Failed to read ciphertext file {input_file}"))?;

    let decryptor = Decryptor::new(&ciphertext[..]).context("Failed to parse age file")?;

    let identities: Vec<Box<dyn Identity>> = if let Some(id_path) = identity {
        load_identities_from_file(id_path)?
    } else {
        get_default_identities()
            .into_iter()
            .flat_map(|path| load_identities_from_file(&path).unwrap_or_default())
            .collect()
    };

    let mut reader = decryptor
        .decrypt(identities.iter().map(|i| i.as_ref() as &dyn Identity))
        .map_err(|e| anyhow::anyhow!("Failed to decrypt {input_file}: {e}"))?;

    let mut plaintext = vec![];
    reader
        .read_to_end(&mut plaintext)
        .context("Failed to read decrypted plaintext")?;

    // Write to stdout
    std::io::stdout()
        .write_all(&plaintext)
        .context("Failed to write decrypted plaintext to stdout")?;

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

/// Load identities from a file, handling both age identity files and SSH private keys
fn load_identities_from_file(path: &str) -> Result<Vec<Box<dyn Identity>>> {
    let content =
        fs::read_to_string(path).with_context(|| format!("Failed to read identity file {path}"))?;

    // Try to parse as SSH identity first
    if content.contains("-----BEGIN OPENSSH PRIVATE KEY-----")
        || content.contains("-----BEGIN RSA PRIVATE KEY-----")
        || content.contains("-----BEGIN EC PRIVATE KEY-----")
    {
        let ssh_identity =
            age::ssh::Identity::from_buffer(std::io::Cursor::new(content), Some(path.to_string()))
                .map_err(|e| anyhow::anyhow!("Failed to parse SSH identity from {path}: {e}"))?;
        return Ok(vec![Box::new(ssh_identity)]);
    }

    // Fall back to age identity file format
    let id_file = IdentityFile::from_file(path.to_string())
        .with_context(|| format!("Failed to parse identity file {path}"))?;
    id_file
        .into_identities()
        .context("Failed to convert identity file into identities")
}

/// Get default SSH identity files
pub fn get_default_identities() -> Vec<String> {
    let mut identities = Vec::new();

    if let Ok(home) = std::env::var("HOME") {
        let id_rsa = format!("{home}/.ssh/id_rsa");
        let id_ed25519 = format!("{home}/.ssh/id_ed25519");

        if Path::new(&id_rsa).exists() {
            identities.push(id_rsa);
        }
        if Path::new(&id_ed25519).exists() {
            identities.push(id_ed25519);
        }
    }

    identities
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
mod tests {
    use super::*;

    #[test]
    fn test_get_default_identities() {
        let identities = get_default_identities();
        // Should return 0-2 identities depending on system
        assert!(identities.len() <= 2);
    }

    #[test]
    fn test_files_equal_nonexistent() {
        let result = files_equal("nonexistent1", "nonexistent2");
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_files_equal_same_content() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let mut file1 = NamedTempFile::new()?;
        let mut file2 = NamedTempFile::new()?;

        writeln!(file1, "test content")?;
        writeln!(file2, "test content")?;

        let result = files_equal(
            file1.path().to_str().unwrap(),
            file2.path().to_str().unwrap(),
        )?;
        assert!(result);

        Ok(())
    }

    #[test]
    fn test_files_equal_different_content() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let mut file1 = NamedTempFile::new()?;
        let mut file2 = NamedTempFile::new()?;

        writeln!(file1, "content 1")?;
        writeln!(file2, "content 2")?;

        let result = files_equal(
            file1.path().to_str().unwrap(),
            file2.path().to_str().unwrap(),
        )?;
        assert!(!result);

        Ok(())
    }
}
