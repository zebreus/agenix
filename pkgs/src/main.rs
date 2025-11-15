use age::{Decryptor, Encryptor};
use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;
use tempfile::NamedTempFile;

const VERSION: &str = "0.15.0";

#[derive(Parser)]
#[command(name = "agenix")]
#[command(about = "edit and rekey age secret files", long_about = None)]
#[command(version = VERSION)]
struct Cli {
    /// Edit FILE using $EDITOR
    #[arg(short = 'e', long = "edit", value_name = "FILE")]
    edit: Option<PathBuf>,

    /// Re-encrypt all secrets with specified recipients
    #[arg(short = 'r', long = "rekey")]
    rekey: bool,

    /// Decrypt FILE to STDOUT
    #[arg(short = 'd', long = "decrypt", value_name = "FILE")]
    decrypt: Option<PathBuf>,

    /// Path to private SSH key used to decrypt file
    #[arg(short, long)]
    identity: Option<PathBuf>,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

struct AgenixConfig {
    rules_path: PathBuf,
    identity_paths: Vec<PathBuf>,
    verbose: bool,
}

impl AgenixConfig {
    fn new(identity: Option<PathBuf>, verbose: bool) -> Result<Self> {
        let rules_path = std::env::var("RULES")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("./secrets.nix"));

        let mut identity_paths = Vec::new();
        if let Some(id) = identity {
            identity_paths.push(id);
        } else {
            // Add default SSH keys if they exist
            let home = std::env::var("HOME").context("HOME environment variable not set")?;
            let home_path = PathBuf::from(home);
            
            let id_rsa = home_path.join(".ssh/id_rsa");
            if id_rsa.exists() {
                identity_paths.push(id_rsa);
            }
            
            let id_ed25519 = home_path.join(".ssh/id_ed25519");
            if id_ed25519.exists() {
                identity_paths.push(id_ed25519);
            }
        }

        if identity_paths.is_empty() {
            return Err(anyhow!("No identity found to decrypt. Try adding an SSH key at $HOME/.ssh/id_rsa or $HOME/.ssh/id_ed25519 or using the --identity flag to specify a file."));
        }

        Ok(AgenixConfig {
            rules_path,
            identity_paths,
            verbose,
        })
    }

    fn get_public_keys(&self, file: &str) -> Result<Vec<String>> {
        let nix_expr = format!(
            "(let rules = import {}; in rules.\"{}\".publicKeys)",
            self.rules_path.display(),
            file
        );

        let output = Command::new("nix-instantiate")
            .args(["--json", "--eval", "--strict", "-E", &nix_expr])
            .output()
            .context("Failed to run nix-instantiate")?;

        if !output.status.success() {
            return Err(anyhow!(
                "nix-instantiate failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        let json_output = String::from_utf8(output.stdout)?;
        let keys: Vec<String> = serde_json::from_str(&json_output)
            .context("Failed to parse public keys from nix-instantiate output")?;

        if keys.is_empty() {
            return Err(anyhow!(
                "There is no rule for {} in {}",
                file,
                self.rules_path.display()
            ));
        }

        Ok(keys)
    }

    fn get_armor(&self, file: &str) -> Result<bool> {
        let nix_expr = format!(
            "(let rules = import {}; in (builtins.hasAttr \"armor\" rules.\"{}\" && rules.\"{}\".armor))",
            self.rules_path.display(),
            file,
            file
        );

        let output = Command::new("nix-instantiate")
            .args(["--json", "--eval", "--strict", "-E", &nix_expr])
            .output()
            .context("Failed to run nix-instantiate")?;

        if !output.status.success() {
            return Err(anyhow!(
                "nix-instantiate failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        let json_output = String::from_utf8(output.stdout)?;
        let armor: bool = serde_json::from_str(&json_output)
            .context("Failed to parse armor setting from nix-instantiate output")?;

        Ok(armor)
    }

    fn list_all_secrets(&self) -> Result<Vec<String>> {
        let nix_expr = format!(
            "(let rules = import {}; in builtins.attrNames rules)",
            self.rules_path.display()
        );

        let output = Command::new("nix-instantiate")
            .args(["--json", "--eval", "-E", &nix_expr])
            .output()
            .context("Failed to run nix-instantiate")?;

        if !output.status.success() {
            return Err(anyhow!(
                "nix-instantiate failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        let json_output = String::from_utf8(output.stdout)?;
        let secrets: Vec<String> = serde_json::from_str(&json_output)
            .context("Failed to parse secret list from nix-instantiate output")?;

        Ok(secrets)
    }
}

fn load_ssh_identities(paths: &[PathBuf]) -> Result<Vec<Box<dyn age::Identity>>> {
    let mut identities: Vec<Box<dyn age::Identity>> = Vec::new();

    for path in paths {
        let key_data = fs::read_to_string(path)
            .with_context(|| format!("Failed to read identity file: {}", path.display()))?;

        let parsed_identities = age::ssh::Identity::from_buffer(key_data.as_bytes(), None)
            .with_context(|| format!("Failed to parse SSH identity from {}", path.display()))?;

        identities.push(Box::new(parsed_identities));
    }

    if identities.is_empty() {
        return Err(anyhow!("No valid identities found"));
    }

    Ok(identities)
}

fn decrypt_file(file_path: &PathBuf, identities: Vec<Box<dyn age::Identity>>) -> Result<Vec<u8>> {
    let encrypted = fs::read(file_path)
        .with_context(|| format!("Failed to read encrypted file: {}", file_path.display()))?;

    let decryptor = match Decryptor::new(&encrypted[..])? {
        Decryptor::Recipients(d) => d,
        _ => return Err(anyhow!("Unexpected decryptor type")),
    };

    let mut decrypted = Vec::new();
    let mut reader = decryptor
        .decrypt(identities.iter().map(|i| i.as_ref() as &dyn age::Identity))
        .context("Failed to decrypt file")?;
    reader.read_to_end(&mut decrypted)?;

    Ok(decrypted)
}

fn encrypt_data(
    data: &[u8],
    public_keys: &[String],
    armor: bool,
) -> Result<Vec<u8>> {
    let recipients: Result<Vec<_>> = public_keys
        .iter()
        .map(|key| {
            age::ssh::Recipient::from_str(key)
                .map(|r| Box::new(r) as Box<dyn age::Recipient + Send>)
                .map_err(|e| anyhow!("Failed to parse public key: {:?}", e))
        })
        .collect();
    let recipients = recipients?;

    let encryptor = Encryptor::with_recipients(recipients)
        .context("Failed to create encryptor")?;

    let mut encrypted = Vec::new();
    
    if armor {
        let armored_writer = age::armor::ArmoredWriter::wrap_output(
            &mut encrypted,
            age::armor::Format::AsciiArmor,
        )?;
        let mut writer = encryptor.wrap_output(armored_writer)
            .context("Failed to create armored writer")?;
        writer.write_all(data)?;
        writer.finish()?.finish()?;
    } else {
        let mut writer = encryptor.wrap_output(&mut encrypted)
            .context("Failed to create writer")?;
        writer.write_all(data)?;
        writer.finish()?;
    }

    Ok(encrypted)
}

fn handle_edit(file: PathBuf, config: &AgenixConfig) -> Result<()> {
    let file_name = file
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow!("Invalid file name"))?;

    let public_keys = config.get_public_keys(file_name)?;
    let armor = config.get_armor(file_name)?;

    // Decrypt existing file if it exists
    let mut cleartext = Vec::new();
    if file.exists() {
        let identities = load_ssh_identities(&config.identity_paths)?;
        cleartext = decrypt_file(&file, identities)?;
    }

    // Create temporary file for editing
    let mut temp_file = NamedTempFile::new().context("Failed to create temporary file")?;
    temp_file.write_all(&cleartext)?;
    temp_file.flush()?;

    let temp_path = temp_file.path().to_path_buf();

    // Store original content for comparison
    let original_content = cleartext.clone();

    // Determine editor
    let editor = if atty::is(atty::Stream::Stdin) {
        std::env::var("EDITOR").unwrap_or_else(|_| "vi".to_string())
    } else {
        // If STDIN is not interactive, read from stdin
        let mut stdin_content = Vec::new();
        std::io::stdin().read_to_end(&mut stdin_content)?;
        temp_file.write_all(&stdin_content)?;
        temp_file.flush()?;
        String::from(":")
    };

    // Open editor (skip if editor is ":")
    if editor != ":" {
        let status = Command::new(&editor)
            .arg(&temp_path)
            .status()
            .with_context(|| format!("Failed to run editor: {}", editor))?;

        if !status.success() {
            return Err(anyhow!("Editor exited with non-zero status"));
        }
    }

    // Read edited content
    let new_content = fs::read(&temp_path).context("Failed to read edited file")?;

    // Check if file was changed
    if file.exists() && editor != ":" && new_content == original_content {
        eprintln!("{} wasn't changed, skipping re-encryption.", file_name);
        return Ok(());
    }

    // Check if file was created
    if new_content.is_empty() && !file.exists() {
        eprintln!("{} wasn't created.", file_name);
        return Ok(());
    }

    // Re-encrypt
    let encrypted = encrypt_data(&new_content, &public_keys, armor)?;

    // Write encrypted file
    if let Some(parent) = file.parent() {
        fs::create_dir_all(parent).context("Failed to create parent directory")?;
    }
    fs::write(&file, encrypted)
        .with_context(|| format!("Failed to write encrypted file: {}", file.display()))?;

    if config.verbose {
        eprintln!("Successfully encrypted {}", file.display());
    }

    Ok(())
}

fn handle_decrypt(file: PathBuf, config: &AgenixConfig) -> Result<()> {
    let file_name = file
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow!("Invalid file name"))?;

    let _public_keys = config.get_public_keys(file_name)?;
    let identities = load_ssh_identities(&config.identity_paths)?;

    let decrypted = decrypt_file(&file, identities)?;
    std::io::stdout().write_all(&decrypted)?;

    Ok(())
}

fn handle_rekey(config: &AgenixConfig) -> Result<()> {
    let secrets = config.list_all_secrets()?;

    for secret in secrets {
        eprintln!("rekeying {}...", secret);
        let file_path = PathBuf::from(&secret);
        
        // Set EDITOR to ":" to skip interactive editing
        std::env::set_var("EDITOR", ":");
        
        handle_edit(file_path, config)?;
    }

    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let config = AgenixConfig::new(cli.identity, cli.verbose)?;

    if cli.rekey {
        handle_rekey(&config)
    } else if let Some(file) = cli.decrypt {
        handle_decrypt(file, &config)
    } else if let Some(file) = cli.edit {
        handle_edit(file, &config)
    } else {
        eprintln!("No action specified. Use -e, -r, or -d. Use --help for more information.");
        std::process::exit(1);
    }
}
