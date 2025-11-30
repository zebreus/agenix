use anyhow::Result;

fn main() -> Result<()> {
    agenix::run(std::env::args())
}

#[cfg(test)]
mod tests {
    // Note: Tests for no-arg behavior are in cli.rs (test_no_subcommand_shows_help)
    // because running through agenix::run() causes clap to exit the process.

    #[test]
    fn test_handle_edit_nonexistent_file() {
        let args = vec![
            "agenix".to_string(),
            "edit".to_string(),
            "nonexistent.age".to_string(),
            "--rules".to_string(),
            "./test_secrets.nix".to_string(),
            "--editor".to_string(),
            "vi".to_string(),
        ];
        let result = agenix::run(args);
        assert!(result.is_err());
    }

    #[test]
    fn test_handle_decrypt_nonexistent_file() {
        let args = vec![
            "agenix".to_string(),
            "decrypt".to_string(),
            "nonexistent.age".to_string(),
            "--rules".to_string(),
            "./test_secrets.nix".to_string(),
        ];
        let result = agenix::run(args);
        assert!(result.is_err());
    }

    #[test]
    fn test_handle_rekey_nonexistent_rules() {
        let args = vec![
            "agenix".to_string(),
            "rekey".to_string(),
            "--rules".to_string(),
            "./test_secrets.nix".to_string(),
        ];
        let result = agenix::run(args);
        assert!(result.is_err());
    }

    #[test]
    fn test_handle_generate_nonexistent_rules() {
        let args = vec![
            "agenix".to_string(),
            "generate".to_string(),
            "--rules".to_string(),
            "./test_secrets.nix".to_string(),
        ];
        let result = agenix::run(args);
        assert!(result.is_err());
    }

    #[test]
    fn test_handle_generate_flag_parsing() {
        let args = vec!["agenix".to_string(), "generate".to_string()];
        let result = agenix::run(args);
        // Should error due to nonexistent default rules file, but subcommand should be parsed correctly
        assert!(result.is_err());

        // Test short alias
        let args = vec!["agenix".to_string(), "g".to_string()];
        let result = agenix::run(args);
        assert!(result.is_err());
    }
}
