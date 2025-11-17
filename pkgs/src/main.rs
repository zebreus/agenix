use anyhow::Result;

fn main() -> Result<()> {
    agenix::run(std::env::args())
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_run_no_args_shows_help() {
        let args = vec!["agenix".to_string()];
        let result = agenix::run(args);
        assert!(result.is_ok());
    }

    #[test]
    fn test_run_with_verbose() {
        let args = vec!["agenix".to_string(), "-v".to_string()];
        let result = agenix::run(args);
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_edit_nonexistent_file() {
        let args = vec![
            "agenix".to_string(),
            "-e".to_string(),
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
            "-d".to_string(),
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
            "-r".to_string(),
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
            "-g".to_string(),
            "--rules".to_string(),
            "./test_secrets.nix".to_string(),
        ];
        let result = agenix::run(args);
        assert!(result.is_err());
    }

    #[test]
    fn test_handle_generate_flag_parsing() {
        let args = vec!["agenix".to_string(), "--generate".to_string()];
        let result = agenix::run(args);
        // Should error due to nonexistent default rules file, but flag should be parsed correctly
        assert!(result.is_err());

        // Test short flag
        let args = vec!["agenix".to_string(), "-g".to_string()];
        let result = agenix::run(args);
        assert!(result.is_err());
    }
}
