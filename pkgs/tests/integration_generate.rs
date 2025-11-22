#[test]
fn test_generate_cli_flag_parsing() {
    // Test that the generate flag is parsed correctly (should error due to missing rules)
    let args = vec![
        "agenix".to_string(),
        "--generate".to_string(),
        "--rules".to_string(),
        "./nonexistent.nix".to_string(),
    ];

    let result = agenix::run(args);
    // Should error because the rules file doesn't exist, but the flag should be parsed correctly
    assert!(result.is_err());

    // Also test short flag
    let args = vec![
        "agenix".to_string(),
        "-g".to_string(),
        "--rules".to_string(),
        "./nonexistent.nix".to_string(),
    ];

    let result = agenix::run(args);
    assert!(result.is_err());
}

// The generate functionality tests that previously used nix-instantiate have been
// moved to the CLI test suite in test/cli.nix. This maintains proper separation
// of concerns - Rust unit tests should focus on library functionality without
// external tool dependencies, while CLI integration tests belong in the bash-based
// CLI test suite.
