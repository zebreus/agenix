use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;

fn have(bin: &str) -> bool {
    Command::new(bin).arg("--version").output().is_ok()
}

const TEST_PRIV_KEY: &str = r"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACC9InTb4BornFoLqf5j+/M8gtt7hY2KtHr3FnYxkFGgRwAAAJC2JJ8htiSf
IQAAAAtzc2gtZWQyNTUxOQAAACC9InTb4BornFoLqf5j+/M8gtt7hY2KtHr3FnYxkFGgRw
AAAEDxt5gC/s53IxiKAjfZJVCCcFIsdeERdIgbYhLO719+Kb0idNvgGiucWgup/mP78zyC
23uFjYq0evcWdjGQUaBHAAAADHJ5YW50bUBob21lMQE=
-----END OPENSSH PRIVATE KEY-----
";

const TEST_PUB_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0idNvgGiucWgup/mP78zyC23uFjYq0evcWdjGQUaBH";

#[test]
fn integration_encrypt_then_decrypt_secret() {
    // Skip if required binaries are not available
    if !have("age") || !have("nix-instantiate") {
        eprintln!("skipping integration test: missing age or nix-instantiate");
        return;
    }

    let tmp = tempfile::tempdir().expect("tempdir");
    let tmp_path = tmp.path();

    // Prepare HOME with SSH identity
    let home = tmp_path.join("home");
    let ssh = home.join(".ssh");
    fs::create_dir_all(&ssh).unwrap();

    let key_path = ssh.join("id_ed25519");
    fs::write(&key_path, TEST_PRIV_KEY).unwrap();
    let mut perms = fs::metadata(&key_path).unwrap().permissions();
    perms.set_mode(0o600);
    fs::set_permissions(&key_path, perms).unwrap();

    // Prepare minimal secrets.nix
    let rules_path = tmp_path.join("secrets.nix");
    let rules_content =
        format!("{{\n  \"secret1.age\" = {{ publicKeys = [ \"{TEST_PUB_KEY}\" ]; }};\n}}\n",);
    fs::write(&rules_path, rules_content).unwrap();

    // Create plaintext and encrypt with age
    let plaintext_path = tmp_path.join("message.txt");
    fs::write(&plaintext_path, b"hello\n").unwrap();

    let secret_path = tmp_path.join("secret1.age");
    let status = Command::new("age")
        .args([
            "-r",
            TEST_PUB_KEY,
            "-o",
            secret_path.to_str().unwrap(),
            "--",
            plaintext_path.to_str().unwrap(),
        ])
        .status()
        .expect("run age to encrypt");
    assert!(status.success(), "age encryption failed");

    // Set environment to use our HOME and run from tmp dir
    let old_home = std::env::var("HOME").ok();
    unsafe { std::env::set_var("HOME", &home) };
    let old_cwd: PathBuf = std::env::current_dir().unwrap();
    std::env::set_current_dir(tmp_path).unwrap();

    // Decrypt using public entrypoint with custom identity to a file
    let out_path = tmp_path.join("out.txt");
    let result = agenix::run([
        "agenix",
        "-d",
        "secret1.age",
        "--rules",
        rules_path.to_str().unwrap(),
        "-i",
        key_path.to_str().unwrap(),
        "-o",
        out_path.to_str().unwrap(),
    ]);
    assert!(result.is_ok(), "decrypt should succeed: {:?}", result.err());

    // Restore env
    std::env::set_current_dir(&old_cwd).unwrap();
    match old_home {
        Some(v) => unsafe { std::env::set_var("HOME", v) },
        None => unsafe { std::env::remove_var("HOME") },
    }

    // Assert content
    let stdout = fs::read_to_string(out_path).expect("read decrypted file");
    assert_eq!(stdout, "hello\n");
}
