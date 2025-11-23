use snix_eval::builtin_macros;

#[builtin_macros::builtins]
pub(crate) mod impure_builtins {
    use rand::Rng;
    use rand::distr::Alphanumeric;
    use rand::rng;
    use snix_eval::ErrorKind;
    use snix_eval::NixString;
    use snix_eval::Value;
    use snix_eval::generators::Gen;
    use snix_eval::generators::GenCo;

    /// Generates a random alphanumeric string of given length
    #[builtin("randomString")]
    async fn builtin_random_string(co: GenCo, var: Value) -> Result<Value, ErrorKind> {
        let length = var.as_int()?;
        if length < 0 && length > 2i64.pow(16) {
            // TODO use better error kind
            return Err(ErrorKind::Abort(
                "Length for randomString must be between 0 and 2^16".to_string(),
            ));
        }

        let random_string: String = rng()
            .sample_iter(&Alphanumeric)
            .take(usize::try_from(length).unwrap())
            .map(char::from)
            .collect();
        Ok(Value::String(NixString::from(random_string.as_bytes())))
    }

    /// Generates an SSH Ed25519 keypair
    #[builtin("sshKey")]
    async fn builtin_ssh_key(co: GenCo, _var: Value) -> Result<Value, ErrorKind> {
        use snix_eval::NixAttrs;
        use std::collections::BTreeMap;

        use super::super::keypair::generate_ed25519_keypair;

        // Generate the SSH keypair
        let (private_key, public_key) = generate_ed25519_keypair()
            .map_err(|e| ErrorKind::Abort(format!("Failed to generate SSH keypair: {}", e)))?;

        // Create a Nix attribute set with `secret` and `public`
        let mut attrs: BTreeMap<NixString, Value> = BTreeMap::new();
        attrs.insert(
            NixString::from("secret".as_bytes()),
            Value::String(NixString::from(private_key.as_bytes())),
        );
        attrs.insert(
            NixString::from("public".as_bytes()),
            Value::String(NixString::from(public_key.as_bytes())),
        );

        Ok(Value::Attrs(Box::new(NixAttrs::from(attrs))))
    }

    /// Generates an age x25519 keypair
    #[builtin("ageKey")]
    async fn builtin_age_key(co: GenCo, _var: Value) -> Result<Value, ErrorKind> {
        use snix_eval::NixAttrs;
        use std::collections::BTreeMap;

        use super::super::keypair::generate_age_x25519_keypair;

        // Generate the age x25519 keypair
        let (private_key, public_key) = generate_age_x25519_keypair()
            .map_err(|e| ErrorKind::Abort(format!("Failed to generate age keypair: {}", e)))?;

        // Create a Nix attribute set with `secret` and `public`
        let mut attrs: BTreeMap<NixString, Value> = BTreeMap::new();
        attrs.insert(
            NixString::from("secret".as_bytes()),
            Value::String(NixString::from(private_key.as_bytes())),
        );
        attrs.insert(
            NixString::from("public".as_bytes()),
            Value::String(NixString::from(public_key.as_bytes())),
        );

        Ok(Value::Attrs(Box::new(NixAttrs::from(attrs))))
    }
}
