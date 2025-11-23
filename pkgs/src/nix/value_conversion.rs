use anyhow::{Result, anyhow};
use snix_eval::Value;

pub fn value_to_string_array(value: Value) -> Result<Vec<String>> {
    match value {
        Value::List(arr) => arr
            .into_iter()
            .map(|v| {
                match v {
                    Value::String(s) => Ok(s.as_str().map(std::string::ToString::to_string)?),
                    Value::Thunk(thunk) => {
                        // Try to extract the value from the thunk
                        let debug_str = format!("{thunk:?}");
                        // Look for pattern: Thunk(RefCell { value: Evaluated(String("...")) })
                        if let Some(start) = debug_str.find("Evaluated(String(\"") {
                            let start = start + "Evaluated(String(\"".len();
                            if let Some(end) = debug_str[start..].find("\"))") {
                                let extracted = &debug_str[start..start + end];
                                return Ok(extracted.to_string());
                            }
                        }
                        Err(anyhow!("Could not extract string from thunk: {thunk:?}"))
                    }
                    _ => Err(anyhow!("Expected string public key, got: {v:?}")),
                }
            })
            .collect::<Result<Vec<_>, _>>(),
        _ => Err(anyhow!(
            "Expected JSON array for public keys, got: {value:?}"
        )),
    }
}

pub fn value_to_string(v: Value) -> Result<String> {
    match v {
        Value::String(s) => Ok(s.as_str().map(std::string::ToString::to_string)?),
        Value::Thunk(thunk) => {
            // Try to extract the value from the thunk
            let debug_str = format!("{thunk:?}");
            // Look for pattern: Thunk(RefCell { value: Evaluated(String("...")) })
            if let Some(start) = debug_str.find("Evaluated(String(\"") {
                let start = start + "Evaluated(String(\"".len();
                if let Some(end) = debug_str[start..].find("\"))") {
                    let extracted = &debug_str[start..start + end];
                    return Ok(extracted.to_string());
                }
            }
            Err(anyhow!("Could not extract string from thunk: {thunk:?}"))
        }
        _ => Err(anyhow!("Expected string public key, got: {v:?}")),
    }
}

pub fn value_to_bool(value: &Value) -> Result<bool> {
    match value {
        Value::Bool(b) => Ok(*b),
        _ => Err(anyhow!("Expected boolean value, got: {value:?}")),
    }
}

pub fn value_to_optional_string(value: Value) -> Result<Option<String>> {
    match value {
        Value::Null => Ok(None),
        _ => value_to_string(value).map(Some),
    }
}
