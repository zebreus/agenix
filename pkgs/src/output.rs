//! Output and logging utilities for agenix.
//!
//! This module provides centralized output handling with support for quiet and verbose modes.
//! All output to stderr should go through these utilities to ensure consistent behavior.
//!
//! ## Output Macros
//!
//! - **verbose!**: Detailed debugging information, only shown when `-v` is passed
//! - **log!**: Normal output messages, suppressed in quiet mode
//!
//! ## Quiet Mode Behavior by Command
//!
//! | Command         | Normal Mode                    | Quiet Mode                       |
//! |-----------------|--------------------------------|----------------------------------|
//! | list            | Secret list + summary          | Secret list only (no summary)    |
//! | check           | Progress + results + summary   | Nothing (exit code only)         |
//! | generate        | Progress per secret            | Nothing (exit code only)         |
//! | generate --dry-run | What would be generated     | Nothing (no actual changes)      |
//! | rekey           | Progress per secret            | Nothing (exit code only)         |
//! | edit            | Warnings if unchanged          | Nothing (exit code only)         |
//! | encrypt         | Nothing                        | Nothing                          |
//! | decrypt         | Content to stdout              | Content to stdout (unchanged)    |
//! | completions     | Completions to stdout          | Completions to stdout (unchanged)|
//!
//! Note: Actual content output (decrypt, completions, list) goes to stdout and is never suppressed.
//! Error messages always go to stderr and are never suppressed by quiet mode.

use std::sync::atomic::{AtomicBool, Ordering};

/// Global verbosity flag - set via command line
static VERBOSE: AtomicBool = AtomicBool::new(false);

/// Global quiet flag - set via command line
static QUIET: AtomicBool = AtomicBool::new(false);

/// Check if verbose output is enabled
pub fn is_verbose() -> bool {
    VERBOSE.load(Ordering::Relaxed)
}

/// Check if quiet mode is enabled
pub fn is_quiet() -> bool {
    QUIET.load(Ordering::Relaxed)
}

/// Set the verbose flag
pub fn set_verbose(value: bool) {
    VERBOSE.store(value, Ordering::Relaxed);
}

/// Set the quiet flag
pub fn set_quiet(value: bool) {
    QUIET.store(value, Ordering::Relaxed);
}

/// Print a message only if verbose mode is enabled.
///
/// Use for detailed debugging information that's only useful when troubleshooting.
///
/// # Example
/// ```ignore
/// verbose!("Using rules file: {}", rules_path);
/// verbose!("Processing {} files", count);
/// ```
#[macro_export]
macro_rules! verbose {
    ($($arg:tt)*) => {
        if $crate::output::is_verbose() {
            eprintln!($($arg)*);
        }
    };
}

/// Print a message only if quiet mode is NOT enabled.
///
/// Use for normal output messages that users would typically want to see.
/// This includes informational messages, progress updates, warnings, and success messages.
///
/// # Example
/// ```ignore
/// log!("Generating secret...");
/// log!("✓ secret verified");
/// log!("Warning: File was not modified");
/// log!("Successfully rekeyed {} secrets", count);
/// ```
#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => {
        if !$crate::output::is_quiet() {
            eprintln!($($arg)*);
        }
    };
}

/// Helper for correct pluralization of "secret(s)".
///
/// Returns "secret" for count == 1, "secrets" otherwise.
///
/// # Example
/// ```ignore
/// println!("Found {} {}", count, pluralize_secret(count));
/// // "Found 1 secret" or "Found 3 secrets"
/// ```
pub fn pluralize_secret(count: usize) -> &'static str {
    if count == 1 { "secret" } else { "secrets" }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: These tests need to be careful about global state.
    // We reset flags after each test.

    fn reset_flags() {
        set_verbose(false);
        set_quiet(false);
    }

    #[test]
    fn test_default_flags() {
        reset_flags();
        assert!(!is_verbose());
        assert!(!is_quiet());
    }

    #[test]
    fn test_set_verbose() {
        reset_flags();
        set_verbose(true);
        assert!(is_verbose());
        set_verbose(false);
        assert!(!is_verbose());
    }

    #[test]
    fn test_set_quiet() {
        reset_flags();
        set_quiet(true);
        assert!(is_quiet());
        set_quiet(false);
        assert!(!is_quiet());
    }

    #[test]
    fn test_verbose_and_quiet_independent() {
        reset_flags();
        set_verbose(true);
        set_quiet(true);
        assert!(is_verbose());
        assert!(is_quiet());
        reset_flags();
    }

    #[test]
    fn test_pluralize_secret_zero() {
        assert_eq!(pluralize_secret(0), "secrets");
    }

    #[test]
    fn test_pluralize_secret_one() {
        assert_eq!(pluralize_secret(1), "secret");
    }

    #[test]
    fn test_pluralize_secret_many() {
        assert_eq!(pluralize_secret(2), "secrets");
        assert_eq!(pluralize_secret(10), "secrets");
        assert_eq!(pluralize_secret(100), "secrets");
    }
}
