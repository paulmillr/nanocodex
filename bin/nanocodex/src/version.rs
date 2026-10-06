//! Build and version information for the Nanocodex CLI.

/// Compact CLI version displayed by `nanocodex --version`.
pub(crate) const SHORT_VERSION: &str = env!("NANOCODEX_SHORT_VERSION");

/// Detailed CLI version displayed by the long version flag.
pub(crate) const LONG_VERSION: &str = concat!(
    env!("NANOCODEX_LONG_VERSION_0"),
    "\n",
    env!("NANOCODEX_LONG_VERSION_1"),
    "\n",
    env!("NANOCODEX_LONG_VERSION_2"),
    "\n",
    env!("NANOCODEX_LONG_VERSION_3"),
);
