//! Shims to provide compatibility with different systems.

// nix does not support daemon(3) on macOS, so we have to provide our own implementation:
#[cfg(target_os = "macos")]
mod daemon;
#[cfg(target_os = "macos")]
pub use daemon::daemon;

// Use nix's daemon(3) wrapper on other platforms:
#[cfg(not(target_os = "macos"))]
pub use nix::unistd::daemon;
