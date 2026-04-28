//! Sentinel — open-source DNS shield for Windows.
//!
//! Pre-v0.1 skeleton. Modules below are intentionally placeholders so the
//! crate compiles cleanly on Linux + Windows CI while v0.1 sprint code is
//! written. Each module's surface is sketched in `DESIGN.md`; behaviour
//! lands per the `TODOS.md` v0.1 checklist.

pub mod blockpage;
pub mod feed;
pub mod resolver;

/// Crate version, sourced from `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
