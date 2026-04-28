//! Threat-feed integration.
//!
//! v0.1 wires up URLhaus (live blocklist) and a Tranco-anchored allowlist.
//! T2 in `TODOS.md` adds quarterly Tranco baseline auto-refresh.

pub mod tranco;
pub mod urlhaus;
