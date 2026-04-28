//! Local DNS resolver bound to `127.0.0.1:53`.
//!
//! Intercepts system DNS (set by installer), looks each query up against
//! the allowlist + blocklist, and either forwards upstream
//! (Cloudflare 1.1.1.1 with Quad9 9.9.9.9 failover) or sinkholes the
//! response to `127.0.0.1` so the block-page server takes over.
