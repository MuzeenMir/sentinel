//! Threat-feed integration.
//!
//! Wires up URLhaus (live blocklist) and a Tranco-anchored allowlist.
//! T2 in `TODOS.md` adds quarterly Tranco baseline auto-refresh.

pub mod tranco;
pub mod urlhaus;

use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Shared, reader-friendly blocklist. Cheap to clone — wraps an `Arc`.
///
/// Many readers (resolver hot path, block-page server) hit it concurrently;
/// the writer (feed refresher) swaps the inner set wholesale on each cycle.
pub type BlockList = Arc<RwLock<HashSet<String>>>;

/// Construct an empty `BlockList`.
pub fn new_blocklist() -> BlockList {
    Arc::new(RwLock::new(HashSet::new()))
}

/// Fetch URLhaus and replace `blocklist`'s contents wholesale.
///
/// Returns the number of domains in the new set.
pub async fn refresh_urlhaus(blocklist: &BlockList) -> anyhow::Result<usize> {
    let domains = urlhaus::fetch_domains().await?;
    let count = domains.len();
    let mut guard = blocklist.write().await;
    *guard = domains;
    Ok(count)
}

/// Look `domain` up in `blocklist`. Domains are normalized to lowercase
/// at insertion time, so the lookup lower-cases too.
pub async fn is_blocked(blocklist: &BlockList, domain: &str) -> bool {
    blocklist.read().await.contains(&domain.to_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn empty_blocklist_blocks_nothing() {
        let bl = new_blocklist();
        assert!(!is_blocked(&bl, "example.com").await);
    }

    #[tokio::test]
    async fn manual_insert_then_lookup_is_case_insensitive() {
        let bl = new_blocklist();
        bl.write().await.insert("malicious.example".to_string());
        assert!(is_blocked(&bl, "malicious.example").await);
        assert!(is_blocked(&bl, "MALICIOUS.EXAMPLE").await);
        assert!(!is_blocked(&bl, "benign.example").await);
    }
}
