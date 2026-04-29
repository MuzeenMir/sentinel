//! Threat-feed integration.
//!
//! Wires up URLhaus (live blocklist) and a Tranco-anchored allowlist.
//! T2 in `TODOS.md` adds quarterly Tranco baseline auto-refresh.

pub mod tranco;
pub mod urlhaus;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::sleep;

/// Steady-state URLhaus refresh cadence. URLhaus is updated continuously
/// upstream; six hours keeps the local list fresh without hammering the
/// feed.
const URLHAUS_REFRESH_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);

/// Retry cadence after a failed fetch. Far shorter than the steady-state
/// interval so a transient first-boot network hiccup doesn't leave the
/// resolver running with an empty blocklist for hours.
const URLHAUS_RETRY_AFTER_FAILURE: Duration = Duration::from_secs(5 * 60);

/// Per-domain block metadata surfaced on the block-page (listing date,
/// threat classification). Populated from URLhaus's CSV feed when
/// available; left empty when we fall back to the hostfile feed.
///
/// `listed_date` is `YYYY-MM-DD` per `DESIGN.md` block-page copy.
/// `threat_type` is URLhaus's snake_case classification
/// (e.g. `malware_download`, `phishing`); the resolver humanizes it
/// for display.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlockMetadata {
    pub listed_date: String,
    pub threat_type: String,
}

/// Shared, reader-friendly blocklist. Cheap to clone — wraps an `Arc`.
///
/// Many readers (resolver hot path, block-page server) hit it concurrently;
/// the writer (feed refresher) swaps the inner map wholesale on each cycle.
///
/// Domain key is always lowercase. The metadata value is empty for entries
/// sourced from the hostfile fallback (no listing date upstream).
pub type BlockList = Arc<RwLock<HashMap<String, BlockMetadata>>>;

/// Construct an empty `BlockList`.
pub fn new_blocklist() -> BlockList {
    Arc::new(RwLock::new(HashMap::new()))
}

/// Refresh URLhaus.
///
/// Tries the CSV feed first (carries `dateadded` + `threat`), falls back
/// to the hostfile feed (domain-only, no metadata) if CSV is unreachable
/// or returns an empty payload. Wholesale-replaces the blocklist contents
/// and returns the new entry count.
pub async fn refresh_urlhaus(blocklist: &BlockList) -> anyhow::Result<usize> {
    let new_map = match urlhaus::fetch_csv_online().await {
        Ok(m) if !m.is_empty() => m,
        Ok(_) => {
            eprintln!("urlhaus: csv_online returned empty payload, falling back to hostfile");
            hostfile_to_metadata_map(urlhaus::fetch_domains().await?)
        }
        Err(e) => {
            eprintln!("urlhaus: csv_online fetch failed ({e:#}), falling back to hostfile");
            hostfile_to_metadata_map(urlhaus::fetch_domains().await?)
        }
    };
    let count = new_map.len();
    let mut guard = blocklist.write().await;
    *guard = new_map;
    Ok(count)
}

/// Long-running URLhaus refresher loop. Refreshes on entry, then sleeps
/// `URLHAUS_REFRESH_INTERVAL` between successful cycles and
/// `URLHAUS_RETRY_AFTER_FAILURE` between failed ones.
///
/// Fail-open: if URLhaus is unreachable the blocklist stays at its last
/// known contents (empty on first boot) and every domain forwards to
/// upstream. We log the failure but never propagate it — "nothing
/// blocked yet" beats "DNS service refused to start because of an ISP
/// hiccup at install time."
///
/// `Ok(())` is unreachable in practice — the loop runs for the lifetime
/// of the process. The `Result<()>` shape matches the resolver /
/// blockpage tasks so the supervising `tokio::select!` can treat all
/// three uniformly.
pub async fn run_urlhaus_refresher(blocklist: BlockList) -> anyhow::Result<()> {
    loop {
        match refresh_urlhaus(&blocklist).await {
            Ok(count) => {
                eprintln!("urlhaus: loaded {count} domains");
                sleep(URLHAUS_REFRESH_INTERVAL).await;
            }
            Err(e) => {
                eprintln!(
                    "urlhaus: refresh failed: {e:#}; retrying in {:?}",
                    URLHAUS_RETRY_AFTER_FAILURE
                );
                sleep(URLHAUS_RETRY_AFTER_FAILURE).await;
            }
        }
    }
}

/// Look `domain` up in `blocklist`. Returns the per-domain metadata
/// (listing date, threat type) when blocked, or `None` when allowed.
///
/// Domains are stored lowercase at insertion time, so the lookup
/// lower-cases too.
pub async fn lookup(blocklist: &BlockList, domain: &str) -> Option<BlockMetadata> {
    blocklist.read().await.get(&domain.to_lowercase()).cloned()
}

/// Convenience wrapper: presence-only check. Used by call sites that
/// just need a yes/no decision (and tests).
pub async fn is_blocked(blocklist: &BlockList, domain: &str) -> bool {
    lookup(blocklist, domain).await.is_some()
}

/// Convert a hostfile domain set into a metadata map with empty
/// metadata fields. Used as fallback when the CSV feed is unreachable;
/// the resolver substitutes a `—` placeholder for any empty
/// `listed_date` so the page still renders cleanly.
fn hostfile_to_metadata_map(domains: HashSet<String>) -> HashMap<String, BlockMetadata> {
    domains
        .into_iter()
        .map(|d| (d, BlockMetadata::default()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn empty_blocklist_blocks_nothing() {
        let bl = new_blocklist();
        assert!(!is_blocked(&bl, "example.com").await);
        assert!(lookup(&bl, "example.com").await.is_none());
    }

    #[tokio::test]
    async fn manual_insert_then_lookup_is_case_insensitive() {
        let bl = new_blocklist();
        bl.write().await.insert(
            "malicious.example".to_string(),
            BlockMetadata {
                listed_date: "2026-04-22".to_string(),
                threat_type: "malware_download".to_string(),
            },
        );
        assert!(is_blocked(&bl, "malicious.example").await);
        assert!(is_blocked(&bl, "MALICIOUS.EXAMPLE").await);
        assert!(!is_blocked(&bl, "benign.example").await);

        let meta = lookup(&bl, "Malicious.Example").await.unwrap();
        assert_eq!(meta.listed_date, "2026-04-22");
        assert_eq!(meta.threat_type, "malware_download");
    }

    #[test]
    fn hostfile_fallback_yields_empty_metadata() {
        let mut set = HashSet::new();
        set.insert("a.example".to_string());
        set.insert("b.example".to_string());
        let map = hostfile_to_metadata_map(set);
        assert_eq!(map.len(), 2);
        for (_, meta) in map {
            assert!(meta.listed_date.is_empty());
            assert!(meta.threat_type.is_empty());
        }
    }
}
