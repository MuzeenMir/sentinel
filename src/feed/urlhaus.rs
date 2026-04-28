//! URLhaus live-blocklist consumer.
//!
//! Pulls the URLhaus hostfile feed (`<ip> <domain>` per line, comments
//! prefixed with `#`), normalizes each domain, and yields a deduped set
//! ready to swap into a [`crate::feed::BlockList`].
//!
//! The block-page surfaces the listing date (e.g. "Listed in URLhaus
//! since 2026-04-22") per `DESIGN.md` voice. Listing-date metadata
//! lands with the resolver wiring; the parser here only normalizes
//! domains.

use std::collections::HashSet;

use anyhow::{Context, Result};

/// URLhaus public hostfile feed. Plain text, refreshed continuously upstream.
const URLHAUS_HOSTFILE_URL: &str = "https://urlhaus.abuse.ch/downloads/hostfile/";

/// Fetch the URLhaus hostfile and parse it into a deduped domain set.
pub async fn fetch_domains() -> Result<HashSet<String>> {
    let body = reqwest::get(URLHAUS_HOSTFILE_URL)
        .await
        .context("URLhaus hostfile fetch failed")?
        .error_for_status()
        .context("URLhaus hostfile returned non-2xx")?
        .text()
        .await
        .context("URLhaus hostfile body read failed")?;
    Ok(parse_hostfile(&body))
}

/// Parse a hostfile body into a deduped, lowercased domain set.
///
/// Skips:
/// - blank lines
/// - comments (lines starting with `#`)
/// - the `localhost` entry (every hostfile carries one)
/// - empty domain fields after splitting
pub fn parse_hostfile(body: &str) -> HashSet<String> {
    let mut domains = HashSet::new();
    for raw in body.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Format: `<ip>\t<domain>` or `<ip> <domain>`. Anything past the
        // first whitespace run is the domain field.
        let Some((_ip, rest)) = line.split_once(char::is_whitespace) else {
            continue;
        };
        let domain = rest.trim().to_ascii_lowercase();
        if domain.is_empty() || domain == "localhost" {
            continue;
        }
        domains.insert(domain);
    }
    domains
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tab_separated_hostfile() {
        let body = "\
# URLhaus hostfile feed
# Header line two
127.0.0.1\tmalicious.example
127.0.0.1\tEvil-Domain.test
0.0.0.0\tphish.example.com

# trailing comment
";
        let domains = parse_hostfile(body);
        assert!(domains.contains("malicious.example"));
        assert!(domains.contains("evil-domain.test"));
        assert!(domains.contains("phish.example.com"));
        assert_eq!(domains.len(), 3);
    }

    #[test]
    fn parses_space_separated_hostfile() {
        let body = "127.0.0.1 a.example\n0.0.0.0 b.example\n";
        let domains = parse_hostfile(body);
        assert!(domains.contains("a.example"));
        assert!(domains.contains("b.example"));
    }

    #[test]
    fn skips_comments_blank_lines_and_localhost() {
        let body = "\
# header
127.0.0.1 localhost
::1 localhost

127.0.0.1 real.example
";
        let domains = parse_hostfile(body);
        assert!(!domains.contains("localhost"));
        assert!(domains.contains("real.example"));
        assert_eq!(domains.len(), 1);
    }

    #[test]
    fn lowercases_uppercase_input() {
        let body = "127.0.0.1 EXAMPLE.COM\n127.0.0.1 example.com\n";
        let domains = parse_hostfile(body);
        // Both lines collapse to the same key.
        assert_eq!(domains.len(), 1);
        assert!(domains.contains("example.com"));
    }

    #[test]
    fn ignores_lines_without_a_domain_field() {
        let body = "127.0.0.1\n# nope\nbad-line-no-whitespace\n";
        let domains = parse_hostfile(body);
        assert!(domains.is_empty());
    }
}
