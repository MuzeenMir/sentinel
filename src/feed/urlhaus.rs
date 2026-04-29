//! URLhaus live-blocklist consumer.
//!
//! Two feed paths:
//!
//! * **CSV (`csv_online`)** — preferred. Carries `dateadded` and
//!   `threat` per URL so the block-page can surface "Listed in URLhaus
//!   since 2026-04-22 (6 days ago)" and "malware download" instead of
//!   placeholder copy. Currently-online URLs only (~3 MB plain text);
//!   offline URLs are dropped because blocking a dead host is a no-op.
//! * **Hostfile** — fallback when the CSV endpoint is unreachable.
//!   Domain-only, no metadata; the resolver substitutes a `—`
//!   placeholder so the page still renders.

use std::collections::{HashMap, HashSet};

use anyhow::{Context, Result};

use crate::feed::BlockMetadata;

/// URLhaus public hostfile feed. Plain text, refreshed continuously upstream.
const URLHAUS_HOSTFILE_URL: &str = "https://urlhaus.abuse.ch/downloads/hostfile/";

/// URLhaus CSV feed, currently-online URLs only. Plain text, 9 columns:
/// `id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter`.
const URLHAUS_CSV_ONLINE_URL: &str = "https://urlhaus.abuse.ch/downloads/csv_online/";

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

/// Fetch the URLhaus CSV (online URLs only) and parse it into a
/// `domain -> metadata` map.
pub async fn fetch_csv_online() -> Result<HashMap<String, BlockMetadata>> {
    let body = reqwest::get(URLHAUS_CSV_ONLINE_URL)
        .await
        .context("URLhaus csv_online fetch failed")?
        .error_for_status()
        .context("URLhaus csv_online returned non-2xx")?
        .text()
        .await
        .context("URLhaus csv_online body read failed")?;
    Ok(parse_csv_online(&body))
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

/// Parse a URLhaus `csv_online` body into a deduped `domain -> metadata`
/// map.
///
/// CSV columns (9): `id, dateadded, url, url_status, last_online,
/// threat, tags, urlhaus_link, reporter`. We read fields 1 (dateadded),
/// 2 (url), and 5 (threat); the rest are ignored.
///
/// Skips comment lines (`#`) and rows shorter than 6 fields. On
/// duplicate domains — the same domain appearing under multiple URLs —
/// keeps the EARLIEST `dateadded`, matching the block-page copy
/// "Listed in URLhaus since YYYY-MM-DD".
pub fn parse_csv_online(body: &str) -> HashMap<String, BlockMetadata> {
    let mut domains: HashMap<String, BlockMetadata> = HashMap::new();
    for raw in body.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields = parse_csv_line(line);
        if fields.len() < 6 {
            continue;
        }
        // Some URLhaus dumps include an inline header row; skip it
        // defensively.
        if fields[0].eq_ignore_ascii_case("id") {
            continue;
        }
        let dateadded_full = &fields[1];
        let url = &fields[2];
        let threat = &fields[5];

        let Some(domain) = domain_from_url(url) else {
            continue;
        };
        // URLhaus dateadded is `YYYY-MM-DD HH:MM:SS UTC`. We only show the
        // calendar date on the block-page, so the time portion is
        // truncated here at parse time.
        let listed_date = dateadded_full
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_string();
        if listed_date.is_empty() {
            continue;
        }
        let metadata = BlockMetadata {
            listed_date: listed_date.clone(),
            threat_type: threat.clone(),
        };
        domains
            .entry(domain)
            .and_modify(|existing| {
                // Lexicographic comparison of `YYYY-MM-DD` is also
                // chronological, so this keeps the earliest listing.
                if listed_date < existing.listed_date {
                    *existing = metadata.clone();
                }
            })
            .or_insert(metadata);
    }
    domains
}

/// Minimal RFC-4180-ish single-line CSV parser. Handles quoted fields
/// with embedded commas and doubled-quote escaping. Does NOT handle
/// newlines inside quoted fields — URLhaus does not embed newlines in
/// any of its columns, and we already split on lines upstream.
fn parse_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match (c, in_quotes) {
            ('"', true) => {
                // Doubled quote inside a quoted field is an escaped quote.
                if chars.peek() == Some(&'"') {
                    current.push('"');
                    chars.next();
                } else {
                    in_quotes = false;
                }
            }
            ('"', false) => in_quotes = true,
            (',', false) => {
                fields.push(std::mem::take(&mut current));
            }
            (other, _) => current.push(other),
        }
    }
    fields.push(current);
    fields
}

/// Extract the lowercased host portion of a URL. Strips the scheme,
/// any `user@` segment, port, and path/query/fragment. Bracketed IPv6
/// literals (`[::1]`) are returned without the brackets. Returns
/// `None` for inputs without a `://` separator or with an empty host.
fn domain_from_url(url: &str) -> Option<String> {
    let after_scheme = url.split_once("://")?.1;
    let host_segment = after_scheme.split(['/', '?', '#']).next()?;
    let host_segment = host_segment
        .rsplit_once('@')
        .map_or(host_segment, |(_, h)| h);
    if let Some(rest) = host_segment.strip_prefix('[') {
        // IPv6 literal: `[<addr>]:port`. Take everything up to `]`.
        let (host, _) = rest.split_once(']')?;
        if host.is_empty() {
            return None;
        }
        return Some(host.to_ascii_lowercase());
    }
    // IPv4 / domain. Strip the `:port` suffix if present.
    let host = host_segment
        .rsplit_once(':')
        .map_or(host_segment, |(h, _)| h);
    if host.is_empty() {
        return None;
    }
    Some(host.to_ascii_lowercase())
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

    #[test]
    fn parse_csv_line_handles_quotes_and_embedded_commas() {
        let line = r#""3018000","2026-04-22 12:34:56","http://evil.example/p?q=a,b","online","2026-04-22 12:34:56","malware_download""#;
        let fields = parse_csv_line(line);
        assert_eq!(fields.len(), 6);
        assert_eq!(fields[0], "3018000");
        assert_eq!(fields[1], "2026-04-22 12:34:56");
        assert_eq!(fields[2], "http://evil.example/p?q=a,b");
        assert_eq!(fields[3], "online");
        assert_eq!(fields[4], "2026-04-22 12:34:56");
        assert_eq!(fields[5], "malware_download");
    }

    #[test]
    fn parse_csv_line_handles_doubled_quote_escape() {
        // RFC 4180: a quote inside a quoted field is escaped by doubling.
        let line = r#""x","say ""hi""","y""#;
        let fields = parse_csv_line(line);
        assert_eq!(fields, vec!["x", r#"say "hi""#, "y"]);
    }

    #[test]
    fn domain_from_url_strips_scheme_path_query_port() {
        assert_eq!(
            domain_from_url("http://evil.example.com/payload.exe"),
            Some("evil.example.com".to_string())
        );
        assert_eq!(
            domain_from_url("https://Evil.Example.com:8443/x?q=1#frag"),
            Some("evil.example.com".to_string())
        );
        assert_eq!(
            domain_from_url("http://user:pass@host.example/p"),
            Some("host.example".to_string())
        );
        assert_eq!(
            domain_from_url("http://192.0.2.10:80/x"),
            Some("192.0.2.10".to_string())
        );
        assert_eq!(
            domain_from_url("http://[2001:db8::1]:8080/x"),
            Some("2001:db8::1".to_string())
        );
    }

    #[test]
    fn domain_from_url_returns_none_for_malformed_input() {
        assert!(domain_from_url("not a url").is_none());
        assert!(domain_from_url("http:///path").is_none());
        assert!(domain_from_url("").is_none());
    }

    #[test]
    fn parse_csv_online_extracts_metadata_and_dedupes_to_earliest() {
        // URLhaus csv_online schema: id, dateadded, url, url_status,
        // last_online, threat, tags, urlhaus_link, reporter.
        let body = r#"# URLhaus database dump (CSV) - online URLs only
# Last updated: 2026-04-29 12:00:00 UTC
#
"3018000","2026-04-22 12:34:56","http://evil.example/a.exe","online","2026-04-22 13:00:00","malware_download","exe","https://urlhaus.abuse.ch/url/3018000/","reporter1"
"3018001","2026-04-25 09:00:00","http://evil.example/b.exe","online","2026-04-25 09:30:00","malware_download","exe","https://urlhaus.abuse.ch/url/3018001/","reporter2"
"3018002","2026-04-26 11:11:11","http://phish.example.com/login","online","2026-04-26 11:30:00","phishing","creds","https://urlhaus.abuse.ch/url/3018002/","reporter3"
"#;
        let map = parse_csv_online(body);
        assert_eq!(map.len(), 2);
        // Same domain on two URLs — earliest dateadded wins.
        let evil = map.get("evil.example").expect("evil.example present");
        assert_eq!(evil.listed_date, "2026-04-22");
        assert_eq!(evil.threat_type, "malware_download");
        let phish = map
            .get("phish.example.com")
            .expect("phish.example.com present");
        assert_eq!(phish.listed_date, "2026-04-26");
        assert_eq!(phish.threat_type, "phishing");
    }

    #[test]
    fn parse_csv_online_skips_comments_blanks_and_short_rows() {
        let body = r#"# header
# more header

"too","short"
"3018000","2026-04-22 12:34:56","http://ok.example/x","online","2026-04-22 13:00:00","malware_download"
"#;
        let map = parse_csv_online(body);
        assert_eq!(map.len(), 1);
        assert!(map.contains_key("ok.example"));
    }

    #[test]
    fn parse_csv_online_skips_inline_header_row() {
        let body = r#""id","dateadded","url","url_status","last_online","threat","tags","urlhaus_link","reporter"
"3018000","2026-04-22 12:34:56","http://ok.example/x","online","2026-04-22 13:00:00","malware_download","exe","https://urlhaus.abuse.ch/url/3018000/","reporter1"
"#;
        let map = parse_csv_online(body);
        assert_eq!(map.len(), 1);
        assert!(map.contains_key("ok.example"));
    }

    #[test]
    fn parse_csv_online_does_not_confuse_last_online_with_threat() {
        // Regression: an earlier version of this parser read `threat`
        // from index 4, which is `last_online` in the 9-column schema.
        // The block-page surfaced the timestamp as the threat label.
        let body = r#""3018000","2026-04-22 12:34:56","http://evil.example/a.exe","online","2026-04-22 13:00:00","malware_download","exe","https://urlhaus.abuse.ch/url/3018000/","reporter"
"#;
        let map = parse_csv_online(body);
        let meta = map.get("evil.example").expect("evil.example present");
        assert_eq!(meta.listed_date, "2026-04-22");
        assert_eq!(meta.threat_type, "malware_download");
        assert_ne!(meta.threat_type, "2026-04-22 13:00:00");
    }
}
