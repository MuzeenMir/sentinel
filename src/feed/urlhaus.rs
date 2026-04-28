//! URLhaus live-blocklist consumer.
//!
//! Polls the URLhaus feed, normalizes domains, and feeds the resolver's
//! block-decision path. Block-page surfaces the listing date (e.g.
//! "Listed in URLhaus since 2026-04-22") per `DESIGN.md` voice.
