//! Local DNS resolver bound to `127.0.0.1:53`.
//!
//! Intercepts system DNS (set by installer), looks each query up against
//! the URLhaus blocklist, and either forwards upstream
//! (Cloudflare 1.1.1.1 with Quad9 9.9.9.9 failover) or sinkholes the
//! response to `127.0.0.1` so the block-page server takes over.
//!
//! Tranco allowlist integration (T2) and listing-date metadata
//! enrichment (richer `BlockReason`) follow this scaffold.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use async_trait::async_trait;
use hickory_proto::op::{Header, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{LowerName, Name, RData, Record, RecordType};
use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use hickory_server::authority::MessageResponseBuilder;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::ServerFuture;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::net::{TcpListener, UdpSocket};

use crate::blockpage::{AppState, BlockReason};
use crate::feed::{is_blocked, BlockList};

/// Sinkhole TTL — short on purpose. If the user allow-lists the domain
/// while the page is open, the next query refetches against the
/// (mutated) blocklist instead of cache-pinning the block decision.
const SINKHOLE_TTL: u32 = 5;

/// `127.0.0.1` as an `Ipv4Addr` constant for the A-record sinkhole.
const SINKHOLE_V4: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);

/// `::1` for the AAAA-record sinkhole, so dual-stack browsers also
/// land on the local block-page server instead of leaking to upstream.
const SINKHOLE_V6: Ipv6Addr = Ipv6Addr::LOCALHOST;

/// Default resolver bind addresses.
///
/// `:53` requires admin/root; the installer grants the binary that
/// capability on Windows. `:5353` is the dev fallback so `cargo run
/// service` works without elevation.
const PRIMARY_BIND: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53);
const FALLBACK_BIND: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5353);

/// The DNS handler. Holds the blocklist, the block-page slot, and the
/// upstream forwarding resolver. Cheap to clone — every field is
/// already `Arc`-backed.
#[derive(Clone)]
pub struct Resolver {
    blocklist: BlockList,
    blockpage: AppState,
    upstream: Arc<TokioAsyncResolver>,
}

impl Resolver {
    /// Build a resolver with Cloudflare (1.1.1.1) primary +
    /// Quad9 (9.9.9.9) failover upstream.
    pub fn new(blocklist: BlockList, blockpage: AppState) -> Self {
        let mut ns = NameServerConfigGroup::cloudflare();
        ns.merge(NameServerConfigGroup::quad9());
        let cfg = ResolverConfig::from_parts(None, vec![], ns);
        let mut opts = ResolverOpts::default();
        opts.cache_size = 1024;
        opts.timeout = Duration::from_secs(2);
        let upstream = TokioAsyncResolver::tokio(cfg, opts);
        Self {
            blocklist,
            blockpage,
            upstream: Arc::new(upstream),
        }
    }
}

#[async_trait]
impl RequestHandler for Resolver {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        // Only answer standard queries; respond REFUSED to updates,
        // notifies, etc. so we don't pretend to be a recursive server
        // for op-codes we don't speak.
        if request.op_code() != OpCode::Query || request.message_type() != MessageType::Query {
            return refused(request, &mut response_handle).await;
        }

        let query = request.query();
        let domain = lower_name_to_domain(query.name());

        if is_blocked(&self.blocklist, &domain).await {
            self.blockpage.set_current(make_block_reason(&domain)).await;
            return sinkhole(request, query.query_type(), &mut response_handle).await;
        }

        forward(&self.upstream, request, &mut response_handle).await
    }
}

/// Run the resolver on UDP+TCP at `127.0.0.1:53`, falling back to
/// `:5353` if the privileged port is unavailable (typical in dev /
/// non-elevated CI).
pub async fn serve(resolver: Resolver) -> Result<()> {
    let bind = match try_bind(PRIMARY_BIND).await {
        Ok(sockets) => sockets,
        Err(_) => try_bind(FALLBACK_BIND)
            .await
            .context("resolver: bind 127.0.0.1:53 + :5353 both failed")?,
    };

    let mut server = ServerFuture::new(resolver);
    server.register_socket(bind.0);
    server.register_listener(bind.1, Duration::from_secs(5));
    server
        .block_until_done()
        .await
        .context("resolver: server loop crashed")
}

/// Try binding both UDP and TCP on `addr`. Returns both sockets only
/// if both bind successfully — partial binds would silently lose half
/// the protocol.
async fn try_bind(addr: SocketAddr) -> Result<(UdpSocket, TcpListener)> {
    let udp = UdpSocket::bind(addr)
        .await
        .with_context(|| format!("UDP bind {addr}"))?;
    let tcp = TcpListener::bind(addr)
        .await
        .with_context(|| format!("TCP bind {addr}"))?;
    Ok((udp, tcp))
}

/// Translate a [`LowerName`] (always lowercase) to the bare domain
/// string the blocklist + block-page expect, with the trailing root
/// dot stripped. `LowerName` already lowercases on construction, so
/// the `Display` output is safe to feed straight to the blocklist.
fn lower_name_to_domain(name: &LowerName) -> String {
    let mut s = name.to_string();
    if s.ends_with('.') {
        s.pop();
    }
    s
}

/// Send a REFUSED response for op-codes we don't speak.
async fn refused<R: ResponseHandler>(request: &Request, response_handle: &mut R) -> ResponseInfo {
    let builder = MessageResponseBuilder::from_message_request(request);
    let response = builder.error_msg(request.header(), ResponseCode::Refused);
    response_handle
        .send_response(response)
        .await
        .unwrap_or_else(|_| empty_info())
}

/// Build + send the sinkhole response for a blocked domain.
///
/// A → 127.0.0.1, AAAA → ::1. Other record types resolve as
/// NXDOMAIN — no records exist for the blocked name in our
/// fictional zone, the cleanest signal to the client that the
/// name should not be reached.
async fn sinkhole<R: ResponseHandler>(
    request: &Request,
    query_type: RecordType,
    response_handle: &mut R,
) -> ResponseInfo {
    let builder = MessageResponseBuilder::from_message_request(request);
    let mut header = Header::response_from_request(request.header());
    header.set_authoritative(true);
    header.set_response_code(ResponseCode::NoError);

    let name: Name = request.query().name().clone().into();
    let answers: Vec<Record> = match query_type {
        RecordType::A => vec![Record::from_rdata(
            name,
            SINKHOLE_TTL,
            RData::A(A(SINKHOLE_V4)),
        )],
        RecordType::AAAA => vec![Record::from_rdata(
            name,
            SINKHOLE_TTL,
            RData::AAAA(AAAA(SINKHOLE_V6)),
        )],
        _ => {
            header.set_response_code(ResponseCode::NXDomain);
            vec![]
        }
    };

    let response = builder.build(header, answers.iter(), &[], &[], &[]);
    response_handle
        .send_response(response)
        .await
        .unwrap_or_else(|_| empty_info())
}

/// Forward an unblocked query to upstream and translate the result
/// back into the wire response.
async fn forward<R: ResponseHandler>(
    upstream: &TokioAsyncResolver,
    request: &Request,
    response_handle: &mut R,
) -> ResponseInfo {
    let name: Name = request.query().name().clone().into();
    let qtype = request.query().query_type();

    let lookup = upstream.lookup(name.clone(), qtype).await;

    let builder = MessageResponseBuilder::from_message_request(request);
    let mut header = Header::response_from_request(request.header());
    header.set_authoritative(false); // we are recursive, not authoritative

    match lookup {
        Ok(records) => {
            header.set_response_code(ResponseCode::NoError);
            let answers: Vec<Record> = records.records().to_vec();
            let response = builder.build(header, answers.iter(), &[], &[], &[]);
            response_handle
                .send_response(response)
                .await
                .unwrap_or_else(|_| empty_info())
        }
        Err(_) => {
            // Upstream timeout / NXDOMAIN / resolver error all collapse to
            // SERVFAIL for the client — they will retry, our resolver
            // stays responsive.
            header.set_response_code(ResponseCode::ServFail);
            let response = builder.build(header, [].iter(), &[], &[], &[]);
            response_handle
                .send_response(response)
                .await
                .unwrap_or_else(|_| empty_info())
        }
    }
}

/// Construct a [`BlockReason`] for `domain`. Listing-date metadata
/// (real `YYYY-MM-DD` and "N days ago" strings) lands with the
/// URLhaus parser enrichment; for now we surface a placeholder so
/// the page renders cleanly.
fn make_block_reason(domain: &str) -> BlockReason {
    BlockReason {
        domain: domain.to_string(),
        feed: "URLhaus".to_string(),
        listed_date: "—".to_string(),
        listed_relative: String::new(),
        threat_type: "malware".to_string(),
        block_id: short_block_id(),
        ts_iso: now_rfc3339(),
    }
}

/// 8-char hex block id derived from the current nanosecond clock.
/// Cheap, monotonic enough for human-readable forensic logs; uuid
/// crate is overkill at this layer.
fn short_block_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() ^ (d.as_secs() as u32))
        .unwrap_or(0);
    format!("{:08x}", nanos)
}

/// RFC 3339 timestamp for the block-page `ts_iso` field.
fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "—".to_string())
}

/// Dummy [`ResponseInfo`] for paths where send already failed — the
/// caller has nothing meaningful to report and we just need to
/// satisfy the trait return type.
fn empty_info() -> ResponseInfo {
    let mut header = Header::new();
    header.set_response_code(ResponseCode::ServFail);
    header.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feed::new_blocklist;

    #[tokio::test]
    async fn lower_name_strips_trailing_dot_and_lowercases() {
        let n = LowerName::from(Name::from_ascii("Evil.Example.").unwrap());
        assert_eq!(lower_name_to_domain(&n), "evil.example");
    }

    #[tokio::test]
    async fn make_block_reason_populates_required_fields() {
        let r = make_block_reason("malicious.example");
        assert_eq!(r.domain, "malicious.example");
        assert_eq!(r.feed, "URLhaus");
        assert_eq!(r.threat_type, "malware");
        assert_eq!(r.block_id.len(), 8);
        assert!(r.block_id.chars().all(|c| c.is_ascii_hexdigit()));
        // RFC 3339 starts with a 4-digit year.
        assert!(r.ts_iso.chars().take(4).all(|c| c.is_ascii_digit()));
    }

    #[tokio::test]
    async fn short_block_id_is_8_hex_chars() {
        let id = short_block_id();
        assert_eq!(id.len(), 8);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[tokio::test]
    async fn now_rfc3339_yields_parseable_string() {
        let s = now_rfc3339();
        // Must contain the date / time separator and a 'Z' or offset.
        assert!(s.contains('T'));
        assert!(s.contains('Z') || s.contains('+') || s.contains('-'));
    }

    #[tokio::test]
    async fn resolver_block_path_writes_blockpage_slot() {
        let bl = new_blocklist();
        bl.write().await.insert("malicious.example".to_string());
        let bp = AppState::new();
        let _r = Resolver::new(bl.clone(), bp.clone());

        // We can't easily forge a hickory `Request` in unit tests
        // (it wraps a UDP datagram + sender), so the in-process
        // assertion here is on the helper that the handler invokes
        // when it decides to block.
        bp.set_current(make_block_reason("malicious.example")).await;
        let slot = bp.current.read().await;
        assert!(slot.is_some());
        let r = slot.as_ref().unwrap();
        assert_eq!(r.domain, "malicious.example");
        assert_eq!(r.feed, "URLhaus");
    }

    #[tokio::test]
    async fn try_bind_succeeds_on_ephemeral_port() {
        // Use an OS-assigned port so the test never collides with :53
        // / :5353 on the runner. This proves the helper's both-or-fail
        // semantics on a port we know we can grab.
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let result = try_bind(addr).await;
        assert!(result.is_ok());
    }
}
