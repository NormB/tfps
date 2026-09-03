//! HEP v3 forwarding: a copy of every SIP message this sensor sees, for a second opinion.
//!
//! TFPS condemns a source and the source vanishes. An operator who wants to check that
//! verdict -- or an analyzer that wants to learn from it -- needs the packets that led to
//! it, and this project deliberately keeps no packet store, no database of messages and
//! no UI. So it forwards instead: every SIP datagram observed on the watched ports is
//! encapsulated as HEP v3 (Homer Encapsulation Protocol, the EEP/HEP3 capture protocol)
//! and sent to whichever UDP collector `--hep-send` names. What the collector does with
//! the copy is its business.
//!
//! **Off unless asked for.** With the flag absent nothing in this module is constructed:
//! no socket, no thread, no work on the packet path.
//!
//! On the packet path the cost is one encode and one `try_send` into a bounded queue --
//! `SPEC.md` §10, the hot path never waits on I/O. A separate thread does the `send(2)`.
//! When the queue is full the copy is **dropped and counted**; a collector that cannot
//! keep up costs copies, never capture.
//!
//! The layout follows the HEP3 specification (sipcapture/HEP, rev. 37): a six-octet header
//! -- the ASCII `HEP3` identifier and a big-endian total length that includes itself --
//! then chunks, each `vendor(2) type(2) length(2) value`, the length covering all six
//! header octets. Only generic chunks (vendor `0x0000`) are sent. The specification's own
//! worked example is the golden vector in the tests below.

#![deny(missing_docs)]

use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::Arc;

/// The four-octet protocol identifier every HEP3 packet starts with.
pub const MAGIC: [u8; 4] = *b"HEP3";
/// Chunk vendor ID for the generic chunk types defined by the specification itself.
pub const VENDOR_GENERIC: u16 = 0x0000;
/// `uint8`: IP protocol family.
pub const CHUNK_IP_FAMILY: u16 = 0x0001;
/// `uint8`: IP protocol ID.
pub const CHUNK_IP_PROTO: u16 = 0x0002;
/// `inet4-addr`: IPv4 source address.
pub const CHUNK_SRC_IPV4: u16 = 0x0003;
/// `inet4-addr`: IPv4 destination address.
pub const CHUNK_DST_IPV4: u16 = 0x0004;
/// `uint16`: protocol source port.
pub const CHUNK_SRC_PORT: u16 = 0x0007;
/// `uint16`: protocol destination port.
pub const CHUNK_DST_PORT: u16 = 0x0008;
/// `uint32`: timestamp, seconds since the epoch.
pub const CHUNK_TS_SECS: u16 = 0x0009;
/// `uint32`: microseconds added to the timestamp.
pub const CHUNK_TS_USECS: u16 = 0x000a;
/// `uint8`: protocol type of the captured payload.
pub const CHUNK_PROTO_TYPE: u16 = 0x000b;
/// `uint32`: capture agent ID.
pub const CHUNK_AGENT_ID: u16 = 0x000c;
/// `octet-string`: the authenticate key -- a shared secret verbatim, or a signed token.
pub const CHUNK_AUTH_KEY: u16 = 0x000e;
/// `octet-string`: the captured packet payload.
pub const CHUNK_PAYLOAD: u16 = 0x000f;
/// IP protocol family value for IPv4.
pub const AF_INET: u8 = 2;
/// IP protocol ID for UDP.
pub const IPPROTO_UDP: u8 = 17;
/// Capture protocol type for SIP.
pub const PROTO_SIP: u8 = 0x01;
/// The capture agent ID sent unless `--hep-agent-id` chooses one. The specification's own
/// example list of IDs is "202, 1201, 2033..."; this is the last of them.
pub const DEFAULT_AGENT_ID: u32 = 2033;
/// How many encoded copies may wait for the sending thread. Beyond this they are dropped:
/// the bound is what keeps a slow collector from ever backing up into capture.
pub const QUEUE: usize = 1024;
/// Header, the ten fixed chunks, and the payload chunk's own six-octet header.
const OVERHEAD: usize = 6 + 7 + 7 + 10 + 10 + 8 + 8 + 10 + 10 + 7 + 10 + 6;
/// The largest payload the sixteen-bit total length can describe, with no auth chunk.
pub const MAX_PAYLOAD: usize = u16::MAX as usize - OVERHEAD;
/// The token version the receiver accepts: the one whose MAC covers the whole datagram.
/// Version 1 signed only the payload and left the addressing chunks forgeable; sipnab
/// refuses it outright, so there is nothing to be compatible with.
pub const HMAC_TOKEN_VERSION: u8 = 2;
/// version(1) + timestamp(8) + nonce(16) + HMAC-SHA256(32).
pub const HMAC_TOKEN_LEN: usize = 1 + 8 + 16 + 32;
/// Where the MAC sits inside the token: the only bytes of the datagram it does not cover.
const HMAC_MAC_OFFSET: usize = 1 + 8 + 16;

/// How the shared secret is presented in the authenticate chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    /// The secret itself, verbatim. What a stock Homer expects; replayable by
    /// anyone on the path.
    Plain,
    /// A per-message token: timestamp, nonce, and an HMAC-SHA256 over the whole
    /// datagram. Resists replay and forgery of the addressing chunks; sipnab to
    /// sipnab. **The default**, because the plain key is the weaker of the two
    /// and an operator who wants it can say so.
    Hmac,
}

impl std::str::FromStr for AuthMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "plain" => Ok(AuthMode::Plain),
            "hmac" => Ok(AuthMode::Hmac),
            other => Err(format!("expected plain or hmac, got \"{other}\"")),
        }
    }
}

/// The shared secret and how to present it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Auth {
    /// The secret, exactly as the receiver has it.
    pub key: Vec<u8>,
    /// Verbatim or signed.
    pub mode: AuthMode,
}

/// Reads the shared secret from a file, refusing one the world can read.
///
/// A secret in a world-readable file is not a secret, and a tool that reads it
/// anyway lets the operator believe the stream is authenticated when any local
/// user can sign into it. The contents are trimmed, as the receiver trims its
/// own copy, so a trailing newline from an editor is not part of the key.
pub fn read_secret(path: &Path) -> Result<Vec<u8>, String> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if meta.permissions().mode() & 0o004 != 0 {
        return Err(format!(
            "{}: the secret is world-readable (mode {:04o}); chmod 600 it",
            path.display(),
            meta.permissions().mode() & 0o7777
        ));
    }
    let raw = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let key = String::from_utf8_lossy(&raw).trim().as_bytes().to_vec();
    if key.is_empty() {
        return Err(format!("{}: the secret file is empty", path.display()));
    }
    Ok(key)
}

/// One SIP datagram as the sensor saw it, with the clock reading at that moment.
#[derive(Debug, Clone, Copy)]
pub struct Observed<'a> {
    /// IPv4 source of the datagram.
    pub src: Ipv4Addr,
    /// IPv4 destination of the datagram.
    pub dst: Ipv4Addr,
    /// UDP source port.
    pub src_port: u16,
    /// UDP destination port.
    pub dst_port: u16,
    /// Seconds since the epoch when it was observed.
    pub secs: u32,
    /// Microseconds within that second.
    pub usecs: u32,
    /// The UDP payload: the SIP message itself.
    pub payload: &'a [u8],
}

/// Encapsulates one observed datagram as a HEP3 packet.
///
/// `None` when the payload is too large for the sixteen-bit total length: refusing is the
/// only honest answer, because a wrapped length would produce a packet a collector reads as
/// a different, shorter message rather than as an error.
pub fn encode(o: &Observed<'_>, agent_id: u32) -> Option<Vec<u8>> {
    encode_with(o, agent_id, None)
}

/// Encapsulates one observed datagram with an authenticate chunk.
///
/// `Plain` carries the key verbatim. `Hmac` carries a token signed over the
/// finished datagram, in two passes: the packet is assembled with a token of
/// the final length whose MAC field is zero, the MAC is taken over every byte
/// of it, and the tag is written into that field. The length never changes
/// between the passes, so no length field is disturbed. `token_ts` and `nonce`
/// are arguments so the bytes can be pinned by a test; the forwarder supplies
/// the clock and a nonce that never repeats.
pub fn encode_with_auth(
    o: &Observed<'_>,
    agent_id: u32,
    auth: &Auth,
    token_ts: u64,
    nonce: &[u8; 16],
) -> Option<Vec<u8>> {
    match auth.mode {
        AuthMode::Plain => encode_with(o, agent_id, Some(&auth.key)),
        AuthMode::Hmac => {
            let mut token = [0u8; HMAC_TOKEN_LEN];
            token[0] = HMAC_TOKEN_VERSION;
            token[1..9].copy_from_slice(&token_ts.to_be_bytes());
            token[9..HMAC_MAC_OFFSET].copy_from_slice(nonce);
            let mut pkt = encode_with(o, agent_id, Some(&token))?;
            // The token is found by reading the packet back rather than by
            // arithmetic over the chunk order, so a chunk added later cannot
            // move the signature onto the wrong bytes.
            let start = auth_chunk_start(&pkt)?;
            let mac_start = start + HMAC_MAC_OFFSET;
            let mac = hmac_sha256(&auth.key, &pkt);
            pkt[mac_start..mac_start + 32].copy_from_slice(&mac);
            Some(pkt)
        }
    }
}

/// Offset of the authenticate chunk's data, by walking the chunks.
fn auth_chunk_start(pkt: &[u8]) -> Option<usize> {
    let mut off = 6;
    while off + 6 <= pkt.len() {
        let ty = u16::from_be_bytes([pkt[off + 2], pkt[off + 3]]);
        let len = usize::from(u16::from_be_bytes([pkt[off + 4], pkt[off + 5]]));
        if len < 6 || off + len > pkt.len() {
            return None;
        }
        if ty == CHUNK_AUTH_KEY {
            return Some(off + 6);
        }
        off += len;
    }
    None
}

/// HMAC-SHA256 over `data` under `key`. The MAC field inside `data` is zero
/// when this is called, which is how the verifier reads it back.
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, KeyInit, Mac};
    // HMAC takes a key of any length; the constructor cannot fail. The
    // impossible branch yields a zero tag, which no receiver will ever accept,
    // so a failure here fails closed rather than silently unsigned.
    match Hmac::<sha2::Sha256>::new_from_slice(key) {
        Ok(mut m) => {
            m.update(data);
            m.finalize().into_bytes().into()
        }
        Err(_) => [0u8; 32],
    }
}

/// The one layout, with or without an authenticate chunk before the payload.
fn encode_with(o: &Observed<'_>, agent_id: u32, auth_chunk: Option<&[u8]>) -> Option<Vec<u8>> {
    let auth_len = auth_chunk.map_or(0, |a| 6 + a.len());
    let total = OVERHEAD + auth_len + o.payload.len();
    if total > u16::MAX as usize {
        return None;
    }
    let mut p = Vec::with_capacity(total);
    p.extend_from_slice(&MAGIC);
    p.extend_from_slice(&(total as u16).to_be_bytes());
    chunk(&mut p, CHUNK_IP_FAMILY, &[AF_INET]);
    chunk(&mut p, CHUNK_IP_PROTO, &[IPPROTO_UDP]);
    chunk(&mut p, CHUNK_SRC_IPV4, &o.src.octets());
    chunk(&mut p, CHUNK_DST_IPV4, &o.dst.octets());
    chunk(&mut p, CHUNK_SRC_PORT, &o.src_port.to_be_bytes());
    chunk(&mut p, CHUNK_DST_PORT, &o.dst_port.to_be_bytes());
    chunk(&mut p, CHUNK_TS_SECS, &o.secs.to_be_bytes());
    chunk(&mut p, CHUNK_TS_USECS, &o.usecs.to_be_bytes());
    chunk(&mut p, CHUNK_PROTO_TYPE, &[PROTO_SIP]);
    chunk(&mut p, CHUNK_AGENT_ID, &agent_id.to_be_bytes());
    if let Some(a) = auth_chunk {
        chunk(&mut p, CHUNK_AUTH_KEY, a);
    }
    chunk(&mut p, CHUNK_PAYLOAD, o.payload);
    debug_assert_eq!(p.len(), total, "OVERHEAD must describe what is emitted");
    Some(p)
}

/// One generic chunk: vendor, type, a length that covers this six-octet header too, value.
fn chunk(p: &mut Vec<u8>, ty: u16, value: &[u8]) {
    p.extend_from_slice(&VENDOR_GENERIC.to_be_bytes());
    p.extend_from_slice(&ty.to_be_bytes());
    p.extend_from_slice(&((6 + value.len()) as u16).to_be_bytes());
    p.extend_from_slice(value);
}

/// What the forwarder has done so far, as plain numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Counters {
    /// Copies the sending thread handed to the socket without error.
    pub sent: u64,
    /// Copies never queued: the queue was full, or the payload could not be encoded.
    pub dropped: u64,
    /// Copies the socket refused, e.g. the collector's host answered unreachable.
    pub failed: u64,
}

impl Counters {
    /// The counters as `key=value` pairs, in the shape the checkpoint line and
    /// `tfps_ctl stats` already read. One format, produced in one place.
    pub fn line(&self) -> String {
        format!(
            "hep_sent={} hep_dropped={} hep_failed={}",
            self.sent, self.dropped, self.failed
        )
    }
}

#[derive(Default)]
struct Shared {
    sent: AtomicU64,
    dropped: AtomicU64,
    failed: AtomicU64,
}

/// Where the sending thread puts each packet. A boxed closure rather than the socket
/// itself so a test can drive the thread with a sink that refuses.
type Sink = Box<dyn FnMut(&[u8]) -> std::io::Result<()> + Send>;

/// The queue in front of the sending thread. Owned by the capture loop; the packet path
/// only ever calls [`Forwarder::forward`].
pub struct Forwarder {
    tx: SyncSender<Vec<u8>>,
    agent_id: u32,
    auth: Option<Auth>,
    /// Per-process half of every nonce: the clock and the pid at start, so two
    /// sensors sharing a key do not share a nonce. Uniqueness is the property
    /// the receiver's replay cache needs; unpredictability is not, the MAC
    /// carries that.
    nonce_salt: u64,
    nonce_counter: AtomicU64,
    shared: Arc<Shared>,
}

impl Forwarder {
    /// Opens a UDP socket towards `collector` (`host:port`) and starts the sending thread.
    /// Returns the address the collector resolved to, for the startup report.
    pub fn start(
        collector: &str,
        agent_id: u32,
        auth: Option<Auth>,
    ) -> std::io::Result<(Self, SocketAddr)> {
        use std::net::{Ipv6Addr, ToSocketAddrs, UdpSocket};
        let addr = collector.to_socket_addrs()?.next().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "resolved to no address")
        })?;
        let bind = if addr.is_ipv4() {
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
        } else {
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
        };
        let sock = UdpSocket::bind(bind)?;
        // Connected, so an ICMP unreachable comes back as an error on a later send and is
        // counted, instead of every copy vanishing into a route to nowhere.
        sock.connect(addr)?;
        let sink: Sink = Box::new(move |pkt| sock.send(pkt).map(|_| ()));
        Ok((Self::spawn(sink, QUEUE, agent_id, auth)?, addr))
    }

    /// Starts the sending thread over an arbitrary sink with a queue of `capacity`.
    fn spawn(
        mut sink: Sink,
        capacity: usize,
        agent_id: u32,
        auth: Option<Auth>,
    ) -> std::io::Result<Self> {
        let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(capacity);
        let shared = Arc::new(Shared::default());
        let s = Arc::clone(&shared);
        std::thread::Builder::new()
            .name("hep-forward".into())
            .spawn(move || {
                let mut warned = false;
                for pkt in rx {
                    match sink(&pkt) {
                        Ok(()) => s.sent.fetch_add(1, Ordering::Relaxed),
                        Err(e) => {
                            // Once, loudly; the counter carries the rest. Printing every
                            // failure would flood the log at exactly the wrong moment.
                            if !warned {
                                eprintln!(
                                    "WARNING: HEP forwarding failed: {e} (counted from here on)"
                                );
                                warned = true;
                            }
                            s.failed.fetch_add(1, Ordering::Relaxed)
                        }
                    };
                }
            })?;
        let started = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        Ok(Self {
            tx,
            agent_id,
            auth,
            nonce_salt: started ^ (u64::from(std::process::id()) << 32),
            nonce_counter: AtomicU64::new(0),
            shared,
        })
    }

    /// The next nonce: the salt, then a counter. Never the same twice in one process.
    fn next_nonce(&self) -> [u8; 16] {
        let n = self.nonce_counter.fetch_add(1, Ordering::Relaxed);
        let mut nonce = [0u8; 16];
        nonce[..8].copy_from_slice(&self.nonce_salt.to_be_bytes());
        nonce[8..].copy_from_slice(&n.to_be_bytes());
        nonce
    }

    /// Whether the copies are authenticated, and how, for the startup report.
    pub fn auth_mode(&self) -> Option<AuthMode> {
        self.auth.as_ref().map(|a| a.mode)
    }

    /// Queues a copy of one datagram. Never blocks: a full queue drops the copy and counts
    /// the drop, because capture must not wait on a collector.
    pub fn forward(&self, o: &Observed<'_>) {
        let pkt = match &self.auth {
            None => encode(o, self.agent_id),
            Some(auth) => {
                let ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                encode_with_auth(o, self.agent_id, auth, ts, &self.next_nonce())
            }
        };
        let queued = pkt.is_some_and(|pkt| self.tx.try_send(pkt).is_ok());
        if !queued {
            self.shared.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// A snapshot of the counters.
    pub fn counters(&self) -> Counters {
        Counters {
            sent: self.shared.sent.load(Ordering::Relaxed),
            dropped: self.shared.dropped.load(Ordering::Relaxed),
            failed: self.shared.failed.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    // The capture side of this feature cannot be driven from a test: the sensor reads
    // AF_PACKET, which needs CAP_NET_RAW, and a test suite must not. So the wire is
    // covered from the other end. The ENCODING is held to the specification's own worked
    // example, byte for byte, and the queue, the thread and a real UDP socket are proven
    // on loopback, which needs no privilege. What remains unproven here is only that
    // `main` hands every on-port datagram to `forward`, and that is a single call under
    // the same `Option` that decides whether a forwarder exists at all.

    /// The example packet from the HEP3 specification (rev. 37), hexadecimal octets
    /// transcribed from the document. 113 octets; the SIP payload is shortened there too.
    const SPEC_EXAMPLE: [u8; 113] = [
        0x48, 0x45, 0x50, 0x33, // HEP3
        0x00, 0x71, // total length = 113
        0x00, 0x00, 0x00, 0x01, 0x00, 0x07, 0x02, // protocol family = 2 (IPv4)
        0x00, 0x00, 0x00, 0x02, 0x00, 0x07, 0x11, // protocol ID = 17 (UDP)
        0x00, 0x00, 0x00, 0x03, 0x00, 0x0a, 0xd4, 0xca, 0x00, 0x01, // src 212.202.0.1
        0x00, 0x00, 0x00, 0x04, 0x00, 0x0a, 0x52, 0x74, 0x00, 0xd3, // dst 82.116.0.211
        0x00, 0x00, 0x00, 0x07, 0x00, 0x08, 0x2e, 0xea, // source port = 12010
        0x00, 0x00, 0x00, 0x08, 0x00, 0x08, 0x13, 0xc4, // destination port = 5060
        0x00, 0x00, 0x00, 0x09, 0x00, 0x0a, 0x4e, 0x49, 0x82, 0xcb, // 1313440459 s
        0x00, 0x00, 0x00, 0x0a, 0x00, 0x0a, 0x00, 0x01, 0xd4, 0xc0, // 120000 us
        0x00, 0x00, 0x00, 0x0b, 0x00, 0x07, 0x01, // protocol type SIP
        0x00, 0x00, 0x00, 0x0c, 0x00, 0x0a, 0x00, 0x00, 0x00, 0xe4, // capture ID 228
        0x00, 0x00, 0x00, 0x0f, 0x00, 0x14, // payload chunk, 20 octets
        0x49, 0x4e, 0x56, 0x49, 0x54, 0x45, 0x20, 0x73, 0x69, 0x70, 0x3a, 0x62, 0x6f,
        0x62, // "INVITE sip:bob"
    ];
    const SPEC_AGENT_ID: u32 = 228;

    fn spec_observed(payload: &[u8]) -> Observed<'_> {
        Observed {
            src: Ipv4Addr::new(212, 202, 0, 1),
            dst: Ipv4Addr::new(82, 116, 0, 211),
            src_port: 12010,
            dst_port: 5060,
            secs: 1_313_440_459,
            usecs: 120_000,
            payload,
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    enum Reject {
        Magic,
        Length,
        Chunk,
    }

    fn be16(b: &[u8]) -> u16 {
        u16::from_be_bytes([b[0], b[1]])
    }

    /// An independent reader of the format: every chunk as (vendor, type, value). Strict
    /// on purpose -- the total length must equal the buffer, every chunk must fit and
    /// carry at least its own header, and nothing may trail.
    fn decode(pkt: &[u8]) -> Result<Vec<(u16, u16, Vec<u8>)>, Reject> {
        if pkt.len() < 6 || pkt[..4] != MAGIC {
            return Err(Reject::Magic);
        }
        if be16(&pkt[4..]) as usize != pkt.len() {
            return Err(Reject::Length);
        }
        let mut chunks = Vec::new();
        let mut off = 6;
        while off < pkt.len() {
            if off + 6 > pkt.len() {
                return Err(Reject::Chunk);
            }
            let len = be16(&pkt[off + 4..]) as usize;
            if len < 6 || off + len > pkt.len() {
                return Err(Reject::Chunk);
            }
            chunks.push((
                be16(&pkt[off..]),
                be16(&pkt[off + 2..]),
                pkt[off + 6..off + len].to_vec(),
            ));
            off += len;
        }
        Ok(chunks)
    }

    // THE RULE: the bytes are the specification's, not ours. A vector produced by the
    // encoder under test would be self-consistent and worth nothing.
    #[test]
    fn the_spec_example_packet_is_reproduced_byte_for_byte() {
        let pkt = encode(&spec_observed(b"INVITE sip:bob"), SPEC_AGENT_ID)
            .expect("a fourteen-byte payload must encode");
        assert_eq!(pkt.as_slice(), &SPEC_EXAMPLE[..]);
    }

    #[test]
    fn every_chunk_decodes_back_in_order_with_the_payload_last() {
        let pkt = encode(&spec_observed(b"OPTIONS sip:x"), 7).unwrap();
        let chunks = decode(&pkt).expect("our own output must decode");
        // Literal ids from the specification's table, not the module's constants: a list
        // written in terms of the constants would move with a wrong one and prove nothing.
        let want: Vec<(u16, u16, Vec<u8>)> = vec![
            (0x0000, 0x0001, vec![2]),
            (0x0000, 0x0002, vec![17]),
            (0x0000, 0x0003, vec![212, 202, 0, 1]),
            (0x0000, 0x0004, vec![82, 116, 0, 211]),
            (0x0000, 0x0007, vec![0x2e, 0xea]),
            (0x0000, 0x0008, vec![0x13, 0xc4]),
            (0x0000, 0x0009, vec![0x4e, 0x49, 0x82, 0xcb]),
            (0x0000, 0x000a, vec![0x00, 0x01, 0xd4, 0xc0]),
            (0x0000, 0x000b, vec![0x01]),
            (0x0000, 0x000c, vec![0, 0, 0, 7]),
            (0x0000, 0x000f, b"OPTIONS sip:x".to_vec()),
        ];
        assert_eq!(chunks, want);
        assert_eq!(chunks.last().unwrap().1, 0x000f, "the payload comes last");
    }

    #[test]
    fn the_total_length_counts_the_header_and_every_chunk() {
        let payload = vec![b'x'; 1000];
        let pkt = encode(&spec_observed(&payload), 1).unwrap();
        assert_eq!(pkt.len(), OVERHEAD + 1000);
        assert_eq!(be16(&pkt[4..]) as usize, pkt.len());
    }

    // NEGATIVE CONTROL on the reader the tests above rely on. A decoder that accepted
    // anything would make "our own output decodes" vacuous.
    #[test]
    fn a_packet_with_the_wrong_magic_is_rejected() {
        assert_eq!(decode(&SPEC_EXAMPLE), Ok(decode(&SPEC_EXAMPLE).unwrap()));
        let mut wrong = SPEC_EXAMPLE;
        wrong[..4].copy_from_slice(b"HEP2");
        assert_eq!(decode(&wrong), Err(Reject::Magic));
        let mut short = SPEC_EXAMPLE.to_vec();
        short.pop();
        assert_eq!(
            decode(&short),
            Err(Reject::Length),
            "a length that overruns the buffer"
        );
        let mut overrun = SPEC_EXAMPLE;
        overrun[11] = 0x08; // the first chunk claims one octet more than it has
        assert_eq!(decode(&overrun), Err(Reject::Chunk));
    }

    // The Go reference casts the total to sixteen bits unchecked. A payload one octet
    // over the limit would wrap to a tiny length and be read as a different packet.
    #[test]
    fn a_payload_that_cannot_fit_the_length_field_is_refused_not_truncated() {
        let fits = vec![b'a'; MAX_PAYLOAD];
        let pkt = encode(&spec_observed(&fits), 1).expect("the largest payload encodes");
        assert_eq!(pkt.len(), u16::MAX as usize);
        assert!(decode(&pkt).is_ok());
        let over = vec![b'a'; MAX_PAYLOAD + 1];
        assert_eq!(encode(&spec_observed(&over), 1), None);
    }

    #[test]
    fn counters_read_as_key_value_pairs() {
        let c = Counters {
            sent: 1,
            dropped: 2,
            failed: 3,
        };
        assert_eq!(c.line(), "hep_sent=1 hep_dropped=2 hep_failed=3");
    }

    fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !done() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    // THE PROPERTY that keeps this off the hot path. The sink holds the thread inside the
    // first send, the second copy fills a queue of one, and the third must come back at
    // once as a counted drop -- this test returning is the proof it did not block.
    #[test]
    fn a_full_queue_drops_the_copy_and_counts_it_without_blocking_capture() {
        let (entered_tx, entered_rx) = mpsc::channel::<()>();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let sink: Sink = Box::new(move |_| {
            entered_tx.send(()).unwrap();
            let _ = release_rx.recv();
            Ok(())
        });
        let f = Forwarder::spawn(sink, 1, 1, None).unwrap();
        let o = spec_observed(b"REGISTER sip:y");
        f.forward(&o);
        entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the thread took the first copy");
        f.forward(&o); // sits in the queue of one
        f.forward(&o); // nowhere to go
        assert_eq!(
            f.counters().dropped,
            1,
            "exactly the third copy was dropped"
        );
        release_tx.send(()).unwrap();
        wait_until("the first copy to be sent", || f.counters().sent >= 1);
    }

    #[test]
    fn a_send_that_fails_is_counted_as_failed_not_sent() {
        let sink: Sink = Box::new(|_| {
            Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "no collector",
            ))
        });
        let f = Forwarder::spawn(sink, 8, 1, None).unwrap();
        f.forward(&spec_observed(b"INVITE sip:z"));
        wait_until("the failure to be counted", || f.counters().failed == 1);
        assert_eq!(f.counters().sent, 0);
        assert_eq!(f.counters().dropped, 0);
    }

    // The real socket, on loopback: what a collector receives is the specification's
    // packet, unchanged by the queue or the thread.
    #[test]
    fn the_spec_example_arrives_on_a_loopback_collector() {
        let collector = UdpSocket::bind("127.0.0.1:0").unwrap();
        collector
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let target = collector.local_addr().unwrap();
        let (f, resolved) = Forwarder::start(&target.to_string(), SPEC_AGENT_ID, None).unwrap();
        assert_eq!(resolved, target);
        f.forward(&spec_observed(b"INVITE sip:bob"));
        let mut buf = [0u8; 2048];
        let n = collector
            .recv(&mut buf)
            .expect("the collector received nothing in 5s");
        assert_eq!(&buf[..n], &SPEC_EXAMPLE[..]);
        wait_until("the copy to be counted as sent", || f.counters().sent == 1);
        assert_eq!(
            f.counters(),
            Counters {
                sent: 1,
                dropped: 0,
                failed: 0
            }
        );
    }

    // ---- R2(b), authenticated: the receiver must be able to tell this sensor from anyone ----
    //
    // The collector is sipnab. Its verifier (`src/capture/hep.rs`, `verify_hmac_datagram`)
    // is the specification: the 0x000e chunk carries version 2, a big-endian u64
    // timestamp, a 16-octet nonce and an HMAC-SHA256 over EVERY byte of the datagram with
    // the 32 MAC octets read as zeros. The vectors below were computed from that reading
    // with Python's `hmac`, not with this module, so they are worth something.
    //
    // The wire itself cannot be driven from `cargo test`: the capture side needs
    // CAP_NET_RAW, and the verifier is a separate program. It was driven by hand against
    // sipnab 0.5.146 on 2026-09-03 -- one OPTIONS on loopback through `tfps --no-enforce
    // --hep-send --hep-auth-file --hep-auth-mode hmac` came out of `sipnab --hep-parse
    // --hep-auth-mode hmac --json` as a parsed message, and the same packet under a
    // different secret was logged as `BadMac` and not printed. See the commit.

    const KEY: &[u8] = b"correct horse battery staple";
    const TOKEN_TS: u64 = 1_788_453_610;
    const NONCE: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// The spec example, plus the signed token, as the Python derivation produced it.
    fn hmac_vector() -> Vec<u8> {
        unhex(concat!(
            "4845503300b0",
            "000000010007020000000200071100000003000ad4ca000100000004000a527400d3",
            "0000000700082eea00000008000813c400000009000a4e4982cb0000000a000a0001d4c0",
            "0000000b0007010000000c000a000000e4",
            "0000000e003f02000000006a99a2ea000102030405060708090a0b0c0d0e0f",
            "dc31efb4005fd6cfb9d1b0e31e9a09a080047b5e6c67830e98ca6b2be454d350",
            "0000000f0014494e56495445207369703a626f62"
        ))
    }

    fn hmac_auth() -> Auth {
        Auth {
            key: KEY.to_vec(),
            mode: AuthMode::Hmac,
        }
    }

    /// An independent reading of the verifier, for the properties the vector alone cannot
    /// show: which bytes the MAC covers.
    fn verifies(pkt: &[u8], key: &[u8]) -> bool {
        use hmac::{Hmac, KeyInit, Mac};
        let Some((_, ty, token)) = decode(pkt)
            .ok()
            .and_then(|c| c.into_iter().find(|(_, t, _)| *t == 0x000e))
        else {
            return false;
        };
        assert_eq!(ty, 0x000e);
        if token.len() != 57 || token[0] != 2 {
            return false;
        }
        let start = pkt.windows(57).position(|w| w == token.as_slice()).unwrap();
        let mac_start = start + 25;
        let mut zeroed = pkt.to_vec();
        zeroed[mac_start..mac_start + 32].fill(0);
        let mut m = Hmac::<sha2::Sha256>::new_from_slice(key).unwrap();
        m.update(&zeroed);
        m.finalize().into_bytes().as_slice() == &pkt[mac_start..mac_start + 32]
    }

    // THE RULE: the bytes are the verifier's reading, not this encoder's.
    #[test]
    fn the_hmac_vector_derived_from_the_verifier_is_reproduced_byte_for_byte() {
        let pkt = encode_with_auth(
            &spec_observed(b"INVITE sip:bob"),
            SPEC_AGENT_ID,
            &hmac_auth(),
            TOKEN_TS,
            &NONCE,
        )
        .unwrap();
        assert_eq!(pkt, hmac_vector());
    }

    #[test]
    fn plain_mode_carries_the_key_verbatim_before_the_payload() {
        let auth = Auth {
            key: KEY.to_vec(),
            mode: AuthMode::Plain,
        };
        let pkt = encode_with_auth(
            &spec_observed(b"INVITE sip:bob"),
            SPEC_AGENT_ID,
            &auth,
            0,
            &NONCE,
        )
        .unwrap();
        assert_eq!(
            pkt,
            unhex(concat!(
                "484550330093",
                "000000010007020000000200071100000003000ad4ca000100000004000a527400d3",
                "0000000700082eea00000008000813c400000009000a4e4982cb0000000a000a0001d4c0",
                "0000000b0007010000000c000a000000e4",
                "0000000e0022636f727265637420686f727365206261747465727920737461706c65",
                "0000000f0014494e56495445207369703a626f62"
            ))
        );
        let chunks = decode(&pkt).unwrap();
        assert_eq!(chunks[10], (0x0000, 0x000e, KEY.to_vec()));
        assert_eq!(chunks[11].1, 0x000f, "the payload still comes last");
    }

    // The property version 2 exists for: the addressing is inside the signature. A
    // packet whose destination chunk was rewritten after signing must not verify --
    // that is exactly the forgery that pointed a kill response at a third party.
    #[test]
    fn the_mac_covers_the_addressing_chunks_and_the_payload() {
        let pkt = hmac_vector();
        assert!(
            verifies(&pkt, KEY),
            "the vector must verify under its own key"
        );
        let mut dst_changed = pkt.clone();
        dst_changed[36] ^= 0x01; // one octet of the destination address chunk
        assert!(!verifies(&dst_changed, KEY));
        let mut payload_changed = pkt.clone();
        let n = payload_changed.len();
        payload_changed[n - 1] ^= 0x01;
        assert!(!verifies(&payload_changed, KEY));
        let mut ts_changed = pkt.clone();
        ts_changed[68] ^= 0x01; // the token's own timestamp is covered too
        assert!(!verifies(&ts_changed, KEY));
        assert!(!verifies(&pkt, b"wrong key"));
    }

    #[test]
    fn the_token_has_the_verifiers_layout() {
        let pkt = hmac_vector();
        let chunks = decode(&pkt).unwrap();
        let (_, ty, token) = &chunks[10];
        assert_eq!(*ty, 0x000e, "the auth chunk sits after the agent id");
        assert_eq!(token.len(), 57);
        assert_eq!(token[0], 2, "version 2: the MAC covers the datagram");
        assert_eq!(
            u64::from_be_bytes(token[1..9].try_into().unwrap()),
            TOKEN_TS
        );
        assert_eq!(&token[9..25], &NONCE);
        assert_eq!(chunks.last().unwrap().1, 0x000f);
    }

    // The receiver's replay cache rejects a nonce it has seen; a forwarder that repeated
    // one would have its own copies refused as replays.
    #[test]
    fn a_forwarder_never_reuses_a_nonce_and_stamps_the_clock() {
        let (tx, rx) = mpsc::channel::<Vec<u8>>();
        let sink: Sink = Box::new(move |pkt| {
            tx.send(pkt.to_vec()).unwrap();
            Ok(())
        });
        let f = Forwarder::spawn(sink, 8, 1, Some(hmac_auth())).unwrap();
        assert_eq!(f.auth_mode(), Some(AuthMode::Hmac));
        let o = spec_observed(b"OPTIONS sip:x");
        for _ in 0..3 {
            f.forward(&o);
        }
        let before = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut nonces = std::collections::HashSet::new();
        for _ in 0..3 {
            let pkt = rx.recv_timeout(Duration::from_secs(5)).unwrap();
            assert!(verifies(&pkt, KEY));
            let token = decode(&pkt).unwrap()[10].2.clone();
            let ts = u64::from_be_bytes(token[1..9].try_into().unwrap());
            assert!(ts.abs_diff(before) <= 5, "the token carries the wall clock");
            nonces.insert(token[9..25].to_vec());
        }
        assert_eq!(nonces.len(), 3, "three copies, three nonces");
    }

    #[test]
    fn a_secret_file_the_world_can_read_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("tfps-hep-secret-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let open = dir.join("open.key");
        std::fs::write(&open, "s3cr3t\n").unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o644)).unwrap();
        let e = read_secret(&open).unwrap_err();
        assert!(e.contains("world"), "the refusal must say why: {e}");

        let closed = dir.join("closed.key");
        std::fs::write(&closed, "  s3cr3t\n").unwrap();
        std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            read_secret(&closed).unwrap(),
            b"s3cr3t",
            "trimmed, as the receiver trims its copy"
        );

        let empty = dir.join("empty.key");
        std::fs::write(&empty, "\n").unwrap();
        std::fs::set_permissions(&empty, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            read_secret(&empty).is_err(),
            "an empty secret authenticates nothing"
        );
        assert!(read_secret(&dir.join("missing.key")).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // The token takes 63 octets of the sixteen-bit total; a payload that fit without
    // one must be refused with one rather than wrapped.
    #[test]
    fn the_payload_ceiling_accounts_for_the_token() {
        let fits = vec![b'a'; MAX_PAYLOAD - 6 - HMAC_TOKEN_LEN];
        let pkt =
            encode_with_auth(&spec_observed(&fits), 1, &hmac_auth(), TOKEN_TS, &NONCE).unwrap();
        assert_eq!(pkt.len(), u16::MAX as usize);
        assert!(verifies(&pkt, KEY));
        let over = vec![b'a'; MAX_PAYLOAD - 6 - HMAC_TOKEN_LEN + 1];
        assert_eq!(
            encode_with_auth(&spec_observed(&over), 1, &hmac_auth(), TOKEN_TS, &NONCE),
            None
        );
    }

    #[test]
    fn the_mode_is_named_plain_or_hmac_and_nothing_else() {
        assert_eq!("plain".parse::<AuthMode>(), Ok(AuthMode::Plain));
        assert_eq!("hmac".parse::<AuthMode>(), Ok(AuthMode::Hmac));
        assert!("HMAC".parse::<AuthMode>().is_err());
        assert!("".parse::<AuthMode>().is_err());
    }
}
