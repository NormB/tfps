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
/// The largest payload the sixteen-bit total length can describe.
pub const MAX_PAYLOAD: usize = u16::MAX as usize - OVERHEAD;

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
    if o.payload.len() > MAX_PAYLOAD {
        return None;
    }
    let total = OVERHEAD + o.payload.len();
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
    shared: Arc<Shared>,
}

impl Forwarder {
    /// Opens a UDP socket towards `collector` (`host:port`) and starts the sending thread.
    /// Returns the address the collector resolved to, for the startup report.
    pub fn start(collector: &str, agent_id: u32) -> std::io::Result<(Self, SocketAddr)> {
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
        Ok((Self::spawn(sink, QUEUE, agent_id)?, addr))
    }

    /// Starts the sending thread over an arbitrary sink with a queue of `capacity`.
    fn spawn(mut sink: Sink, capacity: usize, agent_id: u32) -> std::io::Result<Self> {
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
        Ok(Self {
            tx,
            agent_id,
            shared,
        })
    }

    /// Queues a copy of one datagram. Never blocks: a full queue drops the copy and counts
    /// the drop, because capture must not wait on a collector.
    pub fn forward(&self, o: &Observed<'_>) {
        let queued = encode(o, self.agent_id).is_some_and(|pkt| self.tx.try_send(pkt).is_ok());
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
        let f = Forwarder::spawn(sink, 1, 1).unwrap();
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
        let f = Forwarder::spawn(sink, 8, 1).unwrap();
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
        let (f, resolved) = Forwarder::start(&target.to_string(), SPEC_AGENT_ID).unwrap();
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
}
