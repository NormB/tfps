//! What a condemned source kept doing: the drop events the XDP program reports.
//!
//! A packet dropped at XDP never becomes an `sk_buff`, so nothing below that hook sees
//! it — not the softswitch, not an analyzer on the box, and not TFPS's own `AF_PACKET`
//! sensor, which reads the same tap. Until these events existed, the counters were the
//! entire record of what the product does after a block, and a wrong block was
//! unobservable from the inside: a customer's `REGISTER`s and a scanner's `OPTIONS` flood
//! counted the same.
//!
//! This module is the userspace half: the conversion of a raw ring-buffer record into a
//! typed event, and the decisions that follow — what to announce, what to keep, what to
//! persist. It does no I/O, so all of it is driven from tests; the kernel half in
//! `ebpf/tfps_xdp.c` is pinned to it by a layout contract, not by trust.
//!
//! **The events are a sample; the counts are not.** The program reports the first few
//! drops from each source per second and only counts the rest, but every event carries
//! the source's running total, so the volume here is exact whatever the sampling did.

use std::collections::HashMap;
use std::fmt;
use std::net::Ipv4Addr;

/// Bytes of payload the program copies into each event — enough for the SIP request line.
pub const PREVIEW_LEN: usize = 96;
/// `sizeof(struct drop_event)` in `ebpf/tfps_xdp.c`: one ring-buffer record.
pub const EVENT_LEN: usize = 128;
/// IANA protocol number for UDP, as `ip->protocol` carries it.
pub const PROTO_UDP: u8 = 17;
/// IANA protocol number for TCP.
pub const PROTO_TCP: u8 = 6;
/// How long a source stays out of the journal after being announced. The kernel already
/// caps events per source per second; this second cap is what keeps a blocked flood
/// from writing more than one line a minute.
pub const ANNOUNCE_EVERY_NS: u64 = 60_000_000_000;
/// Ceiling on the sources the ledger remembers — the kernel's own `MAX_BLOCKED`, since
/// nothing more than that can be dropping at once.
pub const MAX_SOURCES: usize = 65_536;

/// Byte offsets of each field inside the record, mirroring `struct drop_event`.
///
/// Read by offset rather than by casting: the record comes from another language and
/// another address space, and a cast would make a layout disagreement a silent misread
/// rather than a checked one.
pub mod offset {
    /// `bpf_ktime_get_ns()` at the drop, `u64` in host order.
    pub const TS_NS: usize = 0;
    /// The source's running drop count, this packet included.
    pub const DROPS: usize = 8;
    /// `ip->saddr` as it came off the wire: four bytes in network order.
    pub const SRC: usize = 16;
    /// Source port, host order — the program already swapped it.
    pub const SPORT: usize = 20;
    /// Destination port, host order.
    pub const DPORT: usize = 22;
    /// L4 payload length as the IP header declares it, host order.
    pub const LEN: usize = 24;
    /// `ip->protocol`.
    pub const PROTO: usize = 26;
    /// How many bytes of the preview are valid.
    pub const PREVIEW_LEN: usize = 27;
    /// The first bytes of the payload.
    pub const PREVIEW: usize = 28;
}

/// `sizeof(struct drop_window)`: one value of the program's per-source sampling map.
pub const WINDOW_LEN: usize = 24;

/// Byte offsets inside `struct drop_window`, the per-source sampling state.
///
/// The events are a sample, capped per source per second; this map is the total. It is
/// read at report and checkpoint time so a source that stops mid-window — thirty packets
/// and four events, the last one saying `drops=4` — is still counted in full.
pub mod window_offset {
    /// When the current window opened, monotonic ns.
    pub const START_NS: usize = 0;
    /// The source's running drop count since the entry was created.
    pub const DROPS: usize = 8;
    /// Events emitted in the current window.
    pub const REPORTED: usize = 16;
}

/// The running drop count inside one `drop_windows` value, or `None` when the value is
/// not the size the program pins — a layout disagreement, never read as zero.
pub fn parse_window_drops(raw: &[u8]) -> Option<u64> {
    if raw.len() < WINDOW_LEN {
        return None;
    }
    let mut b = [0u8; 8];
    b.copy_from_slice(&raw[window_offset::DROPS..window_offset::DROPS + 8]);
    Some(u64::from_ne_bytes(b))
}

/// One dropped packet, as the program described it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DropEvent {
    /// Monotonic nanoseconds at the drop (`bpf_ktime_get_ns`).
    pub ts_ns: u64,
    /// This source's running drop count in the kernel, this packet included.
    pub drops: u64,
    /// The condemned source.
    pub src: Ipv4Addr,
    /// Source port.
    pub sport: u16,
    /// Destination port — one of the watched SIP ports.
    pub dport: u16,
    /// Payload length on the wire, whatever the preview captured of it.
    pub len: u16,
    /// IP protocol number: [`PROTO_UDP`] or [`PROTO_TCP`].
    pub proto: u8,
    /// The first bytes of the payload, at most [`PREVIEW_LEN`].
    pub preview: Vec<u8>,
}

impl DropEvent {
    /// The SIP request line, or whatever the first line of the payload was.
    pub fn request_line(&self) -> String {
        request_line(&self.preview)
    }

    /// `udp` or `tcp` — the only two protocols the program drops.
    pub fn proto_name(&self) -> &'static str {
        proto_name(self.proto)
    }
}

/// The name of an IP protocol number the program can drop: `udp`, `tcp`, else `other`.
///
/// One function for the daemon's line and the control tool's column, so the two never
/// name the same packet differently.
pub fn proto_name(proto: u8) -> &'static str {
    match proto {
        PROTO_UDP => "udp",
        PROTO_TCP => "tcp",
        _ => "other",
    }
}

/// Why a record could not be read. Either means the two halves disagree on the layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// Fewer bytes than a record. Reading zeros for the tail would hide a moved field.
    Short {
        /// How many bytes arrived.
        got: usize,
    },
    /// The preview length claims more than the field holds.
    PreviewOverrun {
        /// The claimed length.
        claimed: u8,
    },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Short { got } => write!(f, "drop event of {got} bytes, expected {EVENT_LEN}"),
            Self::PreviewOverrun { claimed } => {
                write!(
                    f,
                    "drop event claims a {claimed}-byte preview in a {PREVIEW_LEN}-byte field"
                )
            }
        }
    }
}

/// Reads one record as `struct drop_event` laid it out.
pub fn parse_event(raw: &[u8]) -> Result<DropEvent, ParseError> {
    if raw.len() < EVENT_LEN {
        return Err(ParseError::Short { got: raw.len() });
    }
    let n = raw[offset::PREVIEW_LEN];
    if usize::from(n) > PREVIEW_LEN {
        return Err(ParseError::PreviewOverrun { claimed: n });
    }
    let u64_at = |o: usize| {
        let mut b = [0u8; 8];
        b.copy_from_slice(&raw[o..o + 8]);
        u64::from_ne_bytes(b)
    };
    let u16_at = |o: usize| u16::from_ne_bytes([raw[o], raw[o + 1]]);
    let s = offset::SRC;
    Ok(DropEvent {
        ts_ns: u64_at(offset::TS_NS),
        drops: u64_at(offset::DROPS),
        // The bytes are already in wire order; no integer conversion is involved,
        // which is what makes this the same key the `blocked` map uses.
        src: Ipv4Addr::new(raw[s], raw[s + 1], raw[s + 2], raw[s + 3]),
        sport: u16_at(offset::SPORT),
        dport: u16_at(offset::DPORT),
        len: u16_at(offset::LEN),
        proto: raw[offset::PROTO],
        preview: raw[offset::PREVIEW..offset::PREVIEW + usize::from(n)].to_vec(),
    })
}

/// The first line of a payload, made safe for a log.
///
/// Control bytes are masked the way the `NOT-SIP` preview masks them, and a line the
/// preview cut short is marked, so an operator does not read the cut as the end.
pub fn request_line(preview: &[u8]) -> String {
    let end = preview.iter().position(|b| *b == b'\r' || *b == b'\n');
    let line = &preview[..end.unwrap_or(preview.len())];
    let mut out: String = line
        .iter()
        .map(|b| {
            if b.is_ascii_graphic() || *b == b' ' {
                *b as char
            } else {
                '.'
            }
        })
        .collect();
    if end.is_none() && preview.len() >= PREVIEW_LEN {
        out.push_str(" [cut]");
    }
    out
}

/// How loudly a drop should be reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Announce {
    /// The first drop seen from this source: it is still sending after its block.
    First,
    /// Still at it, a minute or more after the last line about it.
    Again,
    /// Within the interval; the count is kept, the journal is spared.
    Quiet,
}

/// Everything remembered about one dropped source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DropSummary {
    /// The source.
    pub src: Ipv4Addr,
    /// Monotonic ns of the first drop seen.
    pub first_ns: u64,
    /// Monotonic ns of the latest drop seen, or of the block note if none was.
    pub last_ns: u64,
    /// Packets dropped — the kernel's exact count, not the number of events.
    pub drops: u64,
    /// Events received: the sample.
    pub events: u64,
    /// Destination port of the latest drop.
    pub last_dport: u16,
    /// Payload length of the latest drop.
    pub last_len: u16,
    /// Protocol of the latest drop.
    pub last_proto: u8,
    /// Request line of the latest drop.
    pub last_line: String,
    /// `(kind, detail)` this process blocked the source for, if this process did.
    pub reason: Option<(String, String)>,
    /// The last running count the kernel reported, to turn totals into deltas.
    kernel_count: u64,
    /// How much of `drops` has been handed to the database.
    flushed_drops: u64,
    /// How much of `events` has been handed to the database.
    flushed_events: u64,
    /// When the journal last heard about this source.
    announced_ns: Option<u64>,
}

impl DropSummary {
    fn blank(src: Ipv4Addr, now_ns: u64) -> Self {
        Self {
            src,
            first_ns: 0,
            last_ns: now_ns,
            drops: 0,
            events: 0,
            last_dport: 0,
            last_len: 0,
            last_proto: 0,
            last_line: String::new(),
            reason: None,
            kernel_count: 0,
            flushed_drops: 0,
            flushed_events: 0,
            announced_ns: None,
        }
    }
}

/// What the database is owed since the last checkpoint, per source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DropDelta {
    /// The source.
    pub src: Ipv4Addr,
    /// Drops not yet persisted.
    pub drops: u64,
    /// Events not yet persisted.
    pub events: u64,
    /// Monotonic ns of the first drop seen.
    pub first_ns: u64,
    /// Monotonic ns of the latest drop seen.
    pub last_ns: u64,
    /// Destination port of the latest drop.
    pub last_dport: u16,
    /// Payload length of the latest drop.
    pub last_len: u16,
    /// Protocol of the latest drop.
    pub last_proto: u8,
    /// Request line of the latest drop.
    pub last_line: String,
}

/// One row of `drop_log`, in wall-clock time — what `tfps_ctl dropped` reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DropRow {
    /// The source, as text.
    pub ip: String,
    /// Unix seconds of the first drop seen.
    pub first_ts: u32,
    /// Unix seconds of the latest drop seen.
    pub last_ts: u32,
    /// Packets dropped.
    pub drops: u64,
    /// Events received.
    pub events: u64,
    /// Destination port of the latest drop.
    pub last_port: u16,
    /// Payload length of the latest drop.
    pub last_len: u16,
    /// Protocol of the latest drop.
    pub last_proto: u8,
    /// Request line of the latest drop.
    pub last_line: String,
}

impl DropDelta {
    /// Converts to wall-clock time, given a pair of readings taken together.
    pub fn to_row(&self, now_wall: u32, now_mono_ns: u64) -> DropRow {
        DropRow {
            ip: self.src.to_string(),
            first_ts: wall_secs(now_wall, now_mono_ns, self.first_ns),
            last_ts: wall_secs(now_wall, now_mono_ns, self.last_ns),
            drops: self.drops,
            events: self.events,
            last_port: self.last_dport,
            last_len: self.last_len,
            last_proto: self.last_proto,
            last_line: self.last_line.clone(),
        }
    }
}

/// Monotonic nanoseconds to Unix seconds, anchored on one pair of readings.
///
/// An event stamped after the monotonic reading — the drain raced the clock — is
/// clamped to now rather than allowed to wrap.
pub fn wall_secs(now_wall: u32, now_mono_ns: u64, ev_mono_ns: u64) -> u32 {
    let behind = now_mono_ns.saturating_sub(ev_mono_ns) / 1_000_000_000;
    now_wall.saturating_sub(u32::try_from(behind).unwrap_or(u32::MAX))
}

/// The dropped sources this process has seen, and what is owed to the journal and the
/// database about each.
///
/// Bounded at construction. When full, the quietest sixty-fourth is evicted at once, so
/// the scan is paid once per batch of newcomers rather than once per newcomer.
pub struct Ledger {
    cap: usize,
    sources: HashMap<Ipv4Addr, DropSummary>,
}

impl Default for Ledger {
    fn default() -> Self {
        Self::new()
    }
}

impl Ledger {
    /// A ledger bounded at [`MAX_SOURCES`].
    pub fn new() -> Self {
        Self::with_capacity(MAX_SOURCES)
    }

    /// A ledger bounded at `cap` sources (at least one).
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            cap: cap.max(1),
            sources: HashMap::new(),
        }
    }

    fn entry(&mut self, src: Ipv4Addr, now_ns: u64) -> &mut DropSummary {
        if !self.sources.contains_key(&src) && self.sources.len() >= self.cap {
            self.evict();
        }
        self.sources
            .entry(src)
            .or_insert_with(|| DropSummary::blank(src, now_ns))
    }

    fn evict(&mut self) {
        let n = (self.cap / 64).max(1);
        let mut by_age: Vec<(u64, Ipv4Addr)> =
            self.sources.values().map(|s| (s.last_ns, s.src)).collect();
        by_age.sort_unstable();
        for (_, ip) in by_age.into_iter().take(n) {
            self.sources.remove(&ip);
        }
    }

    /// Records why this process blocked `src`, so its drops can say so.
    pub fn note_block(&mut self, src: Ipv4Addr, kind: &str, detail: &str, now_ns: u64) {
        self.entry(src, now_ns).reason = Some((kind.to_string(), detail.to_string()));
    }

    /// Folds a kernel running count into a summary.
    ///
    /// The kernel's count is a running total per source, so the new drops are the
    /// difference — unless it went backwards, which is the per-source entry having
    /// been evicted and recreated: everything before the reset already counted, and
    /// the new value is everything since. One rule for events and for map reads.
    fn absorb(s: &mut DropSummary, kernel_drops: u64) {
        let delta = if kernel_drops > s.kernel_count {
            kernel_drops - s.kernel_count
        } else if kernel_drops == s.kernel_count {
            0
        } else {
            kernel_drops
        };
        s.kernel_count = kernel_drops;
        s.drops += delta;
    }

    /// Folds the kernel's per-source total in, from the sampling map rather than from
    /// an event. Not an announcement and not an event: the sample stays what it was.
    pub fn sync_count(&mut self, src: Ipv4Addr, kernel_drops: u64, now_ns: u64) {
        let s = self.entry(src, now_ns);
        Self::absorb(s, kernel_drops);
    }

    /// Folds one event in and says how loudly to report it.
    pub fn record(&mut self, ev: &DropEvent) -> Announce {
        let s = self.entry(ev.src, ev.ts_ns);
        Self::absorb(s, ev.drops);
        s.events += 1;
        if s.events == 1 {
            s.first_ns = ev.ts_ns;
        }
        s.last_ns = ev.ts_ns;
        s.last_dport = ev.dport;
        s.last_len = ev.len;
        s.last_proto = ev.proto;
        s.last_line = ev.request_line();
        let announce = match s.announced_ns {
            None => Announce::First,
            Some(t) if ev.ts_ns.saturating_sub(t) >= ANNOUNCE_EVERY_NS => Announce::Again,
            Some(_) => Announce::Quiet,
        };
        if announce != Announce::Quiet {
            s.announced_ns = Some(ev.ts_ns);
        }
        announce
    }

    /// The summary of a source at least one drop is known from — an event or the map.
    pub fn summary(&self, src: Ipv4Addr) -> Option<&DropSummary> {
        self.sources.get(&src).filter(|s| s.drops > 0)
    }

    /// Every source at least one drop is known from, most dropped first.
    pub fn summaries(&self) -> Vec<&DropSummary> {
        let mut out: Vec<&DropSummary> = self.sources.values().filter(|s| s.drops > 0).collect();
        out.sort_by(|a, b| b.drops.cmp(&a.drops).then(a.src.cmp(&b.src)));
        out
    }

    /// How many sources at least one drop is known from.
    pub fn len(&self) -> usize {
        self.sources.values().filter(|s| s.drops > 0).count()
    }

    /// Whether no drop has been seen from any source.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// What has changed since the last flush, and marks it flushed.
    ///
    /// Deltas, not totals: the database adds them, so a row written across two
    /// checkpoints — or two daemon lifetimes — counts every drop once.
    pub fn flush(&mut self) -> Vec<DropDelta> {
        let mut out = Vec::new();
        for s in self.sources.values_mut() {
            let drops = s.drops - s.flushed_drops;
            let events = s.events - s.flushed_events;
            if events == 0 && drops == 0 {
                continue;
            }
            out.push(DropDelta {
                src: s.src,
                drops,
                events,
                first_ns: s.first_ns,
                last_ns: s.last_ns,
                last_dport: s.last_dport,
                last_len: s.last_len,
                last_proto: s.last_proto,
                last_line: s.last_line.clone(),
            });
            s.flushed_drops = s.drops;
            s.flushed_events = s.events;
        }
        out.sort_by_key(|d| d.src);
        out
    }
}

/// The journal line for a drop: who, why, what they sent, and how much of it so far.
///
/// A source this process did not block — one placed by hand with `tfps_ctl ban` — is
/// printed as `unrecorded` rather than given a reason it never had.
pub fn drop_line(ev: &DropEvent, s: &DropSummary) -> String {
    let (kind, detail) = s
        .reason
        .as_ref()
        .map(|(k, d)| (k.as_str(), d.as_str()))
        .unwrap_or(("unrecorded", "-"));
    format!(
        "DROPPED peer={} reason={kind} detail={detail} proto={} port={} drops={} len={} request=\"{}\"",
        ev.src,
        ev.proto_name(),
        ev.dport,
        s.drops,
        ev.len,
        ev.request_line()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    // The wire cannot be driven from here: emitting a real event needs `CAP_BPF`, an
    // attached XDP program and a packet arriving from a blocked source. What CAN be
    // driven is everything userspace does with the bytes once they arrive, so the
    // fixture is a record laid out exactly as `struct drop_event` in the C program —
    // by LITERAL offsets, on purpose. A fixture built from the same constants the parser
    // reads would move with a wrong constant and pass over it.
    fn raw_event(ev: &DropEvent) -> Vec<u8> {
        let mut b = vec![0u8; 128];
        b[0..8].copy_from_slice(&ev.ts_ns.to_ne_bytes());
        b[8..16].copy_from_slice(&ev.drops.to_ne_bytes());
        // The octets ARE the wire order: this is `ip->saddr` copied, not converted.
        b[16..20].copy_from_slice(&ev.src.octets());
        b[20..22].copy_from_slice(&ev.sport.to_ne_bytes());
        b[22..24].copy_from_slice(&ev.dport.to_ne_bytes());
        b[24..26].copy_from_slice(&ev.len.to_ne_bytes());
        b[26] = ev.proto;
        b[27] = ev.preview.len() as u8;
        b[28..28 + ev.preview.len()].copy_from_slice(&ev.preview);
        b
    }

    const OPTIONS: &[u8] =
        b"OPTIONS sip:100@203.0.113.9 SIP/2.0\r\nVia: SIP/2.0/UDP 203.0.113.5:5062\r\n";

    fn sample(proto: u8, preview: &[u8]) -> DropEvent {
        DropEvent {
            ts_ns: 1_234_567_890_123,
            drops: 42,
            src: Ipv4Addr::new(203, 0, 113, 5),
            sport: 5062,
            dport: 5060,
            len: 417,
            proto,
            preview: preview.to_vec(),
        }
    }

    #[test]
    fn a_raw_event_parses_into_every_field() {
        let want = sample(PROTO_UDP, OPTIONS);
        let ev = parse_event(&raw_event(&want)).unwrap();
        assert_eq!(ev.ts_ns, 1_234_567_890_123);
        assert_eq!(ev.drops, 42);
        // `src` is the raw `ip->saddr`, the same bytes the `blocked` map is keyed by:
        // wire order, never swapped.
        assert_eq!(ev.src, Ipv4Addr::new(203, 0, 113, 5));
        // The ports were `bpf_ntohs`-ed in the kernel and are host order here.
        assert_eq!(ev.sport, 5062);
        assert_eq!(ev.dport, 5060);
        assert_eq!(ev.len, 417);
        assert_eq!(ev.proto, PROTO_UDP);
        assert_eq!(ev.preview, OPTIONS);
        assert_eq!(ev, want, "and nothing else differs");
    }

    #[test]
    fn the_layout_constants_are_the_ones_the_fixture_was_built_with() {
        // The fixture above uses literal offsets. This is the other half: the parser's
        // constants must be those literals, or the two agree only by accident.
        assert_eq!(EVENT_LEN, 128);
        assert_eq!(PREVIEW_LEN, 96);
        assert_eq!(offset::TS_NS, 0);
        assert_eq!(offset::DROPS, 8);
        assert_eq!(offset::SRC, 16);
        assert_eq!(offset::SPORT, 20);
        assert_eq!(offset::DPORT, 22);
        assert_eq!(offset::LEN, 24);
        assert_eq!(offset::PROTO, 26);
        assert_eq!(offset::PREVIEW_LEN, 27);
        assert_eq!(offset::PREVIEW, 28);
    }

    #[test]
    fn a_short_record_is_an_error_not_a_zeroed_event() {
        let raw = raw_event(&sample(PROTO_UDP, b""));
        let short = &raw[..raw.len() - 1];
        assert_eq!(
            parse_event(short),
            Err(ParseError::Short { got: 127 }),
            "a truncated record means the two sides disagree on the layout; \
             reading zeros for the missing tail would hide that"
        );
    }

    #[test]
    fn a_preview_length_beyond_the_field_is_rejected() {
        let mut raw = raw_event(&sample(PROTO_UDP, b"x"));
        raw[27] = 97;
        assert_eq!(
            parse_event(&raw),
            Err(ParseError::PreviewOverrun { claimed: 97 }),
            "clamping would silently accept a layout the kernel side does not have"
        );
    }

    #[test]
    fn a_full_preview_is_accepted() {
        // The boundary: 96 is the field, and must not be refused as an overrun.
        let full = [b'A'; 96];
        let raw = raw_event(&sample(PROTO_UDP, &full));
        assert_eq!(parse_event(&raw).unwrap().preview.len(), 96);
    }

    #[test]
    fn an_event_with_no_payload_has_an_empty_preview() {
        // A TCP SYN from a blocked source: dropped, reported, nothing to preview.
        let raw = raw_event(&sample(PROTO_TCP, b""));
        let ev = parse_event(&raw).unwrap();
        assert!(ev.preview.is_empty());
        assert_eq!(ev.request_line(), "");
        assert_eq!(ev.proto_name(), "tcp");
    }

    #[test]
    fn the_request_line_stops_at_the_first_line_break() {
        assert_eq!(request_line(OPTIONS), "OPTIONS sip:100@203.0.113.9 SIP/2.0");
        assert_eq!(
            request_line(b"REGISTER sip:x SIP/2.0\nVia:"),
            "REGISTER sip:x SIP/2.0"
        );
    }

    #[test]
    fn non_printable_bytes_in_the_request_line_are_masked() {
        // A binary probe from a blocked source must not put control bytes in the log.
        assert_eq!(
            request_line(b"INVITE \x00\x01sip \x7f\xff"),
            "INVITE ..sip .."
        );
    }

    #[test]
    fn a_request_line_cut_by_the_preview_says_so() {
        // No line break inside a full preview: the line continues past what was
        // captured, and the operator must not read the cut as the end of the line.
        let full = [b'A'; 96];
        assert_eq!(request_line(&full), format!("{} [cut]", "A".repeat(96)));
        // But a short preview with no line break is the whole payload, not a cut.
        assert_eq!(request_line(b"ping"), "ping");
    }

    // ---- the ledger: what is announced, kept, and persisted ----

    const A: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 5);
    const B: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 7);
    const C: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 9);

    fn ev(secs: u64, src: Ipv4Addr, drops: u64) -> DropEvent {
        DropEvent {
            ts_ns: secs * 1_000_000_000,
            drops,
            src,
            sport: 5062,
            dport: 5060,
            len: 300,
            proto: PROTO_UDP,
            preview: OPTIONS.to_vec(),
        }
    }

    #[test]
    fn the_first_drop_from_a_source_is_announced() {
        let mut l = Ledger::new();
        assert_eq!(l.record(&ev(10, A, 1)), Announce::First);
    }

    #[test]
    fn a_repeat_within_the_announce_interval_is_quiet() {
        // The kernel already caps events per source per second; the announcement is
        // capped again here so a blocked flood costs the journal one line a minute.
        let mut l = Ledger::new();
        l.record(&ev(10, A, 1));
        assert_eq!(l.record(&ev(20, A, 2)), Announce::Quiet);
        assert_eq!(l.record(&ev(69, A, 3)), Announce::Quiet);
    }

    #[test]
    fn after_the_announce_interval_the_source_is_announced_again() {
        let mut l = Ledger::new();
        l.record(&ev(10, A, 1));
        assert_eq!(l.record(&ev(70, A, 2)), Announce::Again);
        // And the clock restarts from that announcement.
        assert_eq!(l.record(&ev(100, A, 3)), Announce::Quiet);
        assert_eq!(l.record(&ev(130, A, 4)), Announce::Again);
    }

    #[test]
    fn sources_are_announced_independently() {
        let mut l = Ledger::new();
        l.record(&ev(10, A, 1));
        assert_eq!(l.record(&ev(11, B, 1)), Announce::First);
    }

    #[test]
    fn the_kernel_running_count_is_carried_not_summed() {
        // Every event carries the source's running drop count, so a sample of the
        // events still yields the exact volume. Adding the counts up would multiply it.
        let mut l = Ledger::new();
        l.record(&ev(10, A, 7));
        l.record(&ev(20, A, 12));
        let s = l.summary(A).unwrap();
        assert_eq!(s.drops, 12);
        assert_eq!(s.events, 2, "events are the sample; drops are the volume");
    }

    #[test]
    fn a_kernel_counter_reset_does_not_move_the_count_backwards() {
        // The per-source window entry is LRU and can be evicted, which restarts the
        // kernel's count. The drops before the reset happened; they stay counted.
        let mut l = Ledger::new();
        l.record(&ev(10, A, 12));
        l.record(&ev(20, A, 3));
        assert_eq!(l.summary(A).unwrap().drops, 15);
    }

    #[test]
    fn the_summary_keeps_the_latest_sighting() {
        let mut l = Ledger::new();
        l.record(&ev(10, A, 1));
        let mut later = ev(20, A, 2);
        later.dport = 5080;
        later.len = 512;
        later.proto = PROTO_TCP;
        later.preview = b"REGISTER sip:pbx SIP/2.0\r\n".to_vec();
        l.record(&later);
        let s = l.summary(A).unwrap();
        assert_eq!(s.first_ns, 10_000_000_000);
        assert_eq!(s.last_ns, 20_000_000_000);
        assert_eq!(s.last_dport, 5080);
        assert_eq!(s.last_len, 512);
        assert_eq!(s.last_proto, PROTO_TCP);
        assert_eq!(s.last_line, "REGISTER sip:pbx SIP/2.0");
    }

    #[test]
    fn flushing_yields_only_what_has_not_been_persisted() {
        let mut l = Ledger::new();
        l.record(&ev(10, A, 7));
        let first = l.flush();
        assert_eq!(first.len(), 1);
        assert_eq!((first[0].src, first[0].drops, first[0].events), (A, 7, 1));

        l.record(&ev(20, A, 12));
        let second = l.flush();
        assert_eq!(
            (second[0].drops, second[0].events),
            (5, 1),
            "the delta since the last flush, so the database adds and never double-counts"
        );
        assert!(l.flush().is_empty(), "nothing new, nothing to write");
    }

    #[test]
    fn the_reason_given_at_block_time_travels_with_the_drop() {
        let mut l = Ledger::new();
        l.note_block(A, "scanner", "sipvicious", 5_000_000_000);
        l.record(&ev(10, A, 1));
        let s = l.summary(A).unwrap();
        assert_eq!(
            s.reason.as_ref().map(|(k, d)| (k.as_str(), d.as_str())),
            Some(("scanner", "sipvicious"))
        );
        // And a source nobody told the ledger about — a block placed by hand with
        // `tfps_ctl ban` — is reported as such rather than invented.
        l.record(&ev(10, B, 1));
        assert_eq!(l.summary(B).unwrap().reason, None);
    }

    #[test]
    fn a_noted_block_that_never_drops_is_not_a_dropped_source() {
        let mut l = Ledger::new();
        l.note_block(A, "scanner", "sipvicious", 5_000_000_000);
        assert_eq!(l.len(), 0);
        assert!(l.summaries().is_empty());
        assert!(l.flush().is_empty());
    }

    #[test]
    fn summaries_come_most_dropped_first() {
        let mut l = Ledger::new();
        l.record(&ev(10, A, 3));
        l.record(&ev(11, B, 10));
        l.record(&ev(12, C, 5));
        let order: Vec<Ipv4Addr> = l.summaries().iter().map(|s| s.src).collect();
        assert_eq!(order, [B, C, A]);
    }

    #[test]
    fn the_ledger_is_bounded_and_evicts_the_longest_silent_source() {
        // Bounded like the kernel map it mirrors: a run that sees more blocked sources
        // than this forgets the quietest, never grows without limit.
        let mut l = Ledger::with_capacity(2);
        l.record(&ev(10, A, 1));
        l.record(&ev(20, B, 1));
        l.record(&ev(30, C, 1));
        assert_eq!(l.len(), 2);
        assert!(l.summary(A).is_none(), "A was silent longest");
        assert!(l.summary(B).is_some());
        assert!(l.summary(C).is_some());
    }

    #[test]
    fn the_wall_clock_conversion_anchors_on_now() {
        // Events carry `bpf_ktime_get_ns`, monotonic; rows carry Unix seconds. The
        // conversion is relative to a pair of readings taken together.
        assert_eq!(
            wall_secs(1_700_000_000, 500_000_000_000, 440_000_000_000),
            1_699_999_940
        );
        // An event stamped after "now" (a reading raced the drain) is clamped to now
        // rather than wrapping into the future.
        assert_eq!(
            wall_secs(1_700_000_000, 500_000_000_000, 501_000_000_000),
            1_700_000_000
        );
    }

    #[test]
    fn a_delta_becomes_a_row_in_wall_clock_time() {
        let mut l = Ledger::new();
        l.record(&ev(440, A, 7));
        let d = l.flush().remove(0);
        let row = d.to_row(1_700_000_000, 500_000_000_000);
        assert_eq!(row.ip, "203.0.113.5");
        assert_eq!(row.first_ts, 1_699_999_940);
        assert_eq!(row.last_ts, 1_699_999_940);
        assert_eq!((row.drops, row.events), (7, 1));
        assert_eq!(row.last_port, 5060);
        assert_eq!(row.last_len, 300);
        assert_eq!(row.last_proto, PROTO_UDP);
        assert_eq!(row.last_line, "OPTIONS sip:100@203.0.113.9 SIP/2.0");
    }

    #[test]
    fn the_dropped_line_names_the_source_the_reason_the_count_and_the_request() {
        let mut l = Ledger::new();
        l.note_block(A, "scanner", "sipvicious", 1);
        let e = ev(10, A, 42);
        l.record(&e);
        let line = drop_line(&e, l.summary(A).unwrap());
        assert_eq!(
            line,
            "DROPPED peer=203.0.113.5 reason=scanner detail=sipvicious proto=udp port=5060 \
             drops=42 len=300 request=\"OPTIONS sip:100@203.0.113.9 SIP/2.0\""
        );
    }

    // ---- the kernel's per-source map completes what the sample cannot ----
    //
    // Found on the wire, not by review: thirty packets from one source in under a
    // second produced four events (the cap), the fourth carrying `drops=4`, and then
    // nothing — so the ledger said 4 where the kernel had counted 30. The events are a
    // sample; the per-source window map is the total. It is read at report and
    // checkpoint time, and this is the conversion and the merge it feeds.

    #[test]
    fn a_window_record_yields_the_kernel_count() {
        // `struct drop_window`: start_ns at 0, drops at 8, reported at 16, pad at 20.
        let mut raw = [0u8; 24];
        raw[0..8].copy_from_slice(&7_000_000_000u64.to_ne_bytes());
        raw[8..16].copy_from_slice(&30u64.to_ne_bytes());
        raw[16..20].copy_from_slice(&4u32.to_ne_bytes());
        assert_eq!(parse_window_drops(&raw), Some(30));
        assert_eq!(
            parse_window_drops(&raw[..23]),
            None,
            "a short value means the two sides disagree on the layout"
        );
    }

    #[test]
    fn the_window_layout_constants_match_the_fixture() {
        assert_eq!(WINDOW_LEN, 24);
        assert_eq!(window_offset::START_NS, 0);
        assert_eq!(window_offset::DROPS, 8);
        assert_eq!(window_offset::REPORTED, 16);
    }

    #[test]
    fn syncing_from_the_kernel_map_completes_the_tail() {
        let mut l = Ledger::new();
        l.record(&ev(10, A, 4));
        l.sync_count(A, 30, 11_000_000_000);
        let s = l.summary(A).unwrap();
        assert_eq!(
            s.drops, 30,
            "the map holds the total the sample stopped short of"
        );
        assert_eq!(s.events, 1, "a sync is not an event");
        assert_eq!(s.last_line, "OPTIONS sip:100@203.0.113.9 SIP/2.0");
    }

    #[test]
    fn a_sync_never_moves_the_count_backwards() {
        // The kernel entry can be evicted and recreated, restarting its count; the
        // same rule as for events applies: what was counted stays counted.
        let mut l = Ledger::new();
        l.record(&ev(10, A, 12));
        l.sync_count(A, 3, 20_000_000_000);
        assert_eq!(l.summary(A).unwrap().drops, 15);
        // And a sync that says nothing new changes nothing.
        l.sync_count(A, 3, 21_000_000_000);
        assert_eq!(l.summary(A).unwrap().drops, 15);
    }

    #[test]
    fn a_source_whose_every_event_was_lost_is_still_a_dropped_source() {
        // Ring buffer full: no event ever arrived, but the map says it dropped.
        let mut l = Ledger::new();
        l.sync_count(B, 7, 20_000_000_000);
        let s = l.summary(B).expect("counted from the map alone");
        assert_eq!((s.drops, s.events), (7, 0));
        assert_eq!(l.len(), 1);
        let d = l.flush();
        assert_eq!(d.len(), 1);
        assert_eq!((d[0].drops, d[0].events), (7, 0));
    }

    #[test]
    fn an_unrecorded_reason_is_printed_as_such() {
        let mut l = Ledger::new();
        let e = ev(10, B, 1);
        l.record(&e);
        let line = drop_line(&e, l.summary(B).unwrap());
        assert!(
            line.contains("reason=unrecorded detail=-"),
            "a block this process did not place must not be given an invented reason: {line}"
        );
    }
}
