// TFPS XDP program — drops SIP traffic from sources already condemned.
//
// This is the program that makes the garbage **vanish from sngrep**, and the reason is
// the ordering inside the kernel: XDP runs in `netif_receive_skb_internal`, before
// `__netif_receive_skb_core` hands the packet to the `ptype_all` taps — which is where
// libpcap (hence sngrep, tcpdump and tshark) hooks in. A packet dropped here never
// reaches the tap.
//
// That is why `nftables` would not do: its drop happens in netfilter, after the tap, and
// the capture would stay polluted.
//
// Written in C rather than Rust because only the kernel side needs LLVM/clang, and
// keeping it in C means no `bpf-linker` on the development machine. The userspace side is
// Rust with `aya`, which is pure Rust.
//
// Build (on the target, with vmlinux.h generated from BTF):
//   clang -O2 -g -target bpf -c tfps_xdp.c -o tfps_xdp.o

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800
#define IPPROTO_UDP_ 17
#define IPPROTO_TCP_ 6

// Ceiling on simultaneously blocked sources. `LRU_HASH` evicts the least recently used
// entry when it fills up, which gives a hard memory bound — the program never grows
// without limit, unlike what the userspace side did before this revision.
#define MAX_BLOCKED 65536

// Condemned sources: IPv4 in network order -> expiry instant in monotonic ns.
// A value of 0 means "never expires".
//
// Expiry exists because a wrong block has to undo itself: nobody will be awake at 3am to
// unblock a legitimate customer.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_BLOCKED);
    __type(key, __u32);
    __type(value, __u64);
} blocked SEC(".maps");

// Watched SIP ports. Only traffic to/from these ports is dropped.
//
// **Limiting the blast radius is deliberate**: an IP behind CGNAT can host a scanner and
// a legitimate user at the same time. Dropping everything from that address would take
// down SSH and the web for people who did nothing. Here the damage stays confined to SIP.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, __u16);
    __type(value, __u8);
} sip_ports SEC(".maps");

// Counters: [0] dropped, [1] seen, [2] expired, [3] reported, [4] lost.
// The indices are mirrored in crates/tfps/src/xdp.rs and held to these by a test.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 5);
    __type(key, __u32);
    __type(value, __u64);
} counters SEC(".maps");

#define C_DROPPED  0
#define C_SEEN     1
#define C_EXPIRED  2
#define C_REPORTED 3 // drop events handed to userspace
#define C_LOST     4 // drop events the ring buffer had no room for

// ---- What a condemned source keeps doing ----
//
// A packet dropped below never becomes an sk_buff, so nothing after this hook sees it:
// not the softswitch, not a capture on the box, and not TFPS's own AF_PACKET sensor,
// which reads the same tap. The counters alone say how MANY packets vanished and nothing
// about WHAT they were, so a wrong block would be unobservable from the inside — a
// customer's REGISTERs and a scanner's OPTIONS flood count the same. SPEC 7: the event
// goes to the ring buffer BEFORE the drop, so the silence does not blind the sensor.
//
// The cost under flood, and the policy that bounds it. A flooding source is precisely
// the one being dropped, and one event per dropped packet would turn a 100k pps flood
// into 100k ring-buffer writes a second — paying per packet for the traffic XDP exists
// to make free. So events are SAMPLED per source: the first DROP_REPORTS_PER_WINDOW
// drops from each source in every DROP_WINDOW_NS window are reported and the rest are
// only counted. The running count travels inside every event, so userspace knows the
// true volume even though it sees a sample. A source that is quiet and comes back is
// reported again on its first packet, because that is the packet an operator wants to
// see. Whatever the ring buffer cannot hold is counted in C_LOST and never blocks the
// drop: reporting is best effort, dropping is not.
//
// The per-source bookkeeping is racy across CPUs by design. RSS keeps one flow on one
// queue, so it rarely matters, and the worst case is a few events over the cap in one
// window — a bound, not an exact count. Making it exact would cost a lock on the drop
// path of every blocked packet.

#define DROP_PREVIEW 96
#define DROP_WINDOW_NS 1000000000ULL
#define DROP_REPORTS_PER_WINDOW 4
#define DROP_RING_BYTES (1 << 20)

struct drop_event {
    __u64 ts_ns;                // bpf_ktime_get_ns() at the drop
    __u64 drops;                // this source's running drop count, this packet included
    __u32 src;                  // ip->saddr as it came off the wire, the `blocked` key
    __u16 sport;                // host order
    __u16 dport;                // host order: one of the watched SIP ports
    __u16 len;                  // L4 payload bytes as the IP header declares them
    __u8  proto;                // 17 UDP, 6 TCP
    __u8  preview_len;          // bytes valid in preview
    __u8  preview[DROP_PREVIEW]; // the start of the payload: the SIP request line
};

// Userspace reads the record by offset (crates/tfps/src/drops.rs). These pin the layout
// on this side, and a test pins the other side to these numbers, so a moved field fails
// a build rather than a parse in production.
_Static_assert(sizeof(struct drop_event) == 128, "drop_event size is read by userspace");
_Static_assert(__builtin_offsetof(struct drop_event, ts_ns) == 0, "drop_event.ts_ns");
_Static_assert(__builtin_offsetof(struct drop_event, drops) == 8, "drop_event.drops");
_Static_assert(__builtin_offsetof(struct drop_event, src) == 16, "drop_event.src");
_Static_assert(__builtin_offsetof(struct drop_event, sport) == 20, "drop_event.sport");
_Static_assert(__builtin_offsetof(struct drop_event, dport) == 22, "drop_event.dport");
_Static_assert(__builtin_offsetof(struct drop_event, len) == 24, "drop_event.len");
_Static_assert(__builtin_offsetof(struct drop_event, proto) == 26, "drop_event.proto");
_Static_assert(__builtin_offsetof(struct drop_event, preview_len) == 27, "drop_event.preview_len");
_Static_assert(__builtin_offsetof(struct drop_event, preview) == 28, "drop_event.preview");

// The ring buffer itself. 1 MiB holds 8192 records; at the sampling cap that is two
// thousand sources flooding at once before anything is lost, and a loss is counted.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, DROP_RING_BYTES);
} drop_events SEC(".maps");

// Per-source sampling state. LRU like `blocked` and the same size: a source that is not
// being dropped has no business here, and eviction only restarts a count that
// userspace knows how to read (it carries on from the last value it saw).
struct drop_window {
    __u64 start_ns;  // when the current window opened
    __u64 drops;     // running drop count since this entry was created
    __u32 reported;  // events emitted in the current window
    __u32 _pad;
};

// Userspace reads `drops` out of this map at report and checkpoint time, because the
// events are a sample and this is the total: a source that stops mid-window would
// otherwise be counted only up to its last reported packet. Pinned like drop_event.
_Static_assert(sizeof(struct drop_window) == 24, "drop_window size is read by userspace");
_Static_assert(__builtin_offsetof(struct drop_window, drops) == 8, "drop_window.drops");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_BLOCKED);
    __type(key, __u32);
    __type(value, struct drop_window);
} drop_windows SEC(".maps");

static __always_inline void bump(__u32 idx)
{
    __u64 *c = bpf_map_lookup_elem(&counters, &idx);
    if (c)
        __sync_fetch_and_add(c, 1);
}

static __always_inline int is_sip_port(__u16 port)
{
    __u8 *v = bpf_map_lookup_elem(&sip_ports, &port);
    return v != 0;
}

// Counts this drop against its source and decides whether it is reported.
// Returns the source's running drop count and sets *report.
static __always_inline __u64 account_drop(__u32 src, __u64 now, int *report)
{
    struct drop_window *w = bpf_map_lookup_elem(&drop_windows, &src);
    if (!w) {
        struct drop_window fresh = { .start_ns = now, .drops = 1, .reported = 1, ._pad = 0 };
        // If the insert fails the count is lost, not the event: a first sighting is
        // always reported.
        bpf_map_update_elem(&drop_windows, &src, &fresh, BPF_ANY);
        *report = 1;
        return 1;
    }
    __sync_fetch_and_add(&w->drops, 1);
    __u64 drops = w->drops;
    if (now - w->start_ns >= DROP_WINDOW_NS) {
        w->start_ns = now;
        w->reported = 1;
        *report = 1;
        return drops;
    }
    if (w->reported < DROP_REPORTS_PER_WINDOW) {
        __sync_fetch_and_add(&w->reported, 1);
        *report = 1;
        return drops;
    }
    *report = 0;
    return drops;
}

// Writes one event. `payload` is where the L4 payload starts; it may already lie past
// `data_end` (a TCP SYN), in which case the preview is empty and the event still goes.
static __always_inline void report_drop(__u32 src, __u16 sport, __u16 dport, __u16 len,
                                        __u8 proto, __u64 now, __u64 drops,
                                        __u8 *payload, void *data_end)
{
    struct drop_event *ev = bpf_ringbuf_reserve(&drop_events, sizeof(*ev), 0);
    if (!ev) {
        // Userspace is not draining fast enough. Counted so it can be reported as the
        // sample being thinner than the policy says; never a reason not to drop.
        bump(C_LOST);
        return;
    }
    __builtin_memset(ev, 0, sizeof(*ev));
    ev->ts_ns = now;
    ev->drops = drops;
    ev->src = src;
    ev->sport = sport;
    ev->dport = dport;
    ev->len = len;
    ev->proto = proto;
    __u32 n = 0;
#pragma unroll
    for (int i = 0; i < DROP_PREVIEW; i++) {
        // One bound check per byte: the verifier will not take a single check over a
        // range that starts at a sender-controlled offset.
        if ((void *)(payload + i + 1) > data_end)
            break;
        ev->preview[i] = payload[i];
        n = i + 1;
    }
    ev->preview_len = n;
    // No wakeup: userspace polls, so the drop path is spared the irq_work per event.
    bpf_ringbuf_submit(ev, BPF_RB_NO_WAKEUP);
    bump(C_REPORTED);
}

SEC("xdp")
int tfps_filter(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS; // IPv6 and the rest pass — see the limitation recorded in the README

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // IHL comes in 32-bit words and is controlled by the sender; the verifier demands the
    // bound be checked after computing it.
    __u32 ihl = ip->ihl * 4;
    if (ihl < sizeof(struct iphdr))
        return XDP_PASS;

    // Ports for UDP and TCP alike. The first two bytes of both headers are the source port
    // and the next two the destination, so one read serves both — but each needs its own
    // length check first. Enforcement covers TCP so a blocked source is dropped on the
    // TLS/TCP SIP port (e.g. 5061), not only on UDP 5060; the content is never parsed here.
    // `l4len` is where the payload starts, for the drop event's preview.
    __u16 sport, dport;
    __u32 l4len;
    if (ip->protocol == IPPROTO_UDP_) {
        if ((void *)ip + ihl + sizeof(struct udphdr) > data_end)
            return XDP_PASS;
        struct udphdr *udp = (void *)ip + ihl;
        sport = bpf_ntohs(udp->source);
        dport = bpf_ntohs(udp->dest);
        l4len = sizeof(struct udphdr);
    } else if (ip->protocol == IPPROTO_TCP_) {
        if ((void *)ip + ihl + sizeof(struct tcphdr) > data_end)
            return XDP_PASS;
        struct tcphdr *tcp = (void *)ip + ihl;
        sport = bpf_ntohs(tcp->source);
        dport = bpf_ntohs(tcp->dest);
        l4len = tcp->doff * 4;
    } else {
        return XDP_PASS;
    }
    if (!is_sip_port(dport) && !is_sip_port(sport))
        return XDP_PASS;

    bump(C_SEEN);

    __u32 src = ip->saddr;
    __u64 *until = bpf_map_lookup_elem(&blocked, &src);
    if (!until)
        return XDP_PASS;

    __u64 now = bpf_ktime_get_ns();
    if (*until != 0 && now > *until) {
        // Expired: remove it and let it through. Unblocking happens on its own, with no
        // background sweep and nobody having to intervene.
        bpf_map_delete_elem(&blocked, &src);
        bump(C_EXPIRED);
        return XDP_PASS;
    }

    bump(C_DROPPED);
    int report = 0;
    __u64 drops = account_drop(src, now, &report);
    if (report) {
        // Payload length from the IP header rather than from what arrived: a
        // fragmented or truncated frame still reports what the sender declared.
        __u32 hdrs = ihl + l4len;
        __u16 tot = bpf_ntohs(ip->tot_len);
        __u16 len = tot > hdrs ? tot - hdrs : 0;
        report_drop(src, sport, dport, len, ip->protocol, now, drops,
                    (__u8 *)ip + hdrs, data_end);
    }
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
