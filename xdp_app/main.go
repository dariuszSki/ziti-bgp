package main

import (
	"fmt"
	bpf "github.com/iovisor/gobpf/bcc"
	"os"
	"os/signal"
	"syscall"
)

/*
#cgo CFLAGS: -I/usr/include/bcc/compat
#cgo LDFLAGS: -lbcc
#include <bcc/bcc_common.h>
#include <bcc/libbpf.h>
void perf_reader_free(void *ptr);
*/
import "C"

const source string = `
#define KBUILD_MODNAME "filter"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#define IP_FRAGMENTED 65343
#define UDP_PORT 6081

struct pkt_meta {
    __be32 src;
    __be32 dst;
    union {
        __u32 ports;
        __u16 port16[2];
    };
};
BPF_TABLE("array", int, long, dropcnt, 256);

static __always_inline bool parse_udp(void *data, __u64 off, void *data_end,
                                      struct pkt_meta *pkt)
{
    struct udphdr *udp;
    udp = data + off;
    if (udp + 1 > data_end)
        return false;
    pkt->port16[0] = udp->source;
    pkt->port16[1] = udp->dest;
	if (udp->dest == htons(UDP_PORT))
		udp->dest = htons(6082);
    return true;
}
static inline int parse_ipv4(void *data, u64 nh_off, void *data_end)
{
    struct iphdr *iph = data + nh_off;
	struct pkt_meta pkt = {};
    __u16 payload_len;
    __u8 protocol;
    if ((void*)&iph[1] > data_end)
        return 0;
    protocol = iph->protocol;
    payload_len = bpf_ntohs(iph->tot_len);
    nh_off += sizeof(struct iphdr);
    /* do not support fragmented packets as L4 headers may be missing */
    if (iph->frag_off & IP_FRAGMENTED)
        return XDP_DROP;
    pkt.src = iph->saddr;
    pkt.dst = iph->daddr;
    /* obtain port numbers for UDP traffic */
    if (protocol == IPPROTO_UDP) {
        if (parse_udp(data, nh_off, data_end, &pkt))
            return protocol;
    }
    return protocol;
}
static inline int parse_ipv6(void *data, u64 nh_off, void *data_end)
{
    struct ipv6hdr *ip6h = data + nh_off;
    if ((void*)&ip6h[1] > data_end)
        return 0;
    return ip6h->nexthdr;
}
int udpfilter(struct CTXTYPE *ctx)
{
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;
    struct ethhdr *eth = data;
    // drop packets
    int rc = RETURNCODE; // let pass XDP_PASS or redirect to tx via XDP_TX
    long *value;
    uint16_t h_proto;
    uint64_t nh_off = 0;
    int index;
    nh_off = sizeof(*eth);
    if (data + nh_off  > data_end)
        return rc;
    h_proto = eth->h_proto;
    // While the following code appears to be duplicated accidentally,
    // it's intentional to handle double tags in ethernet frames.
    if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
        struct vlan_hdr *vhdr;
        vhdr = data + nh_off;
        nh_off += sizeof(struct vlan_hdr);
        if (data + nh_off > data_end)
            return rc;
        h_proto = vhdr->h_vlan_encapsulated_proto;
    }
    if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
        struct vlan_hdr *vhdr;
        vhdr = data + nh_off;
        nh_off += sizeof(struct vlan_hdr);
        if (data + nh_off > data_end)
            return rc;
        h_proto = vhdr->h_vlan_encapsulated_proto;
    }
    if (h_proto == htons(ETH_P_IP))
        index = parse_ipv4(data, nh_off, data_end);
    else if (h_proto == htons(ETH_P_IPV6))
        index = parse_ipv6(data, nh_off, data_end);
    else
        index = 0;
    value = dropcnt.lookup(&index);
    if (value) lock_xadd(value, 1);
    return rc;
}
`

func usage() {
	fmt.Printf("Usage: %v <ifdev>\n", os.Args[0])
	fmt.Printf("e.g.: %v eth0\n", os.Args[0])
	os.Exit(1)
}

func main() {
	var device string

	if len(os.Args) != 2 {
		usage()
	}

	device = os.Args[1]

	ret := "XDP_PASS"
	ctxtype := "xdp_md"

	module := bpf.NewModule(source, []string{
		"-w",
		"-DRETURNCODE=" + ret,
		"-DCTXTYPE=" + ctxtype,
	})
	defer module.Close()

	fn, err := module.Load("udpfilter", C.BPF_PROG_TYPE_XDP, 1, 65536)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Failed to load xdp prog: %v\n", err)
		os.Exit(1)
	}

	err = module.AttachXDP(device, fn)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Failed to attach xdp prog: %v\n", err)
		os.Exit(1)
	}

	defer func() {
		if err := module.RemoveXDP(device); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Failed to remove XDP from %s: %v\n", device, err)
		}
	}()

	fmt.Println("Passing packets, hit CTRL+C to stop")

	/* watch for os signal interrupts to clean up resources and exit gracefully */
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	//sig := make(chan os.Signal, 1)
	//signal.Notify(sig, os.Interrupt, os.Kill)

	dropcnt := bpf.NewTable(module.TableId("dropcnt"), module)

	go func() {
		<-sigCh
		for sig := range sigCh {

			if sig != syscall.SIGHUP {
				err := module.RemoveXDP(device)
				if err != nil {
					_, _ = fmt.Fprintf(os.Stderr, "Failed to remove XDP from %s: %v\n", device, err)
				} else {
					_, _ = fmt.Fprintf(os.Stdout, "Removed XDP from %s\n", device)
				}
				os.Exit(1)
			}

		}
	}()

	_, _ = fmt.Printf("\n{IP protocol-number}: {total dropped pkts}\n")
	for {
		for it := dropcnt.Iter(); it.Next(); {
			key := bpf.GetHostByteOrder().Uint32(it.Key())
			value := bpf.GetHostByteOrder().Uint64(it.Leaf())

			if value > 0 {
				_, _ = fmt.Printf("%v: %v pkts\n", key, value)
			}
		}
	}

}
