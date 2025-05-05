//go:build ignore
#include <linux/bpf.h>
#include <stddef.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <linux/pkt_cls.h>
#include <linux/ip.h> 
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>  
#include <bpf/bpf_endian.h>

// #include "common/xdp_stats_kern_user.h"
// #include "common/xdp_stats_kern.h"
#include "common/parsing_helpers.h"
// #include "utils.h"


#define MAX_PACKET_SIZE 1000
#define MAX_UDP_SIZE 1480
#define RTP_VERSION 2
#define RTP_MIN_HEADER_SIZE 12

struct ip_record {
    __be32 participant_ip;
    __be16 participant_port;
};

#define MAX_clientS 3

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
    // __uint(pinning, LIBBPF_PIN_BY_NAME);
	__type(key, __u32);
	__type(value, struct ip_record); 
	__uint(max_entries, 10);
} xdp_ip_tc_map SEC(".maps");

static __always_inline __u16 csum_fold_helper(__u64 csum)
{
	int i;
#pragma unroll
	for (i = 0; i < 4; i++) {
		if (csum >> 16)
			csum = (csum & 0xffff) + (csum >> 16);
	}
	return ~csum;
}
static __always_inline void ipv4_csum(void *data_start, int data_size,
								__u64 *csum)
{
	*csum = bpf_csum_diff(0, 0, data_start, data_size, *csum);
	*csum = csum_fold_helper(*csum);
}


/* from AirVantage/sbulb/sbulb/bpf/checksum.c */
// Update checksum following RFC 1624 (Eqn. 3):
// https://tools.ietf.org/html/rfc1624
//     HC' = ~(~HC + ~m + m')
// Where :
//   HC	 - old checksum in header
//   HC' - new checksum in header
//   m	 - old value
//   m'	 - new value

static __always_inline void update_csum(__u64 *csum, __be32 old_addr,
								  __be32 new_addr)
{
	// ~HC
	*csum = ~*csum;
	*csum = *csum & 0xffff;
	// + ~m
	__u32 tmp;
	tmp = ~old_addr;
	*csum += tmp;
	// + m
	*csum += new_addr;
	// then fold and complement result !
	*csum = csum_fold_helper(*csum);
}

/* from AirVantage/sbulb/sbulb/bpf/ipv4.c */
static __always_inline int update_udp_checksum(__u64 cs, int old_addr,
									 int new_addr)
{
	update_csum(&cs, old_addr, new_addr);
	return cs;
}

struct l2_fields {
	__u64 smac;
	__u64 dmac;
};

struct l3_fields {
	__u32 saddr;
	__u32 daddr;
};

struct l4_fields {
	__u16 source;
	__u16 dest;
};


SEC("tc")
int tc_sfu(struct __sk_buff *skb) {
    // Get packet data pointers
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    // Parse and verify packet
	struct ethhdr *eth = data;
    int eth_type;
	struct hdr_cursor nh;
	struct iphdr *iphdr;
    int ip_type;
	struct udphdr *udphdr;
    int udp_payload_len;
	struct bpf_fib_lookup fib_params = {0};
	int rc;
	struct l3_fields l3_og, l3_new;
	struct l4_fields l4_og, l4_new;

	unsigned char *rtp_header;
    __be32 orig_saddr, orig_daddr;
    __be16 orig_sport, orig_dport;
    int action = TC_ACT_OK;
    nh.pos = data;
	__u64 ip_csum = 0;
	
	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type < 0) {
		action = TC_ACT_SHOT;
		goto out;
	}
	if (eth_type != bpf_htons(ETH_P_IP)) {
		goto out;
    }
	//bpf_printk("ITS ETH PACKET");

	ip_type = parse_iphdr(&nh, data_end, &iphdr);
	if (ip_type < 0) {
		action = TC_ACT_SHOT;
		goto out;
	}
	if (ip_type != IPPROTO_UDP) {
        goto out;
    }
	//bpf_printk("ITS IP PACKET");
	
	udp_payload_len = parse_udphdr(&nh, data_end, &udphdr);
	if (udp_payload_len < 0) {
		action = TC_ACT_OK;
		goto out;
	} else if (udp_payload_len > MAX_UDP_SIZE) {
		goto out;
	}

    // Ensure UDP payload has enough space for RTP header
    if ((void *)udphdr + sizeof(*udphdr) + RTP_MIN_HEADER_SIZE > data_end)
    {
        goto out;
    }
	//bpf_printk("ITS UDP PACKET");

    // // Access the RTP header
    rtp_header = (unsigned char *)(udphdr + 1);

    // Check the RTP version (first two bits)
    if ((rtp_header[0] >> 6) != RTP_VERSION)
	{
        goto out;
	}
	bpf_printk("ITS RTP PACKET");

    // Edit packet 
	bpf_skb_load_bytes(skb, sizeof(*eth) + offsetof(struct iphdr, saddr), &l3_og, sizeof(l3_og));
	bpf_skb_load_bytes(skb, sizeof(*eth) + sizeof(*iphdr) +offsetof(struct udphdr, source), &l4_og, sizeof(l4_og));

	bpf_skb_load_bytes(skb, sizeof(*eth) + offsetof(struct iphdr, saddr), &l3_new, sizeof(l3_new));
	bpf_skb_load_bytes(skb, sizeof(*eth) + sizeof(*iphdr) + offsetof(struct udphdr, source), &l4_new, sizeof(l4_new));

	int ret = 1;
	#pragma unroll
	for(int k = 0; k < 9; k++)
	{
		int key = k;
		struct ip_record *client;
		client = (struct ip_record *)bpf_map_lookup_elem(&xdp_ip_tc_map, &key);
		
		if (client == NULL) 
			return TC_ACT_SHOT;
		if (client->participant_ip == 0 || client->participant_port == 0)
			continue;
		bpf_printk("THE OG, %d:%d, %pI4:%d", l3_og.daddr, l4_og.dest, l3_og.daddr, l4_og.dest);
		bpf_printk("The Client is %pI4:%d", client->participant_ip, client->participant_port);

		l3_new.saddr = l3_og.daddr;

		l3_new.daddr = client->participant_ip;

		l4_new.source = l4_og.dest;

		l4_new.dest = client->participant_port;

		bpf_skb_store_bytes(skb, sizeof(*eth) + offsetof(struct iphdr, saddr), &l3_new, sizeof(l3_new), BPF_F_RECOMPUTE_CSUM);
		bpf_skb_store_bytes(skb, sizeof(*eth) + sizeof(*iphdr) + offsetof(struct udphdr, source), &l4_new, sizeof(l4_new), BPF_F_RECOMPUTE_CSUM);

		__u64 l3sum = bpf_csum_diff((__u32 *)&l3_og, sizeof(l3_og),(__u32 *)&l3_new, sizeof(l3_new), 0);
		__u64 l4sum = bpf_csum_diff((__u32 *)&l4_og, sizeof(l4_og),(__u32 *)&l4_new, sizeof(l4_new), l3sum);

		int csumret = bpf_l4_csum_replace(skb, sizeof(*eth) + sizeof(*iphdr) + offsetof(struct udphdr, check), 0, l4sum, BPF_F_PSEUDO_HDR);
		csumret |= bpf_l3_csum_replace(skb, sizeof(*eth) + offsetof(struct iphdr, check), 0, l3sum, 0);
		
		bpf_printk("THE NEW, %d:%d, %pI4:%d", l3_new.daddr, l4_new.dest, l3_new.daddr, l4_new.dest);

		if (csumret)
			return TC_ACT_SHOT;
		
		ret &= bpf_clone_redirect(skb, 1, 0);
	}  
	bpf_printk("THE return value is %d", ret);
	
	return ret;

out:
    return TC_ACT_OK;

}
char _license[] SEC("license") = "GPL";


