#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#define IP_TCP 	6
#define ETH_HLEN 14
#define ICMP_TYPE 1

BPF_HASH(bad_ips, u32, bool, 128);

int tc(struct __sk_buff *skb) {
	bpf_trace_printk("got packet");
	u8 *cursor = 0;

	struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));

	if (!(ethernet->type == 0x0800)) {
			return TC_ACT_OK;
	}

	struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));

	u32 target_ip = ip->dst;
	if (bad_ips.lookup(&target_ip)) {
		bpf_trace_printk("blocked request");
		return TC_ACT_SHOT;
	}

	return TC_ACT_OK;
}
