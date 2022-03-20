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

BPF_HASH(ips_list, u32, bool, 128);

static __inline void print_ip(unsigned int ip)
{
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;   
    bpf_trace_printk("%d.%d.%d\n", bytes[3], bytes[2], bytes[0]);  
}

int tc_egress(struct __sk_buff *skb) {
	bpf_trace_printk("got packet");
	u8 *cursor = 0;

	struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
	if (!(ethernet->type == 0x0800)) {
			return TC_ACT_OK;
	}


	struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));

	u32 target_ip = ip->dst;
	if (ips_list.lookup(&target_ip)) {
		bpf_trace_printk("drop");
		return TC_ACT_SHOT;
	}

	return TC_ACT_OK;
}


int tc_ingress(struct __sk_buff *skb) {
	bpf_trace_printk("got packet");
	u8 *cursor = 0;

	struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
	if (!(ethernet->type == 0x0800)) {
			return TC_ACT_OK;
	}


	struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
 
	u32 target_ip = ip->src;
	if (ips_list.lookup(&target_ip)) {
		bpf_trace_printk("drop");
		return TC_ACT_SHOT;
	}

	return TC_ACT_OK;
}

