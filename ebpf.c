#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/sched.h>

#define IP_TCP 	6
#define ETH_HLEN 14
#define ICMP_TYPE 1
#define IP_UDP 17
#define IP_ICMP 1


struct data_t {
    u32 src_ip;
	u32 dst_ip;
	u16 src_port;
	u16 dst_port;
	char protocol[4];
	char msg[20];
};

BPF_HASH(ips_list, u32, bool, 128);
BPF_PERF_OUTPUT(events);

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
	u8 *cursor = 0;

	struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
	if (!(ethernet->type == 0x0800)) {
			return TC_ACT_OK;
	}

	u32  tcp_header_length = 0;
	u32  ip_header_length = 0;
	u32  payload_offset = 0;
	u32  payload_length = 0;

	struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
	ip_header_length = ip->hlen << 2;


	struct data_t data = {};
	if (ip->nextp == IP_ICMP) {
		__builtin_memcpy(&data.protocol, "ICMP", sizeof("ICMP"));
	}
	else if (ip->nextp == IP_TCP) {
		void *_ = cursor_advance(cursor, (ip_header_length-sizeof(*ip)));
		struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));

		tcp_header_length = tcp->offset << 2;

		payload_offset = ETH_HLEN + ip_header_length + tcp_header_length;
		payload_length = ip->tlen - ip_header_length - tcp_header_length;

		if(payload_length < 7) {
				__builtin_memcpy(&data.protocol, "TCP", sizeof("TCP"));
		}
		else {
			unsigned long p[7];
			int i = 0;
			for (i = 0; i < 7; i++) {
				p[i] = load_byte(skb, payload_offset + i);
			}

			//find a match with an HTTP message
			//HTTP
			if ((p[0] == 'H') && (p[1] == 'T') && (p[2] == 'T') && (p[3] == 'P')) {
				__builtin_memcpy(&data.protocol, "HTTP", sizeof("HTTP"));
			}
			//GET
			else if ((p[0] == 'G') && (p[1] == 'E') && (p[2] == 'T')) {
				__builtin_memcpy(&data.protocol, "HTTP", sizeof("HTTP"));
			}
			//POST
			else if ((p[0] == 'P') && (p[1] == 'O') && (p[2] == 'S') && (p[3] == 'T')) {
				__builtin_memcpy(&data.protocol, "HTTP", sizeof("HTTP"));
			}
			//PUT
			else if ((p[0] == 'P') && (p[1] == 'U') && (p[2] == 'T')) {
				__builtin_memcpy(&data.protocol, "HTTP", sizeof("HTTP"));
			}
			//DELETE
			else if ((p[0] == 'D') && (p[1] == 'E') && (p[2] == 'L') && (p[3] == 'E') && (p[4] == 'T') && (p[5] == 'E')) {
				__builtin_memcpy(&data.protocol, "HTTP", sizeof("HTTP"));
			}
			//HEAD
			else if ((p[0] == 'H') && (p[1] == 'E') && (p[2] == 'A') && (p[3] == 'D')) {
				__builtin_memcpy(&data.protocol, "HTTP", sizeof("HTTP"));
			}
			else {
				__builtin_memcpy(&data.protocol, "TCP", sizeof("TCP"));
			}
		
			}
			data.src_port = tcp->src_port;
			data.dst_port = tcp->dst_port;
	}
	
	
	data.src_ip = ip->src;
	data.dst_ip = ip->dst;

	u32 target_ip = ip->dst;
	if (ips_list.lookup(&target_ip)) {
		__builtin_memcpy(&data.msg, "DROPPED", sizeof("DROPPED"));
   		events.perf_submit(skb, &data, sizeof(data));
		return TC_ACT_SHOT;
	}
	__builtin_memcpy(&data.msg, "ACCEPTED", sizeof("ACCEPTED"));
	
	events.perf_submit(skb, &data, sizeof(data));
	return TC_ACT_OK;
}








int tc_ingress(struct __sk_buff *skb) {
	u8 *cursor = 0;

	struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
	if (!(ethernet->type == 0x0800)) {
			return TC_ACT_OK;
	}

	u32  tcp_header_length = 0;
	u32  ip_header_length = 0;
	u32  payload_offset = 0;
	u32  payload_length = 0;

	struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
	ip_header_length = ip->hlen << 2;


	struct data_t data = {};
	if (ip->nextp == IP_ICMP) {
		__builtin_memcpy(&data.protocol, "ICMP", sizeof("ICMP"));
	}
	else if (ip->nextp == IP_TCP) {
		void *_ = cursor_advance(cursor, (ip_header_length-sizeof(*ip)));
		struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));

		tcp_header_length = tcp->offset << 2;

		payload_offset = ETH_HLEN + ip_header_length + tcp_header_length;
		payload_length = ip->tlen - ip_header_length - tcp_header_length;

		if(payload_length < 7) {
				__builtin_memcpy(&data.protocol, "TCP", sizeof("TCP"));
		}
		else {
			unsigned long p[7];
			int i = 0;
			for (i = 0; i < 7; i++) {
				p[i] = load_byte(skb, payload_offset + i);
			}

			//find a match with an HTTP message
			//HTTP
			if ((p[0] == 'H') && (p[1] == 'T') && (p[2] == 'T') && (p[3] == 'P')) {
				__builtin_memcpy(&data.protocol, "HTTP", sizeof("HTTP"));
			}
			//GET
			else if ((p[0] == 'G') && (p[1] == 'E') && (p[2] == 'T')) {
				__builtin_memcpy(&data.protocol, "HTTP", sizeof("HTTP"));
			}
			//POST
			else if ((p[0] == 'P') && (p[1] == 'O') && (p[2] == 'S') && (p[3] == 'T')) {
				__builtin_memcpy(&data.protocol, "HTTP", sizeof("HTTP"));
			}
			//PUT
			else if ((p[0] == 'P') && (p[1] == 'U') && (p[2] == 'T')) {
				__builtin_memcpy(&data.protocol, "HTTP", sizeof("HTTP"));
			}
			//DELETE
			else if ((p[0] == 'D') && (p[1] == 'E') && (p[2] == 'L') && (p[3] == 'E') && (p[4] == 'T') && (p[5] == 'E')) {
				__builtin_memcpy(&data.protocol, "HTTP", sizeof("HTTP"));
			}
			//HEAD
			else if ((p[0] == 'H') && (p[1] == 'E') && (p[2] == 'A') && (p[3] == 'D')) {
				__builtin_memcpy(&data.protocol, "HTTP", sizeof("HTTP"));
			}
			else {
				__builtin_memcpy(&data.protocol, "TCP", sizeof("TCP"));
			}
		
			}
			data.src_port = tcp->src_port;
			data.dst_port = tcp->dst_port;
	}
	
	
	data.src_ip = ip->src;
	data.dst_ip = ip->dst;

	u32 target_ip = ip->src;
	if (ips_list.lookup(&target_ip)) {
		__builtin_memcpy(&data.msg, "DROPPED", sizeof("DROPPED"));
   		events.perf_submit(skb, &data, sizeof(data));
		return TC_ACT_SHOT;
	}
	__builtin_memcpy(&data.msg, "ACCEPTED", sizeof("ACCEPTED"));
	
	events.perf_submit(skb, &data, sizeof(data));
	return TC_ACT_OK;
}

