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
#define ACCEPTED_MSG "ACCEPTED"
#define DROPPED_MSG "DROPPED"


struct dns_hdr_t
{
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} BPF_PACKET_HEADER;

struct dns_query_flags_t
{
  uint16_t qtype;
  uint16_t qclass;
} BPF_PACKET_HEADER;

struct dns_char_t
{
    char c;
} BPF_PACKET_HEADER;

struct dns_query {
  unsigned char p[255];
};

struct data_t {
    u32 src_ip;
	u32 dst_ip;
	u16 src_port;
	u16 dst_port;
	char protocol[4];
	char msg[20];
};
struct Leaf {
  unsigned char p[4];
};

BPF_HASH(ips_list, u32, bool, 128);
BPF_HASH(dns_list, struct dns_query, struct Leaf, 128);
BPF_PERF_OUTPUT(events);

static __inline bool is_drop_ip(u32 ip, struct data_t *data)
{
   if (ips_list.lookup(&ip)){
   	__builtin_memcpy(data->msg, DROPPED_MSG, sizeof(DROPPED_MSG));
	   return true;
   }
   return false;
}

static __inline bool is_http(unsigned long p[])
{
   //find a match with an HTTP message
			//HTTP
			if ((p[0] == 'H') && (p[1] == 'T') && (p[2] == 'T') && (p[3] == 'P')) {
				return true;
			}
			//GET
			else if ((p[0] == 'G') && (p[1] == 'E') && (p[2] == 'T')) {
				return true;
			}
			//POST
			else if ((p[0] == 'P') && (p[1] == 'O') && (p[2] == 'S') && (p[3] == 'T')) {
				return true;
			}
			//PUT
			else if ((p[0] == 'P') && (p[1] == 'U') && (p[2] == 'T')) {
				return true;
			}
			//DELETE
			else if ((p[0] == 'D') && (p[1] == 'E') && (p[2] == 'L') && (p[3] == 'E') && (p[4] == 'T') && (p[5] == 'E')) {
				return true;
			}
			//HEAD
			else if ((p[0] == 'H') && (p[1] == 'E') && (p[2] == 'A') && (p[3] == 'D')) {
				return true;
			}
			return false;
}




int filter_dst(struct __sk_buff *skb) {
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
	data.src_ip = ip->src;
	data.dst_ip = ip->dst;

	u32 target_ip = ip->dst;
	
	 if (ip->nextp == IP_ICMP) {
		__builtin_memcpy(&data.protocol, "ICMP", sizeof("ICMP"));
		if (ips_list.lookup(&target_ip)) {
		__builtin_memcpy(&data.msg, DROPPED_MSG, sizeof(DROPPED_MSG));
   		goto SUBMIT_AND_SHOT;
	}
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

			if  (is_http(p)) {
				__builtin_memcpy(&data.protocol, "HTTP", sizeof("HTTP"));
			}
			else {
				__builtin_memcpy(&data.protocol, "TCP", sizeof("TCP"));
			}
			}
		
	data.src_port = tcp->src_port;
	data.dst_port = tcp->dst_port;

	if (ips_list.lookup(&target_ip)) {
		__builtin_memcpy(&data.msg, DROPPED_MSG, sizeof(DROPPED_MSG));
   	 	goto SUBMIT_AND_SHOT;
	}
	}
	else if (ip->nextp == IPPROTO_UDP){
      // Check for Port 53, DNS packet.
      struct udp_t *udp = cursor_advance(cursor, sizeof(*udp));
	  struct dns_query key = {};
      if(udp->dport == 53){
          __builtin_memcpy(&data.protocol, "DNS", sizeof("DNS"));
		if (ips_list.lookup(&target_ip)) {
		__builtin_memcpy(&data.msg, DROPPED_MSG, sizeof(DROPPED_MSG));
   		 goto SUBMIT_AND_SHOT;
	}
        struct dns_hdr_t *dns_hdr = cursor_advance(cursor, sizeof(*dns_hdr));
        // Do nothing if packet is not a request.
        if((dns_hdr->flags >>15) != 0) {
		   goto SUBMIT_AND_KEEP;
        }

        u16 i = 0;
        struct dns_char_t *c;
        for(i = 0; i<255;i++){
          c = cursor_advance(cursor, 1);
          if (c->c == 0)
            break;
          key.p[i] = c->c;
        }

        struct Leaf * lookup_leaf = dns_list.lookup(&key);

        // If DNS name is contained in our map, keep the packet
        if(lookup_leaf) {
          __builtin_memcpy(&data.msg, DROPPED_MSG, sizeof(DROPPED_MSG));
		  goto SUBMIT_AND_SHOT;
        }
		else{
			__builtin_memcpy(&data.msg, ACCEPTED_MSG, sizeof(ACCEPTED_MSG));
		  goto SUBMIT_AND_KEEP;
		}
      }
	}
	
	__builtin_memcpy(&data.msg, ACCEPTED_MSG, sizeof(ACCEPTED_MSG));
	
	SUBMIT_AND_KEEP:
	events.perf_submit(skb, &data, sizeof(data));
	return TC_ACT_OK;
	
	SUBMIT_AND_SHOT:
	events.perf_submit(skb, &data, sizeof(data));
    return TC_ACT_SHOT;

}





int filter_src(struct __sk_buff *skb) {
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
	data.src_ip = ip->src;
	data.dst_ip = ip->dst;

	u32 target_ip = ip->src;
	
	 if (ip->nextp == IP_ICMP) {
		__builtin_memcpy(&data.protocol, "ICMP", sizeof("ICMP"));
		if (ips_list.lookup(&target_ip)) {
		__builtin_memcpy(&data.msg, DROPPED_MSG, sizeof(DROPPED_MSG));
   		goto SUBMIT_AND_SHOT;
	}
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

			if  (is_http(p)) {
				__builtin_memcpy(&data.protocol, "HTTP", sizeof("HTTP"));
			}
			else {
				__builtin_memcpy(&data.protocol, "TCP", sizeof("TCP"));
			}
			}
		
	data.src_port = tcp->src_port;
	data.dst_port = tcp->dst_port;

	if (ips_list.lookup(&target_ip)) {
		__builtin_memcpy(&data.msg, DROPPED_MSG, sizeof(DROPPED_MSG));
   	 	goto SUBMIT_AND_SHOT;
	}
	}
	else if (ip->nextp == IPPROTO_UDP){
      // Check for Port 53, DNS packet.
      struct udp_t *udp = cursor_advance(cursor, sizeof(*udp));
	  struct dns_query key = {};
      if(udp->dport == 53){
          __builtin_memcpy(&data.protocol, "DNS", sizeof("DNS"));
		if (ips_list.lookup(&target_ip)) {
		__builtin_memcpy(&data.msg, DROPPED_MSG, sizeof(DROPPED_MSG));
   		 goto SUBMIT_AND_SHOT;
	}
        struct dns_hdr_t *dns_hdr = cursor_advance(cursor, sizeof(*dns_hdr));
        // Do nothing if packet is not a request.
        if((dns_hdr->flags >>15) != 0) {
		   goto SUBMIT_AND_KEEP;
        }

        u16 i = 0;
        struct dns_char_t *c;
        for(i = 0; i<255;i++){
          c = cursor_advance(cursor, 1);
          if (c->c == 0)
            break;
          key.p[i] = c->c;
        }

        struct Leaf * lookup_leaf = dns_list.lookup(&key);

        // If DNS name is contained in our map, keep the packet
        if(lookup_leaf) {
          __builtin_memcpy(&data.msg, DROPPED_MSG, sizeof(DROPPED_MSG));
		  goto SUBMIT_AND_SHOT;
        }
		else{
			__builtin_memcpy(&data.msg, ACCEPTED_MSG, sizeof(ACCEPTED_MSG));
		  goto SUBMIT_AND_KEEP;
		}
      }
	}
	
	__builtin_memcpy(&data.msg, ACCEPTED_MSG, sizeof(ACCEPTED_MSG));
	
	SUBMIT_AND_SHOT:
	events.perf_submit(skb, &data, sizeof(data));
    return TC_ACT_SHOT;

	SUBMIT_AND_KEEP:
	events.perf_submit(skb, &data, sizeof(data));
	return TC_ACT_OK;
}

