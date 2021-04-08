#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
//#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/if_ether.h>
#include <linux/string.h>
#include <linux/kallsyms.h>

#define IPHDR_LENGTH 	20

#define DEFAULT_DNS 	53
#define MINISERV_LISTEN 7777

#define DNS_TYPE_A 		0x01
#define DNS_TYPE_NS 	0x02
#define DNS_TYPE_CNAME 	0x05
#define DNS_TYPE_SOA 	0x06
#define DNS_TYPE_WKS 	0x0B
#define DNS_TYPE_PTR 	0x0C
#define DNS_TYPE_MX 	0x0F
#define DNS_TYPE_SRV 	0x21
#define DNS_TYPE_AAAA 	0x1C

#define DNS_CLASS_IN	0x01

#define CACHE_HASHTABLE_LEN 0xFFFF

#pragma message "v0.03"

static struct nf_hook_ops nf_ops_in; /* NF_INET_PRE_ROUTING */
static struct nf_hook_ops nf_ops_out; /* NF_INET_LOCAL_OUT */
static struct net_device* valid_dev;

typedef struct skb_cache skb_cache;

struct skb_cache* cache[CACHE_HASHTABLE_LEN];

struct skb_cache {
	skb_cache* next; /* Next cache entry for hashtable reference */
	struct sk_buff* dns_skb; /* sk_buff structure associated to this dns cache */
	uint32_t ttl; /* Cache time-to-live */
	uint8_t lock; /* Tell if this cache is locked or not ( for overwrite persistance ) */
};

typedef struct /*__attribute__((__packed__))*/ dnshdr {
	uint16_t id;

	/* Flags */
	uint16_t RD :1;
	uint16_t TC :1;
	uint16_t AA :1;
	uint16_t Opcode :4;
	uint16_t QR :1;

	uint16_t RCODE :4;
	uint16_t CD :1;
	uint16_t AD :1;
	uint16_t Z :1;
	uint16_t RA :1;

	uint16_t qcount;
	uint16_t acount;
	uint16_t nscount;
	uint16_t arcount;

	/* Following bytes represent DNS fields of variable size, consider it as a buffer like UDP buffer */
} dnshdr, *p_dnshdr;

typedef struct dns_query {
	uint8_t* qname;
	uint8_t  qlen;
	uint16_t qtype;
	uint16_t qclass;
} dns_query;

void print_data(void* data, uint16_t len) {
	uint8_t* buf = (uint8_t *) data;
	int i = 0;
	while ( i++ < len )
		printk(KERN_INFO "0x%x ", *(buf++));

	return;
}

static unsigned char* search_ksym = NULL;
static struct sk_buff* wait_skb = NULL; /* skb free to use */

static int (*ip_rcv)(struct sk_buff*, struct net_device*, struct packet_type*, struct net_device*);

static void* get_ksym(unsigned char* sym) {
	unsigned long pf = 0;

	int get_ksym_callback(void* data, const char* namebuf, struct module *owner, unsigned long addr) {
		if (strcmp(namebuf, search_ksym))
			return 0;
		*(unsigned long *) data = addr;
		return 1;
	}

	search_ksym = sym; /* Set new search reference */

	kallsyms_on_each_symbol(get_ksym_callback, &pf);
	return (void *) pf;
}

/*
 * Fill a dns_query structure with informations at *buf
 */
uint8_t get_dns_query(void* buf, struct dns_query* query) {
	uint8_t* qu = (uint8_t *) buf;
	uint8_t u;

	query->qname = qu;
	query->qlen = 0;

	while ( *qu ) {
		u = *qu;
		query->qlen += u + 1;
		qu += u + 1;
	}
	qu++;

	query->qtype = ntohs(*(short *)(qu));
	query->qclass = ntohs(*((short *)(qu + 1)));

	return 1;
}

uint16_t csum_dns_query(struct dns_query* query) {
	uint8_t u;
	uint32_t sum = 0;

	for ( u=0; u < query->qlen; u++ )
		sum += query->qname[u];

	sum += query->qlen + query->qtype + query->qclass;

	while ( sum > CACHE_HASHTABLE_LEN )
		sum = ( sum & CACHE_HASHTABLE_LEN ) + ( sum >> 16 );

	return (uint16_t) ~sum;
}

void print_skb(struct sk_buff* skb) {
	printk(KERN_INFO "sk_buff:\n\t\
	struct sk_buff *next: 0x%lx\n\t\
	struct sk_buff *prev: 0x%lx\n\t\
	struct sock *sk: 0x%lx\n\t\
	struct net_device *dev: 0x%lx\n\t\
	unsigned long _skb_refdst: %lu\n\t\
	void (*destructor)(struct sk_buff *skb): 0x%lx\n\t\
	unsigned int len: %u\n\t\
	unsigned int data_len: %u\n\t\
	__u16 mac_len: %d\n\t\
	__u16 hdr_len: %d\n\t\
	__u16 queue_mapping: %d\n\t\
	__wsum csum: 0x%x\n\t\
	__u32 priority: %u\n\t\
	int skb_iif: %d\n\t\
	__u32 hash: %u\n\t",
	(unsigned long) skb->next, (unsigned long) skb->prev, /*(unsigned int) skb->tstamp,*/ (unsigned long) skb->sk, (unsigned long) skb->dev,
	skb->_skb_refdst, (unsigned long) skb->destructor, skb->len, skb->data_len, skb->mac_len,
	skb->hdr_len, skb->queue_mapping, skb->csum, skb->priority, skb->skb_iif,
	skb->hash);

	printk(KERN_INFO "__be16 vlan_proto: %d\n\t\
	__u16 vlan_tci: %u\n\t\
	__u32 mark: %u\n\t\
	__be16 inner_protocol: %d\n\t\
	__u16 inner_transport_header: %u\n\t\
	__u16 inner_network_header: %u\n\t\
	__u16 inner_mac_header: %u\n\t\
	__be16 protocol: %d\n\t\
	__u16 transport_header: %u\n\t\
	__u16 network_header: %u\n\t\
	__u16 mac_header: %u\n\t\
	sk_buff_data_t tail: 0x%lx\n\t\
	sk_buff_data_t end: 0x%lx\n\t\
	unsigned char *head: 0x%lx\n\t\
	unsigned char *data: 0x%lx\n\t\
	unsigned int truesize: %u\n\t\
	atomic_t users: %d\n\n",
	skb->vlan_proto, skb->vlan_tci, skb->mark, skb->inner_protocol,
	skb->inner_transport_header, skb->inner_network_header, skb->inner_mac_header,
	skb->protocol, skb->transport_header, skb->network_header, skb->mac_header,
	(unsigned long) skb->tail, (unsigned long) skb->end, (unsigned long) skb->head, (unsigned long) skb->data, skb->truesize, skb->users.counter);
}

struct net_device* find_valid_net_device(void) {
	struct net_device *dev = NULL;
	read_lock(&dev_base_lock);

	dev = first_net_device(&init_net);
	while (dev) {
		if ( netif_running(dev) && strncmp(dev->name, "lo", IFNAMSIZ) != 0 ) /* Find a UP device , LOOPBACK excluded */
			break;
		dev = next_net_device(dev);
	}

	read_unlock(&dev_base_lock);
	return dev;
}

uint16_t ipv4_csum(struct iphdr* ip) {
	uint32_t sum = 0;
	uint16_t* word_ptr = (uint16_t *) ip;
	uint8_t len = ip->ihl * 4;

	while ( len > 0 ) {
		sum += *(word_ptr++);
		len -= 2;
	}

	while ( sum > 0xFFFF )
		sum = ( sum & 0xFFFF ) + ( sum >> 16 );

	return ( (uint16_t) (~sum) );
}

uint16_t udp_csum(struct iphdr* ip, struct udphdr* udp) {
	uint32_t sum = 0;
	uint16_t* u_data = (uint16_t *) udp, udp_len = ntohs(udp->len);

	sum +=  	*((uint16_t *)  (&ip->saddr))       +
			*((uint16_t *)  (&ip->saddr) + 1)   +
			*((uint16_t *)  (&ip->daddr))       +
			*((uint16_t *)  (&ip->daddr) + 1)   ;

	sum += htons(ip->protocol) + udp->len;

	while ( udp_len > 1 ) {
		sum += *(u_data++);
		if ( sum > 0xFFFF )
			sum %= 0xFFFF;
		udp_len -= 2;
	}

	if ( udp_len & 1 )
		sum += *((uint8_t *) u_data);

	while ( sum >> 16 )
		sum = ( sum & 0xFFFF ) + ( sum >> 16 );

	return ( (uint16_t) (~sum) );
}

/*
		Forge a simple valid standard Ethernet frame.
*/
struct sk_buff* skb_make_eth(struct sk_buff* skb, uint16_t proto, uint8_t* mac_src, uint8_t* mac_dst) {
	#ifdef NET_SKBUFF_DATA_USES_OFFSET
		struct ethhdr* eth = (struct ethhdr *) (skb->data + skb->tail);
		skb_set_network_header(skb, skb->tail);
	#else
		struct ethhdr* eth = (struct ethhdr *) (skb->tail);
		skb_set_network_header(skb, (void *) eth);
	#endif

	skb_put(skb, sizeof(struct ethhdr));

	memcpy(&eth->h_source, mac_src, ETH_ALEN);
	memcpy(&eth->h_dest, mac_dst, ETH_ALEN);
	eth->h_proto = proto;

	return skb;
}

/*
	Build a simple valid standard IP frame.
*/
struct sk_buff* skb_make_ip(struct sk_buff* skb, uint16_t proto, uint16_t transport_len, uint32_t src, uint32_t dst) {
	#ifdef NET_SKBUFF_DATA_USES_OFFSET
		struct iphdr* ip = (struct iphdr *) (skb->data + skb->tail);
		skb_set_network_header(skb, skb->tail);
	#else
		struct iphdr* ip = (struct iphdr *) (skb->tail);
		skb_set_network_header(skb, (void *) ip);
	#endif

	printk(KERN_INFO "[skb_make_ip] skb->network_header set at %d\n", skb->network_header);

	printk(KERN_INFO "[skb_make_ip] Increasing skb->tail for %lu bytes\n", sizeof(struct iphdr));
	skb_put(skb, sizeof(struct iphdr));

	ip->version = IPVERSION;
	ip->ihl = sizeof(struct iphdr) / 4; /* 20 bytes length */
	ip->tos = 0x0000; /* Do not care */
	ip->tot_len = ntohs((ip->ihl * 4) + transport_len);
	ip->id = 0x7777;
	ip->frag_off = 0; /* No fragment */
	ip->ttl = IPDEFTTL; /* 64 , max hop */
	ip->protocol = proto;
	ip->check = 0x0000; /* Set to 0 for ip_csum() */
	/* Use ntohs() to reverse byte order in order to get ports encoded in big-endian in packet memory */
	ip->saddr = htonl(src); /* Experimental */
	ip->daddr = htonl(dst); /* Experimental */
	ip->check = ipv4_csum(ip);

	/* DEBUG CHECK */
	if ( ipv4_csum(ip) != 0 )
		printk(KERN_INFO "[WARNING] ip header checksum is wrong.\n");

	return skb;
}

/*
	Build an UDP frame.
	@warning : This function must receive parameters encoded in little-endian for being converted into big-endian without losing value
*/
struct sk_buff* skb_make_udp(struct sk_buff* skb, uint16_t src, uint16_t dst, uint8_t* data, uint16_t len) {
	#ifdef NET_SKBUFF_DATA_USES_OFFSET
		struct udphdr* udp = (struct udphdr *) (skb->data + skb->tail);
		skb_set_transport_header(skb, skb->tail);
	#else
		struct udphdr* udp = (struct udphdr *) (skb->tail);
		skb_set_transport_header(skb, (void *) udp));
	#endif

	printk(KERN_INFO "[skb_make_udp] skb->transport_header set at %d\n", skb->transport_header);

	printk(KERN_INFO "[skb_make_udp] Increasing skb->tail for %lu bytes, (included %d data length)\n", sizeof(struct udphdr) + len, len);
	skb_put(skb, sizeof(struct udphdr) + len);

	/* Use ntohs() to reverse byte order in order to get ports encoded in big-endian in packet memory */
	udp->source = ntohs(src);
	udp->dest = ntohs(dst);
	udp->len = ntohs(sizeof(struct udphdr) + len); /* Minimum == sizeof(struct udphdr) (8) */
	memcpy(udp + 1, data, len);
	udp->check = 0x0000; /* Set to 0 for checksum calculation purpose */
	udp->check = udp_csum((struct iphdr *) skb_network_header(skb), udp);

	/* DEBUG CHECK */
	if ( udp_csum((struct iphdr *) skb_network_header(skb), udp) != 0 )
		printk(KERN_INFO "[WARNING] udp checksum is wrong.\n");

	return skb;
}

/*
 * 	Takes an sk_buff structure and various needed information such as ip dst/src , udp data ... then build
 * 	a fresh new packet for network layer without eth header included ( must be omitted for network layer )
 */
struct sk_buff* skb_make_net_packet(	struct sk_buff* skb,
					uint32_t ip_src, uint32_t ip_dst,
					uint16_t udp_src, uint16_t udp_dst,
					uint8_t* udp_data, uint16_t udp_len 	)
{
	/*
		Do some check to be sure that there is enough space in the skb allocated buffer to store headers + data
	*/
	printk(KERN_INFO "[skb_make_net_packet] 0x%lx -> 0x%lx , %d:%d\n", (unsigned long) htonl(ip_src), (unsigned long) htonl(ip_dst), ntohs(udp_src), ntohs(udp_dst));

	if ( sizeof(struct iphdr) + sizeof(struct udphdr) + udp_len > skb->truesize ) {
		/* We need to grow the skb memory area */
		/* Omit for now */
	}

	//skb->sk = NULL; /* Upper layer will set socket pointer later */

	/* Reset offsets */
	//skb_reset_mac_header(skb);
	//skb->mac_header = 0xFFFF; /* Experimental */
	#ifdef NET_SKBUFF_DATA_USES_OFFSET
		skb->tail = skb_headroom(skb);
		printk(KERN_INFO "[skb_make_net_packet] skb->tail reset to %d\n", skb->tail);
	#else
		skb->tail = skb->data;
	#endif

	skb_reset_mac_header(skb);
	skb_make_ip(skb, IPPROTO_UDP, sizeof(struct udphdr) + udp_len, ip_src, ip_dst);
	skb_make_udp(skb, udp_src, udp_dst, udp_data, udp_len);

	skb->len = ntohs(((struct iphdr *) skb_network_header(skb))->tot_len);
	printk(KERN_INFO "skb->len = %d, ip->tot_len = %d\n", skb->len, ntohs(((struct iphdr *) skb_network_header(skb))->tot_len));

	return skb;
}

/*
	This function will check every single packet incoming from real world and log every DNS resolving
*/
unsigned int nf_in_hook(	unsigned int hnum,
				struct sk_buff* skb,
				const struct net_device* in,
				const struct net_device* out,
				int (*okfn)(struct sk_buff*) )
{
	struct iphdr* ip = (struct iphdr *) skb_network_header(skb);
	struct dns_query q_dns;
	//int offset;

	if ( ip->protocol == IPPROTO_UDP ) {
		struct udphdr *udp = (struct udphdr *) (skb_transport_header(skb) /* + IPHDR_LENGTH */);
		printk(KERN_INFO "UDP message received (from => 0x%lx:%d)\n", (unsigned long) htonl(ip->saddr), ntohs(udp->source));
		print_skb(skb);

		//ip->saddr = htonl(0x13371337);
		//udp->source = ntohs(11337);
		//memcpy(udp + 1, "abc", 3);

		if ( (unsigned short) ntohs(udp->source) == DEFAULT_DNS ) {
			/* Kernel receive a DNS answer */
			struct dnshdr* dns = (struct dnshdr *) (udp + 1);
			if ( ntohs(dns->qcount) > 1 )
				goto skb_continue;

			get_dns_query(dns + 1, &q_dns);
			if ( q_dns.qtype == DNS_TYPE_A )
				printk(KERN_INFO "[Type: A (0x%x) - Class: IN (0x%x)] DNS query for %s (%d) (csum: 0x%x); 0x%x\n", q_dns.qtype, q_dns.qclass, q_dns.qname, q_dns.qlen, csum_dns_query(&q_dns), dns->id);
			else
				printk(KERN_INFO "Unsupported DNS query, Type: 0x%x; Class: 0x%x; %s\n", q_dns.qtype, q_dns.qclass, q_dns.qname);

			skb_continue:
			return NF_ACCEPT;
		}
	}

	return NF_ACCEPT;
}

/*
	This function will check every single outgoing packet to the real world and do some stuff if there is a DNS packet which is flagged to be hooked
	or will check for DNS cache hit.

	This function will steal the outgoing packet corresponding sk_buff structure with NF_STOLEN, then she will use the allocated
	packet buffer to use it for requeuing newly crafted packet :)
	@return NF_ACCEPT if packet flag is not NF_DROP
*/
unsigned int nf_out_hook(	unsigned int hnum,
				struct sk_buff* skb,
				const struct net_device* in,
				const struct net_device* out,
				int (*okfn)(struct sk_buff*) 	)
{
	/* Try to get some informations on packet */
	//struct ethhdr* eth_hdr = (struct ethhdr *) skb_mac_header(skb);
	struct iphdr* ip = (struct iphdr *) skb_network_header(skb);

	if ( ip->protocol == IPPROTO_UDP ) {
		struct udphdr* udp = (struct udphdr *) (skb_transport_header(skb) /* + IPHDR_LENGTH */);
		if ( ntohs(udp->dest) == DEFAULT_DNS + 1 ) {
			/*
			 * 	Main goal of this entry point will be to steal the packet then use it to build a valid
			 *	skb for mini-serv with some DNS query informations :)
			 */
			uint8_t mini_serv_msg[256];
			struct iphdr* _ip;
			struct udphdr* _udp;
			struct dnshdr* dns = (struct dnshdr *) (udp + 1);
			struct dns_query q_dns;
			printk(KERN_INFO "[MS Delivering] Received following DNS skb\n");
			print_skb(skb);

			//printk(KERN_INFO "[MS Delivering] orphan the packet\n");
			//skb_orphan(skb);

			if ( ntohs(dns->qcount) > 1 )
				return NF_ACCEPT; /* We don't handle DNS request with > 1 query ( almost every DNS server doesn't handle that anyway ) */

			get_dns_query(dns + 1, &q_dns);
			if ( q_dns.qtype == DNS_TYPE_A )
				sprintf(mini_serv_msg, "[Type: A (0x%x) - Class: IN (0x%x)] DNS query for %s (%d) (csum: 0x%x); 0x%x\n", q_dns.qtype, q_dns.qclass, q_dns.qname, q_dns.qlen, csum_dns_query(&q_dns), dns->id);
			else
				return NF_ACCEPT; /* We only take care of DNS query type A */

			/* Build frame */
			skb_make_net_packet(skb, 0x13371337,
						/* saddr is already big-endian encoded, but skb_make_packet need it in little-endian to convert it correctly */
						htonl(ip->saddr),
						13337, 7777, mini_serv_msg, strlen(mini_serv_msg));

			_ip = (struct iphdr *) skb_network_header(skb);
			_udp = (struct udphdr *) skb_transport_header(skb);

			printk(KERN_INFO "[MS Delivering] Sending UDP packet from 0x%lx:%d to 0x%lx:%d with data %s\n", (unsigned long) htonl(_ip->saddr), ntohs(_udp->source), (unsigned long) htonl(_ip->daddr), ntohs(_udp->dest), (char *) (_udp + 1));

			/* Fix some fields ; Experimental :) */
			skb->pkt_type = PACKET_HOST; /* This packet is for us */

			//printk(KERN_INFO "[MS Delivering] Sending following skb\n");
			//print_skb(skb);

			/* Send packet to upper layer (network) */
			//netif_rx_ni(skb);
			//netif_receive_skb(skb);
			ip_rcv(skb, skb->dev, NULL, skb->dev);

			/* Tell to do nothing more with the skb, we got it now */
			return NF_STOLEN;
		}
		else if ( ntohs(udp->dest) == DEFAULT_DNS ) {
			printk(KERN_INFO "Local loop , stolen.\n");
			skb->ip_summed = CHECKSUM_UNNECESSARY;
			//ip_rcv(skb, skb->dev, NULL, skb->dev);
			netif_receive_skb(skb);
			return NF_STOLEN;
		}
	}

	return NF_ACCEPT;
}

int init_module(void) {
	printk(KERN_INFO "Resolving ip_rcv() symbol...");
	ip_rcv = get_ksym("ip_rcv");
	if ( ip_rcv == NULL )
		printk(KERN_INFO "Unable to resolve udp() symbol.\n");
	else
		printk(KERN_INFO "Resolved udp at 0x%lx\n", (unsigned long) ip_rcv);

	printk(KERN_INFO "Finding a net_device ...\n");
	valid_dev = find_valid_net_device();
	printk(KERN_INFO "net_device found: 0x%lx [%s]\n", (unsigned long) valid_dev, valid_dev->name);

	nf_ops_in.hook        	=		(nf_hookfn *) nf_in_hook;
	nf_ops_in.pf          	=		PF_INET;
	nf_ops_in.hooknum     	=		NF_INET_PRE_ROUTING;
	nf_ops_in.priority    	=		NF_IP_PRI_FIRST;
	nf_register_hook(&nf_ops_in);

	nf_ops_out.hook		=		(nf_hookfn *) nf_out_hook;
	nf_ops_out.pf 		=		PF_INET;
	nf_ops_out.hooknum 	=		NF_INET_POST_ROUTING;
	nf_ops_out.priority 	=		NF_IP_PRI_FIRST;
	nf_register_hook(&nf_ops_out);

	return 0;
}

void cleanup_module() {
	nf_unregister_hook(&nf_ops_in);
	nf_unregister_hook(&nf_ops_out);
}

/*
 *  You can use strings, like this:
 */

/*
 * Get rid of taint message by declaring code as GPL.
 */
MODULE_LICENSE("GPL");

/*
 * Or with defines, like this:
 */
MODULE_AUTHOR("Me");	/* Who wrote this module? */
MODULE_DESCRIPTION("Me");	/* What does this module do */

/*
 *  This module uses /dev/testdevice.  The MODULE_SUPPORTED_DEVICE macro might
 *  be used in the future to help automatic configuration of modules, but is
 *  currently unused other than for documentation purposes.
 */
MODULE_SUPPORTED_DEVICE("SKBLoop");
