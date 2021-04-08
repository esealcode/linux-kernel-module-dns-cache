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
#include <linux/time.h>

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

#define CACHE_HASHTABLE_LEN 0xFFFF /* Must be 0xFFFF ( 16-bits ) for id await queue to works */

#define SKB_LOOP_TRACE 	&sk_destructor

#define CACHE_ENTER_SUCCESS 1
#define CACHE_ENTER_FAIL 0

#define CACHE_TTL_DEFAULT 10 /* 10s */

#pragma message "v0.04"

static struct nf_hook_ops nf_ops_in; /* NF_INET_PRE_ROUTING */
static struct nf_hook_ops nf_ops_out; /* NF_INET_LOCAL_OUT */
static struct net_device* valid_dev;

struct skb_root_cache {
	struct sk_buff* first;
	uint32_t await_cnt; /* Contains number of response awaiting for a query sent with ID corresponding to this structure index in cache */
};

struct skb_root_cache cache[CACHE_HASHTABLE_LEN];

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
	uint16_t hash;
} dns_query;



void print_data(void* data, uint16_t len) {
	uint8_t* buf = (uint8_t *) data;
	int i = 0;
	while ( i++ < len )
		printk(KERN_INFO "0x%x ", *(buf++));

	return;
}

void ip_hdr_print(void* ip_data) {
	struct iphdr* ip = (struct iphdr *) ip_data;
	printk(KERN_INFO "[ip_hdr_print] tos:%d, tot_len:%d, id:0x%x, frag_off:0x%x, ttl:%d, protocol:%d, check:0x%x, saddr:0x%x, daddr: 0x%x\n",
	ip->tos, ntohs(ip->tot_len), ntohs(ip->id), ntohs(ip->frag_off), ip->ttl, ip->protocol, ntohs(ip->check), ntohl(ip->saddr), ntohl(ip->daddr));
}

void udp_hdr_print(void* udp_data) {
	struct udphdr* udp = (struct udphdr *) udp_data;
	printk(KERN_INFO "[udp_hdr_print] source:%d, dest:%d, len:%d, check:0x%x\n",
	ntohs(udp->source), ntohs(udp->dest), ntohs(udp->len), ntohs(udp->check));
}

uint16_t do_dns_hash(struct dns_query* query) {
	uint8_t u;
	uint32_t sum = 0;

	for ( u=0; u < query->qlen; u++ ) {
		sum += query->qname[u];
		sum ^= u + sum;
	}

	sum += (query->qtype + query->qclass) | query->qlen;

	while ( sum > CACHE_HASHTABLE_LEN )
		sum = ( sum & CACHE_HASHTABLE_LEN ) + ( sum >> 16 );

	return (uint16_t) sum;
}

/**
 *  cache_invalidate: invalidate cache entry
 *
 *  @c: cache entry pointer
 *
 *  @return: nothing.
 */
void cache_invalidate(struct sk_buff* skb_cache) {
	skb_cache->users.counter = 0; /* Tell there is no more owner/user to this buffer so kfree_skb() will free the structure allocated memory */

	/* Fix links in doubly-linked list */
	if ( skb_cache->prev )
		skb_cache->prev->next = skb_cache->next;
	else
		cache[skb_cache->hash].first = NULL; /* Fix first link in cache memory if it was the only cache entry in the hashtable index */

	if ( skb_cache->next )
		skb_cache->next->prev = skb_cache->prev;

	kfree_skb(skb_cache); /* Free the cachd skb private copy */
}

/*
 * Fill a dns_query structure with informations at *buf
 */
uint8_t struct_dns_query(void* buf, struct dns_query* query) {
	uint8_t* qu = (uint8_t *) buf;
	uint8_t u;

	printk(KERN_INFO "[struct_dns_query] buf: %s\n", (uint8_t *) buf);
	query->qname = qu;
	query->qlen = 0;
	query->hash = 0;

	while ( *qu ) {
		u = *qu;
		//*qu = '.';
		query->qlen += u + 1;
		qu += u + 1;
	}
	qu++;

	query->qtype = ntohs(*(short *)(qu));
	query->qclass = ntohs(*((short *)(qu + 1)));

	query->hash = do_dns_hash(query);

	return 1;
}

/**
 *  cache_lookup: lookup cache table and invalidate cache entry if expired
 *
 *  @q: dns_query* structure corresponding to the initial query Who issued the cache
 *
 *  @return: NULL pointer if cache hit didn't happened, cache entry pointer else.
 */
struct sk_buff* cache_lookup(struct dns_query* q) {
	struct sk_buff* skb_cache;
	struct dns_query q_lookup;
	struct timespec t;

	if ( unlikely(q->hash > CACHE_HASHTABLE_LEN) )
		return NULL;

	skb_cache = cache[q->hash].first;

	while ( skb_cache ) {
		printk(KERN_INFO "get skb_cache at 0x%lx\n", (unsigned long) skb_cache);
		ip_hdr_print(skb_network_header(skb_cache));
		udp_hdr_print(skb_transport_header(skb_cache));

		struct_dns_query( skb_transport_header(skb_cache) + sizeof(struct udphdr) + sizeof(struct dnshdr), &q_lookup);
		if ( strcmp(q->qname, q_lookup.qname) == 0 ) {
			/* Hostname match */
			getnstimeofday(&t);

			/**
			 * Cache expiration check, execute cache_invalidate() if cache entry must be no longer available.
			 */
			printk(KERN_INFO "expire check: (expire at %lu) - %lu, diff: %ld", (unsigned long) skb_cache->tstamp, (unsigned long) t.tv_sec, (long) skb_cache->tstamp - (long) t.tv_sec);
			if ( (long) skb_cache->tstamp - (long) t.tv_sec < 0 ) {
				printk(KERN_INFO "[cache_lookup] Cache entry no longer valid, call cache_invalidate().\n");
				cache_invalidate(skb_cache);
				goto cache_miss; /**
						     It can't be more than one match
						     per cache, so we can assume that there is
						     no more interesting stuff here and just
						     jump to cache_miss routine.
						   */
			}

			printk(KERN_INFO "[cache_lookup] Cache hit.\n");
			return skb_cache; /* Cache hit */
		}
		skb_cache = skb_cache->next;
	}

	cache_miss:
	return NULL;
}

/**
 * cache_enter: cache a dns query entry to cache table and do some operations for maintenance purpose
 *
 * @q: pointer to dns_query struct containing useful informations about the query itself
 * @skb: pointer to sk_buff struct for the network buffer which issued the cache_enter call
 *
 * return: CACHE_ENTER_SUCCESS or CACHE_ENTER_FAIL
 */
uint8_t cache_enter(struct dns_query *q, struct sk_buff* skb) {
	struct sk_buff* skb_cache;
	struct timespec expire;

	if ( unlikely(q->hash > CACHE_HASHTABLE_LEN) )
		return CACHE_ENTER_FAIL;

	getnstimeofday(&expire);

	/* Setup some informations inside the sk_buff for maintenance purpose */
	skb->hash = (uint32_t) q->hash;
	skb->tstamp = (ktime_t) (expire.tv_sec + CACHE_TTL_DEFAULT); /* Increment by our default seconds ttl to get expire timestamp */

	skb_cache = cache[q->hash].first;
	if ( skb_cache ) {
		printk(KERN_INFO "hash index already used, doing dblink.\n");
		/* Hash index is already used by anyone, use doubly-linked list */
		skb->next = skb_cache;
		skb->prev = NULL;
		skb_cache->prev = skb;
	}
	else {
		printk(KERN_INFO "first entry it hash index.\n");
		skb->prev = NULL;
		skb->next = NULL;
		cache[q->hash].first = skb;
	}

	return CACHE_ENTER_SUCCESS;
}

/**
 *  await_candidate: check if dns answer is a valid candidate to an initial query
 *
 *  @dns: dnshdr structure of received packet
 *
 *  @return: TRUE if candidate, FALSE else.
 */
uint8_t await_candidate(struct dnshdr* dns) {
	return cache[dns->id].await_cnt > 0;
}

/**
 *  syn_await: increment awaint_cnt for a given id, giving the information that a response is awaiting
 *
 *  @dns: dnshdr structure of packet
 *
 *  @return: void.
 */
void syn_await(struct dnshdr* dns) {
	cache[dns->id].await_cnt++;
}

/**
 *  ack_await: decrement await_cnt for a given id, giving the information that the response was handled
 *
 *  @dns: dnshdr structure of received packet
 *
 *  @return: void.
 */
void ack_await(struct dnshdr* dns) {
	cache[dns->id].await_cnt--;
}

/**
 *  kfree_cache: free all private skb copy in cache.
 *
 *  @return: void.
 */
void kfree_cache(void) {
	struct sk_buff* skb;
	uint32_t hindex;
	for ( hindex=0; hindex < CACHE_HASHTABLE_LEN; hindex++ ) {
		skb = cache[hindex].first;

		/* Free every cached skb private copy at this given hindex */
		while ( skb ) {
			skb = skb->next;
			kfree_skb(skb);
		}
		cache[hindex].first = NULL;
	}
}

/**
 *  update_resolve: update a resolve ip address with another ip.
 *
 *  @dns: dnshdr structure of resolve packet
 *  @u_ip: update ip
 *
 *  @return: TRUE if success, FALSE else.
 */
uint8_t update_resolve(struct dnshdr* dns, uint32_t u_ip) {

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

	if ( udp_len & 1 ) {
		printk(KERN_INFO "[udp_csum] Overflow padding.\n");
		sum += (uint16_t) (*((uint8_t *) u_data)) << 8;
	}

	while ( sum >> 16 )
		sum = ( sum & 0xFFFF ) + ( sum >> 16 );

	return ( (uint16_t) (~sum) );
}

/**
 * skb_make_eth: make ethernet frame
 *
 * @skb: sk_buff* buffer structure to append to
 * @proto: upper layer protocol id
 * @mac_src: char[ETH_ALEN] buffer corresponding to source mac address
 * @mac_dst: char[ETH_ALEN] buffer corresponding to destination mac address
 *
 * @return: @skb
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

/**
 * skb_make_ip: make ip frame
 *
 * @skb: sk_buff* buffer structure to append to
 * @proto: upper layer protocol id
 * @transport_len: upper layer ( transport ) header + data length
 * @src: source ip address
 * @dst: destination ip address
 *
 * @return: @skb
 */
struct sk_buff* skb_make_ip(struct sk_buff* skb, uint16_t proto, uint16_t transport_len, uint32_t src, uint32_t dst) {
	struct iphdr* ip;
	#ifdef NET_SKBUFF_DATA_USES_OFFSET
		skb_set_network_header(skb, skb->tail - skb_headroom(skb));
	#else
		skb_set_network_header(skb, skb->tail);
	#endif

	ip = (struct iphdr *) skb_network_header(skb);

	printk(KERN_INFO "[skb_make_ip] skb->network_header set at %d\n", skb->network_header);

	printk(KERN_INFO "[skb_make_ip] Increasing skb->tail for %lu bytes\n", sizeof(struct iphdr));
	skb_put(skb, sizeof(struct iphdr));

	ip->version = IPVERSION;
	ip->ihl = sizeof(struct iphdr) / 4; /* 20 bytes length (4 * 5) */
	ip->tos = 0x0000; /* Do not care */
	ip->tot_len = ntohs((ip->ihl * 4) + transport_len);
	printk(KERN_INFO "[skb_make_ip] tot_len: %d\n", ntohs(ip->tot_len));
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

/**
 * skb_make_udp: make udp frame
 *
 * @skb: sk_buff* buffer structure to append to
 * @src: udp source port
 * @dst: udp destination port
 * @data: udp data
 * @len: udp data length
 *
 * @return: @skb
 */
struct sk_buff* skb_make_udp(struct sk_buff* skb, uint16_t src, uint16_t dst, uint8_t* data, uint16_t len) {
	struct udphdr* udp;

	#ifdef NET_SKBUFF_DATA_USES_OFFSET
		skb_set_transport_header(skb, skb->tail - skb_headroom(skb));
	#else
		skb_set_transport_header(skb, skb->tail);
	#endif

	udp = (struct udphdr *) skb_transport_header(skb);

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

/**
 * skb_make_net_packet: build a packet from network layer to transport layer from a sk_buff* structure.
 *
 * @skb: sk_buff* structure to build with
 * @ip_src: source ip address
 * @ip_dst: destination ip address
 * @udp_src: udp source port
 * @udp_dst: udp destination port
 * @udp_data: udp data pointer
 * @udp_len: udp data length
 *
 * @return: @skb
 */
struct sk_buff* skb_make_net_packet(	struct sk_buff* skb,
					uint32_t ip_src, uint32_t ip_dst,
					uint16_t udp_src, uint16_t udp_dst,
					uint8_t* udp_data, uint16_t udp_len 	)
{
	/*
		Do some check to be sure that there is enough space in the skb allocated buffer to store headers + data
	*/
	printk(KERN_INFO "[skb_make_net_packet] 0x%lx -> 0x%lx , %d:%d\n", (unsigned long) ip_src, (unsigned long) ip_dst, udp_src, udp_dst);

	if ( sizeof(struct iphdr) + sizeof(struct udphdr) + udp_len > skb->truesize ) {
		/* We need to grow the skb memory area */
		/* Omit for now */
	}

	//skb->sk = NULL; /* Upper layer will set socket pointer later */

	/* Reset offsets */
	#ifdef NET_SKBUFF_DATA_USES_OFFSET
		skb->tail = skb_headroom(skb);
		printk(KERN_INFO "[skb_make_net_packet] skb->tail reset to %d\n", skb->tail);
	#else
		skb->tail = skb->data;
	#endif

	skb_reset_mac_header(skb);
	skb_make_udp(
			skb_make_ip(	skb,
					IPPROTO_UDP,
					sizeof(struct udphdr) + udp_len,
					ip_src,
					ip_dst),
			udp_src,
			udp_dst,
			udp_data,
			udp_len);

	skb->len = ntohs(((struct iphdr *) skb_network_header(skb))->tot_len);

	/* We invalidated data, telling it to stack for keeping the packet handled correctly */
	skb_clear_hash(skb);
	skb->csum = 0;
	skb->ip_summed = CHECKSUM_UNNECESSARY;

	/* Fix up some fields */
	printk(KERN_INFO "[skb_make_net_packet] let __netif_receive_skb_core setting up the skb_iif with *dev\n");
	skb->skb_iif = skb->dev->ifindex; /* Experimental but __netif_receive_skb_core will do it for us */

	/* Clear dst reference, doing this force ip_rcv to find a valid route and fill up refdst for us */
	skb->_skb_refdst = 0; /* Experimental */

	printk(KERN_INFO "[skb_make_net_packet] packet informations: \n");
	ip_hdr_print(skb_network_header(skb));
	udp_hdr_print(skb_transport_header(skb));

	return skb;
}

/**
 * sk_destructor: SKB_LOOP_TRACE function.
 *
 * @skb: sk_buff* structure for prototype purpose
 *
 * @return: void
 *
 * @comments: sk_destructor reference will be used as id for
 */
void sk_destructor(struct sk_buff* skb) {
	printk(KERN_INFO "[sk_destructor] skb_orphan called by ip_rcv spawned here :)\n");
}

/**
 * nf_in_cache: trace ingress dns answer packet and cache them
 *
 * @return: always NF_ACCEPT
 */
unsigned int nf_in_cache(	unsigned int hnum,
				struct sk_buff* skb,
				const struct net_device* in,
				const struct net_device* out,
				int (*okfn)(struct sk_buff*) )
{
	struct iphdr* ip = (struct iphdr *) skb_network_header(skb);
	//int offset;

	if ( ip->protocol == IPPROTO_UDP ) {
		struct udphdr *udp = (struct udphdr *) (skb_transport_header(skb) /* + IPHDR_LENGTH */);

		if ( unlikely(ntohs(udp->source) == DEFAULT_DNS) ) {
			struct dnshdr* dns = (struct dnshdr *) (udp + 1);
			struct dns_query q_dns;
			struct sk_buff* cpy;

			/*
			 * Check for skb->destructor which must have the SKB_LOOP_TRACE reference if it comes from
			 * local dns answer.
			 */
			if ( likely(skb->destructor == SKB_LOOP_TRACE) ) {
				printk(KERN_INFO "[nf_in_hook] seeing SKB_LOOP_PACKET :)\n");
				goto skb_continue;
			}

			/* Caching happens here */
			if ( ntohs(dns->qcount) > 1 )
				goto skb_continue; /* Non-standard query */

			struct_dns_query(dns + 1, &q_dns);
			if ( unlikely(q_dns.qtype != DNS_TYPE_A) )
				goto skb_continue; /* Only take care of type A cache resolution */

			printk(KERN_INFO "Response with id: 0x%x\n", dns->id);
			/**
			   For avoiding security issue, we must check if id is valid.
			   If it doesn't match with an awaiting answer, we give up.
			 */
			if ( !await_candidate(dns) )
				goto skb_continue;

			printk(KERN_INFO "Caching response... :)\n");
			/* Create a private copy */
			cpy = skb_copy(skb, __GFP_NOFAIL); /* Ensure that memory for copy will be allocated */
			printk(KERN_INFO "original data at 0x%lx, cache private data at 0x%lx\n", (unsigned long) skb->head, (unsigned long) cpy->head);

			/* Cache answer, if answer is received  */
			cache_enter(&q_dns, cpy);

			ack_await(dns); /* ACK the answer in the await queue */

			/* Continue on packet routing in the stack, it probably will be destroyed at the end , but anyway we got a private copy */
		}
	}

	skb_continue:
	return NF_ACCEPT;
}

/**
 * nf_out_loopback: deliver a local dns answer when cache hit happens
 *
 * @return:
 *	    - NF_STOLEN : when cache hit happens, avoiding to really querying remote dns server
 *	    - NF_ACCEPT : when packet is irrelevant
 */
unsigned int nf_out_loopback(	unsigned int hnum,
				struct sk_buff* skb,
				const struct net_device* in,
				const struct net_device* out,
				int (*okfn)(struct sk_buff*) 	)
{
	/* Try to get some informations on packet */
	//struct ethhdr* eth_hdr = (struct ethhdr *) skb_mac_header(skb);
	struct sk_buff* lookup = NULL;
	struct iphdr* ip = (struct iphdr *) skb_network_header(skb);

	if ( ip->protocol == IPPROTO_UDP ) {
		struct udphdr* udp = (struct udphdr *) (skb_transport_header(skb) /* + IPHDR_LENGTH */);
		if ( unlikely(ntohs(udp->dest) == DEFAULT_DNS) ) {
			/*
			 * 	Main goal of this entry point will be to steal the packet then use it to build a valid
			 *	skb for mini-serv with some DNS query informations :)
			 */
			uint8_t mini_serv_msg[256];
			struct dnshdr* dns = (struct dnshdr *) (udp + 1);
			struct dns_query q_dns;
			struct iphdr* _ip;
			struct udphdr* _udp;

			printk(KERN_INFO "[MS Delivering] Received following DNS skb\n");
			print_skb(skb);

			if ( ntohs(dns->qcount) > 1 )
				goto skb_continue; /* We don't handle DNS request with > 1 query ( almost every DNS server doesn't handle that anyway ) */

			struct_dns_query(dns + 1, &q_dns);
			if ( likely(q_dns.qtype == DNS_TYPE_A) )
				sprintf(mini_serv_msg, "id:0x%x := IN::A (%d)%s (csum: 0x%x)\n", dns->id, q_dns.qlen, q_dns.qname, q_dns.hash);
			else
				goto skb_continue; /* We only handle type A query */


			goto cache_verify; /* Avoid hijack part for compiler */
			/**
			 *  PACKET HIJACKING PART
			 */
			/* Build packet with fake fields */
			hijack:
			skb_make_net_packet(skb, 0x0A0B0C0D, htonl(ip->saddr), 1337, 7777, mini_serv_msg, strlen(mini_serv_msg));

			_ip = (struct iphdr *) skb_network_header(skb);
			_udp = (struct udphdr *) skb_transport_header(skb);

			printk(KERN_INFO "[MS Delivering] Sending UDP packet from 0x%lx:%d to 0x%lx:%d with data %s\n", (unsigned long) htonl(_ip->saddr), ntohs(_udp->source), (unsigned long) htonl(_ip->daddr), ntohs(_udp->dest), (char *) (_udp + 1));

			/* Fix some fields ; Experimental :) */
			//skb->pkt_type = PACKET_HOST; /* This packet is for us */

			printk(KERN_INFO "[MS Delivering] Sending following skb\n");
			print_skb(skb);

			/*
			 * We need to ensure that if there was an owner to this buffer, we
			 * called his destructor before using it to identify our local packet.
			 */
			skb_orphan(skb);

			/*
			 * Attach this buffer to SKB_LOOP_TRACE destructor which will be trigered by skb_deliver => ip_rcv => skb_oprhan
			 * destructor will be checked by our ingress packet handler to know if he need to check it or not.
			 */
			skb->destructor = SKB_LOOP_TRACE;

			/* Send packet to layer stack */
			netif_receive_skb(skb);
			printk(KERN_INFO "[MS Delivering] netif_receive_skb returned\n");

			/* Tell to forget about this skb, we use it now */
			return NF_STOLEN;

			cache_verify:
			if ( (lookup = cache_lookup(&q_dns)) ) {
				uint16_t sv_id = dns->id;
				struct udphdr* lk_udp = (struct udphdr *) skb_transport_header(lookup);

				/* Cache hit, trigger local loop */
				printk(KERN_INFO "Cache hit.\n");
				skb_make_net_packet(skb, ntohl(ip->daddr), ntohl(ip->saddr), ntohs(udp->dest), ntohs(udp->source), (uint8_t *) (lk_udp + 1), ntohs(lk_udp->len) - sizeof(struct udphdr));

				printk(KERN_INFO "[Cache hit] Sending UDP packet from 0x%lx:%d to 0x%lx:%d with data %s\n", (unsigned long) htonl(ip->saddr), ntohs(udp->source), (unsigned long) htonl(ip->daddr), ntohs(udp->dest), (char *) (udp + 1));
				/* Fix id */
				((struct dnshdr *) (((struct udphdr *) skb_transport_header(skb)) + 1))->id = sv_id;

				/*
				 * We need to ensure that if there was an owner to this buffer, we
				 * called his destructor before using it to identify our local packet.
				 */
				skb_orphan(skb);

				/*
				 * Attach this buffer to SKB_LOOP_TRACE destructor which will be trigered by skb_deliver => ip_rcv => skb_oprhan
				 * destructor will be checked by our ingress packet handler to know if he need to check it or not.
				 */
				skb->destructor = SKB_LOOP_TRACE;

				/* Send local cache packet to layer stack */
				netif_receive_skb(skb);
				printk(KERN_INFO "[MS Delivering] netif_receive_skb returned\n");

				/* Tell to forget about this skb, we use it now */
				return NF_STOLEN;
			}
			else {
				printk(KERN_INFO "syn_await with 0x%x\n", dns->id);
				/* Log this packet for being cached at server response and let it pass through, [in] handler will do the job */
				syn_await(dns);
				goto skb_continue;
			}
		}
	}

	skb_continue:
		return NF_ACCEPT;
}

int init_module(void) {
	#ifdef NET_SKBUFF_DATA_USES_OFFSET
		printk(KERN_INFO "Kernel use net sk_buff offset.\n");
	#else
		printk(KERN_INFO "Kernel use net sk_buff absolute addresses.\n");
	#endif

	printk(KERN_INFO "Init cache...\n");
	memset(cache, 0x00, sizeof(cache));

	printk(KERN_INFO "Finding a net_device ...\n");
	valid_dev = find_valid_net_device();
	printk(KERN_INFO "net_device found: 0x%lx [%s]\n", (unsigned long) valid_dev, valid_dev->name);

	nf_ops_in.hook        	=		(nf_hookfn *) nf_in_cache;
	nf_ops_in.pf          	=		PF_INET;
	nf_ops_in.hooknum     	=		NF_INET_PRE_ROUTING;
	nf_ops_in.priority    	=		NF_IP_PRI_FIRST;
	nf_register_hook(&nf_ops_in);

	nf_ops_out.hook		=		(nf_hookfn *) nf_out_loopback;
	nf_ops_out.pf 		=		PF_INET;
	nf_ops_out.hooknum 	=		NF_INET_POST_ROUTING;
	nf_ops_out.priority 	=		NF_IP_PRI_FIRST;
	nf_register_hook(&nf_ops_out);

	return 0;
}

void cleanup_module() {
	nf_unregister_hook(&nf_ops_in);
	nf_unregister_hook(&nf_ops_out);
	kfree_cache();
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
