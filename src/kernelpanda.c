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
#include <net/sock.h>
#include <linux/netlink.h>
#include "dns.h"

#define IPHDR_LENGTH 	20

#define MINISERV_LISTEN 7777

#define CONTAINER_QUERY 	0
#define CONTAINER_ANSWER 	1

#define CACHE_HASHTABLE_LEN 0xFFFF /* Must be 0xFFFF ( 16-bits ) for id await queue to works */

#define CACHE_ENTER_SUCCESS 1
#define CACHE_ENTER_FAIL 0

#define CACHE_TTL_DEFAULT 60 /* 10s */

#define PTR_ARI_INC(x) (x + 1)

#define DNS_OBJ_UNINITIALIZED 0
#define DNS_PKT_OK	1
#define DNS_PKT_OOM 2

#pragma message "v0.04"

typedef int ipv4_bytes;

static struct nf_hook_ops nf_ops_in; /* NF_INET_PRE_ROUTING */
static struct nf_hook_ops nf_ops_out; /* NF_INET_LOCAL_OUT */
static struct net_device* valid_dev;

struct dns_t {
	uint8_t* t_name;
	uint16_t old;
	uint32_t cached;
};

struct dns_t types[300];

struct skb_root_cache {
	struct sk_buff* first;
	uint32_t await_cnt; /* Contains number of response awaiting for a query sent with ID corresponding to this structure index in cache */
};

struct skb_root_cache cache[CACHE_HASHTABLE_LEN];

typedef struct dns_query {
	uint8_t* qname;
	uint8_t  qlen;
	uint16_t qtype;
	uint16_t qclass;
	uint16_t hash;
} dns_query;

typedef struct dns_encaps_object {
	struct sk_buff* skb;
	void* mem_limit;
	struct dnshdr* header;
	uint16_t off_label;
	uint8_t init;
	uint16_t len;
} dns_object;

#define NET_PANDA 31

struct sock* netl_sk = NULL;

static void cmd_input(struct sk_buff* skb) {
	struct nlmsghdr *nlh;
	uint32_t pid;
	struct sk_buff* skb_out;
	uint32_t msg_size;
	uint8_t* k_msg = "Output from Panda.\n";
	uint32_t res;

	printk(KERN_INFO "Entering %s\n", __FUNCTION__);

	msg_size = strlen(k_msg);
	nlh = (struct nlmsghdr *) skb->data;
	printk(KERN_INFO "Net Panda received: %s\n", (char *) nlmsg_data(nlh));
	pid = nlh->nlmsg_pid;

	if ( !(skb_out = nlmsg_new(msg_size, 0)) ) {
		printk(KERN_INFO "Error while allocating out skb.\n");
		return;
	}

	nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
	NETLINK_CB(skb_out).dst_group = 0;
	strncpy(nlmsg_data(nlh), k_msg, msg_size);

	res = nlmsg_unicast(netl_sk, skb_out, pid);

	if ( res < 0 )
		printk(KERN_INFO "Error while sending k_msg to process.\n");

	return;

}

void printMem(void* buf, uint32_t len) {
	uint8_t* _b = (uint8_t *) buf;
	while (len--)
		printk(KERN_INFO "0x%x ", *(_b++));
}

struct dns_t* retrieve_dns_t(uint16_t dns_t_num) {
	if ( dns_t_num > 258 )
		switch ( dns_t_num ) {
			case DNS_TA_T:
				return &types[259];
				break;
			case DNS_DLV_T:
				return &types[260];
				break;
			default:
				return NULL;
				break;
		}
	return &types[dns_t_num];
}

/**
 * store_types: set dns_t structure t_name pointer for each DNS valid types
 *
 * @return: void.
 */
void store_types(void) {
	types[DNS_A_T].t_name 			= "A";
	types[DNS_NS_T].t_name 			= "NS";
	types[DNS_MD_T].t_name 			= "MD";
	types[DNS_MF_T].t_name	 		= "MF";
	types[DNS_CNAME_T].t_name 		= "CNAME";
	types[DNS_SOA_T].t_name 		= "SOA";
	types[DNS_MB_T].t_name 			= "MB";
	types[DNS_MG_T].t_name 			= "MG";
	types[DNS_MR_T].t_name 			= "MR";
	types[DNS_NULL_T].t_name 		= "NULL";
	types[DNS_WKS_T].t_name 		= "WKS";
	types[DNS_PTR_T].t_name 		= "PTR";
	types[DNS_HINFO_T].t_name 		= "HINFO";
	types[DNS_MINFO_T].t_name 		= "MINFO";
	types[DNS_MX_T].t_name 			= "MX";
	types[DNS_TXT_T].t_name 		= "TXT";
	types[DNS_RP_T].t_name 			= "RP";
	types[DNS_AFSDB_T].t_name 		= "AFSDB";
	types[DNS_X25_T].t_name 		= "X25";
	types[DNS_ISDN_T].t_name 		= "ISDN";
	types[DNS_NSAP_T].t_name 		= "NSAP";
	types[DNS_NSAP_PTR_T].t_name 		= "NSAP-PTR";
	types[DNS_SIG_T].t_name 		= "SIG";
	types[DNS_KEY_T].t_name 		= "KEY";
	types[DNS_PX_T].t_name 			= "PX";
	types[DNS_GPOS_T].t_name 		= "GPOS";
	types[DNS_AAAA_T].t_name 		= "AAAA";
	types[DNS_LOC_T].t_name 		= "LOC";
	types[DNS_NXT_T].t_name 		= "NXT";
	types[DNS_EID_T].t_name 		= "EID";
	types[DNS_NIMLOC_T].t_name 		= "NIMLOCK";
	types[DNS_SRV_T].t_name 		= "SRV";
	types[DNS_ATMA_T].t_name 		= "ATMA";
	types[DNS_NAPTR_T].t_name 		= "NAPTR";
	types[DNS_KX_T].t_name 			= "KX";
	types[DNS_CERT_T].t_name 		= "CERT";
	types[DNS_A6_T].t_name 			= "A6";
	types[DNS_DNAME_T].t_name 		= "DNAME";
	types[DNS_SINK_T].t_name 		= "SINK";
	types[DNS_OPT_T].t_name 		= "OPT";
	types[DNS_APL_T].t_name 		= "APL";
	types[DNS_DS_T].t_name 			= "DS";
	types[DNS_SSHFP_T].t_name 		= "SSHFP";
	types[DNS_IPSECKEY_T].t_name 		= "IPSECKEY";
	types[DNS_RRSIG_T].t_name 		= "RRSIG";
	types[DNS_NSEC_T].t_name 		= "NSEC";
	types[DNS_DNSKEY_T].t_name 		= "DNSKEY";
	types[DNS_DHCID_T].t_name 		= "DHCID";
	types[DNS_NSEC3_T].t_name 		= "NSEC3";
	types[DNS_NSEC3PARAM_T].t_name	 	= "NSEC3PARAM";
	types[DNS_TLSA_T].t_name 		= "TLSA";
	types[DNS_SMIMEA_T].t_name 		= "SMIMEA";
	types[DNS_HIP_T].t_name 		= "HIP";
	types[DNS_NINFO_T].t_name 		= "NINFO";
	types[DNS_RKEY_T].t_name 		= "RKEY";
	types[DNS_TALINK_T].t_name 		= "TALINK";
	types[DNS_CDS_T].t_name 		= "CDS";
	types[DNS_CDNSKEY_T].t_name 		= "CDNSKEY";
	types[DNS_OPENPGPKEY_T].t_name 		= "OPENPGPKEY";
	types[DNS_CSYNC_T].t_name 		= "CSYNC";
	types[DNS_SPF_T].t_name 		= "SPF";
	types[DNS_UINFO_T].t_name 		= "UINFO";
	types[DNS_UID_T].t_name 		= "UID";
	types[DNS_GID_T].t_name 		= "GID";
	types[DNS_UNSPEC_T].t_name 		= "UNSPEC";
	types[DNS_NID_T].t_name 		= "NID";
	types[DNS_L32_T].t_name 		= "L32";
	types[DNS_L64_T].t_name 		= "L64";
	types[DNS_LP_T].t_name 			= "LP";
	types[DNS_EUI48].t_name 		= "EUI48";
	types[DNS_EUI64].t_name 		= "EUI64";
	types[DNS_TKEY_T].t_name 		= "TKEY";
	types[DNS_TSIG_T].t_name 		= "TSIG";
	types[DNS_IXFR_T].t_name 		= "IXFR";
	types[DNS_AXFR_T].t_name 		= "AXFR";
	types[DNS_MAILB_T].t_name 		= "MAILB";
	types[DNS_MAILA_T].t_name 		= "MAILA";
	types[DNS_ANY_T].t_name 		= "ANY";
	types[DNS_URI_T].t_name 		= "URI";
	types[DNS_CAA_T].t_name 		= "CAA";
	types[DNS_AVC_T].t_name 		= "AVC";
	types[/* DNS_TA_T */ 259].t_name	= "TA";
	types[/* DNS_DLV_T */ 260].t_name 	= "DLV";
}

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

	for ( u=0; u < query->qlen; u++ )
		sum += query->qname[u];

	sum += query->qtype + query->qclass;

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
	skb_cache->users.counter = 1; /**
				 	  Ensure that (likely(!atomic_dec_and_test(&skb->users))) will return 0 by passing value of 1 to atomic_dec_and_test() ( which will therefore return 1 => !1 => 0 )
					  By doing that we ensure that kfree_skb() wrapper will call __kfree_skb()
					*/

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
uint8_t unpack_dns_query(void* buf, struct dns_query* query) {
	uint8_t* qu = (uint8_t *) buf;
	struct dns_query_head* q_head;
	uint8_t u;

	//printk(KERN_INFO "[unpack_dns_query] buf: %s\n", (uint8_t *) buf);
	query->qname = qu;
	//printk(KERN_INFO "unpack_dns , domain str at 0x%lx\n", (unsigned long) query->qname);
	query->qlen = 0;
	query->hash = 0;

	while ( *qu ) {
		u = *qu;
		//*qu = '.';
		query->qlen += u + 1;
		qu += u + 1;
	}
	qu++;

	q_head = (struct dns_query_head *) qu;
	query->qtype = ntohs(q_head->type);
	query->qclass = ntohs(q_head->class);
	printk(KERN_INFO "unpack_dns q_head at 0x%lx, q_head->type: %d (%d) , class: %d (%d)\n", (unsigned long) q_head, q_head->type, ntohs(q_head->type), q_head->class, ntohs(q_head->class));

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
struct sk_buff* cache_lookup(struct sk_buff* skb) {
	struct sk_buff* skb_cache;
	struct dns_query q_lookup;
	struct timespec t;

	struct udphdr* udp;
	struct dnshdr* dns;
	struct dns_query q;

	udp = (struct udphdr *) skb_transport_header(skb);
	dns = (struct dnshdr *) (PTR_ARI_INC(udp));
	unpack_dns_query(PTR_ARI_INC(dns), &q);
	printk(KERN_INFO "[mini-cache] domain: %s (at 0x%lx), hash: 0x%x, type: %d, class: %d, domain length: %d\n", q.qname, (unsigned long) q.qname, q.hash, q.qtype, q.qclass, q.qlen);

	if ( unlikely(q.hash > CACHE_HASHTABLE_LEN) )
		return CACHE_ENTER_FAIL;

	skb_cache = cache[q.hash].first;

	while ( skb_cache ) {
		//printk(KERN_INFO "get skb_cache at 0x%lx\n", (unsigned long) skb_cache);
		//ip_hdr_print(skb_network_header(skb_cache));
		//udp_hdr_print(skb_transport_header(skb_cache));

		unpack_dns_query( skb_transport_header(skb_cache) + sizeof(struct udphdr) + sizeof(struct dnshdr), &q_lookup);
		printk(KERN_INFO "[mini-cache] compare: %s - %s, %d - %d, %d - %d\n", q.qname, q_lookup.qname, q.qtype, q_lookup.qtype, q.qclass, q_lookup.qclass);
		if ( (strcmp(q.qname, q_lookup.qname) == 0 ) && q.qtype == q_lookup.qtype && q.qclass == q_lookup.qclass ) {
			/* DNS match */
			printk(KERN_INFO "[mini-cache] cache hit for [%s] %s :)\n", retrieve_dns_t(q.qtype)->t_name, q.qname);
			getnstimeofday(&t);

			/**
			 * Cache expiration check, execute cache_invalidate() if cache entry must be no longer available.
			 */
			//printk(KERN_INFO "expire check: (expire at %lu) - %lu, diff: %ld", (unsigned long) skb_cache->tstamp, (unsigned long) t.tv_sec, (long) skb_cache->tstamp - (long) t.tv_sec);
			if ( (long) skb_cache->tstamp - (long) t.tv_sec < 0 ) {
				//printk(KERN_INFO "[cache_lookup] Cache entry no longer valid, call cache_invalidate().\n");
				cache_invalidate(skb_cache);
				goto cache_miss; /**
						     It can't be more than one match
						     per cache, so we can assume that there is
						     no more interesting stuff here and just
						     jump to cache_miss routine.
						   */
			}

			//printk(KERN_INFO "[cache_lookup] Cache hit.\n");
			return skb_cache; /* Cache hit */
		}
		skb_cache = skb_cache->next;
		printk(KERN_INFO "[mini-cache] going to next node at 0x%lx\n", (unsigned long) skb_cache);
	}

	cache_miss:
	printk(KERN_INFO "[mini-cache] cache miss for [%s] %s :)\n", retrieve_dns_t(q.qtype)->t_name, q.qname);
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
uint8_t cache_enter(struct sk_buff* skb) {
	struct sk_buff* skb_cache;
	struct timespec expire;

	struct udphdr* udp;
	struct dnshdr* dns;
	struct dns_query q;

	struct dns_t* type = NULL;

	udp = (struct udphdr *) skb_transport_header(skb);
	dns = (struct dnshdr *) (PTR_ARI_INC(udp));
	unpack_dns_query(PTR_ARI_INC(dns), &q);
	printk(KERN_INFO "[mini-cache] domain: %s (at 0x%lx), hash: 0x%x, type: %d, class: %d, domain length: %d\n", q.qname, (unsigned long) q.qname, q.hash, q.qtype, q.qclass, q.qlen);

	if ( unlikely(q.hash > CACHE_HASHTABLE_LEN) )
		return CACHE_ENTER_FAIL;

	getnstimeofday(&expire);

	/* Setup some informations inside the sk_buff for maintenance purpose */
	skb->hash = (uint32_t) q.hash;
	skb->tstamp = (ktime_t) (expire.tv_sec + CACHE_TTL_DEFAULT); /* Increment by our default seconds ttl to get expire timestamp */

	skb_cache = cache[q.hash].first;
	if ( skb_cache ) {
		//printk(KERN_INFO "hash index already used, doing dblink.\n");
		/* Hash index is already used by anyone, use doubly-linked list */
		skb->next = skb_cache;
		skb->prev = NULL;
		skb_cache->prev = skb;
	}
	else {
		//printk(KERN_INFO "first entry it hash index.\n");
		skb->prev = NULL;
		skb->next = NULL;
	}

	cache[q.hash].first = skb;

	type = retrieve_dns_t(q.qtype);
	if ( type == NULL )
		return CACHE_ENTER_FAIL;

	printk(KERN_INFO "[mini-cache] [%s] %s cached. (ref: 0x%x)\n", type->t_name, q.qname, q.hash);
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
	struct sk_buff* _skb;

	uint32_t hindex;

	for ( hindex=0; hindex < CACHE_HASHTABLE_LEN; hindex++ ) {
		skb = cache[hindex].first;

		/* Free every cached skb private copy at this given hindex */
		while ( skb ) {
			_skb = skb->next;
			skb->users.counter = 1;
			kfree_skb(skb);
			skb = _skb;
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
	return 1;
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

	sum +=  	*((uint16_t *)  (&ip->saddr))       		+
			*((uint16_t *)  PTR_ARI_INC(&ip->saddr))   	+
			*((uint16_t *)  (&ip->daddr))       		+
			*((uint16_t *)  PTR_ARI_INC(&ip->daddr))   	;

	sum += htons(ip->protocol) + udp->len;

	while ( udp_len > 1 ) {
		sum += *(u_data++);
		if ( sum > 0xFFFF )
			sum %= 0xFFFF;
		udp_len -= 2;
	}

	if ( udp_len & 1 ) {
		//printk(KERN_INFO "[udp_csum] Overflow padding.\n");
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
		skb_set_mac_header(skb, skb->tail);
	#else
		struct ethhdr* eth = (struct ethhdr *) (skb->tail);
		skb_set_mac_header(skb, (void *) eth);
	#endif

	memcpy(&eth->h_source, mac_src, ETH_ALEN);
	memcpy(&eth->h_dest, mac_dst, ETH_ALEN);
	eth->h_proto = proto;

	skb_put(skb, sizeof(struct ethhdr));

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

	//printk(KERN_INFO "[skb_make_ip] skb->network_header set at %d\n", skb->network_header);

	//printk(KERN_INFO "[skb_make_ip] Increasing skb->tail for %lu bytes\n", sizeof(struct iphdr));

	ip->version = IPVERSION;
	ip->ihl = sizeof(struct iphdr) / 4; /* 20 bytes length (4 * 5) */
	ip->tos = 0x0000; /* Do not care */
	ip->tot_len = ntohs((ip->ihl * 4) + transport_len);
	//printk(KERN_INFO "[skb_make_ip] tot_len: %d\n", ntohs(ip->tot_len));
	ip->id = 0x7777;
	ip->frag_off = 0; /* No fragment */
	ip->ttl = IPDEFTTL; /* 64 , max hop */
	ip->protocol = proto;
	ip->check = 0x0000; /* Set to 0 for ip_csum() */
	/* Use ntohs() to reverse byte order in order to get ports encoded in big-endian in packet memory */
	ip->saddr = htonl(src); /* Experimental */
	ip->daddr = htonl(dst); /* Experimental */
	ip->check = ipv4_csum(ip);

	skb_put(skb, sizeof(struct iphdr));

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

	//printk(KERN_INFO "[skb_make_udp] skb->transport_header set at %d\n", skb->transport_header);

	//printk(KERN_INFO "[skb_make_udp] Increasing skb->tail for %lu bytes, (included %d data length)\n", sizeof(struct udphdr) + len, len);

	/* Use ntohs() to reverse byte order in order to get ports encoded in big-endian in packet memory */
	udp->source = ntohs(src);
	udp->dest = ntohs(dst);
	udp->len = ntohs(sizeof(struct udphdr) + len); /* Minimum == sizeof(struct udphdr) (8) */

	if ( data != NULL )
		memcpy(PTR_ARI_INC(udp), data, len);

	udp->check = 0x0000; /* Set to 0 for checksum calculation purpose */
	udp->check = udp_csum((struct iphdr *) skb_network_header(skb), udp);

	skb_put(skb, sizeof(struct udphdr) + len);

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
	//printk(KERN_INFO "[skb_make_net_packet] 0x%lx -> 0x%lx , %d:%d\n", (unsigned long) ip_src, (unsigned long) ip_dst, udp_src, udp_dst);

	uint32_t skb_real_sz = skb_end_offset(skb);
	uint32_t needed = skb_headroom(skb) + sizeof(struct iphdr) + sizeof(struct udphdr) + udp_len;
	if ( needed > skb_real_sz ) {
		//printk(KERN_INFO "[mini-cache] skb data container default preset is insufficient @needed: %d, @available: %d, expand with pskb_expand_head()\n", needed, skb_real_sz);
		//printk(KERN_INFO "[mini-cache] skb-truesize before: %d, data size: %d\n", skb->truesize, skb_end_offset(skb));
		if ( pskb_expand_head(skb, /* We don't need to expand headroom */ 0, needed - skb_real_sz, __GFP_NOFAIL) != 0 ) {
			//printk(KERN_INFO "[mini-cache] pskb_expand_head() failed, probably ENOMEM return. Can't proceed.\n");
			return NULL;
		}
		//printk(KERN_INFO "[mini-cache] skb->truesize after: %d, data size: %d\n", skb->truesize, skb_end_offset(skb));
		//printk(KERN_INFO "[mini-cache] buffer successfully expanded, continuing...\n");
	}

	//skb->sk = NULL; /* Upper layer will set socket pointer later */

	/* Reset offsets */
	#ifdef NET_SKBUFF_DATA_USES_OFFSET
		skb->tail = skb_headroom(skb);
		//printk(KERN_INFO "[skb_make_net_packet] skb->tail reset to %d\n", skb->tail);
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
	//printk(KERN_INFO "[skb_make_net_packet] let __netif_receive_skb_core setting up the skb_iif with *dev\n");
	skb->skb_iif = skb->dev->ifindex; /* Experimental but __netif_receive_skb_core will do it for us */

	/* Clear dst reference, doing this force ip_rcv to find a valid route and fill up refdst for us */
	skb->_skb_refdst = 0; /* Experimental */

	//printk(KERN_INFO "[skb_make_net_packet] packet informations: \n");
	//ip_hdr_print(skb_network_header(skb));
	//udp_hdr_print(skb_transport_header(skb));

	return skb;
}

/**
  put_dns_label: Copy a domain name string into a buffer with dns label format.

  @dest: destination which will contain dns label
  @src: source domain string

  @return: 1 if OK, 0 if overflow
*/
int skb_encode_dns_label(struct dns_encaps_object* obj, uint8_t* src) {
	unsigned char* len_sv;
	unsigned char* dst;
	struct sk_buff* skb = obj->skb;
	uint32_t dst_prefetch_len = strlen(src) + 2; /* 2 extra bytes needed because of NULL Byte + first pushed length indicator byte */

	if ( skb_tailroom(skb) < dst_prefetch_len )
		return DNS_PKT_OOM;

	dst = skb_tail_pointer(skb);
	//printk(KERN_INFO "domain str at 0x%lx\n", (unsigned long) dst);

	while (*src) {
		len_sv = dst++;
		while ( *src != '.' && *src != 0x00 )
			*(dst++) = *(src++);

		*len_sv = (dst - len_sv) - 1;

		if ( *src == 0x00 )
			break;

		src++; /* Skip EOL symbol */
	}

	*dst = 0x00;

	skb_put(skb, dst_prefetch_len);
	return DNS_PKT_OK;
}

/**
   skb_init_dns_container: Create a dns container for a specified domain from a given sk_buff. Container expect to have records attached to it afterward.

   @skb: sk_buff of the buffer which will contains dns Container, dns container will start right after udp header
   @type: query or answer container flag

   @return: 0 (error, not enough memory), 1 success.
*/
uint8_t skb_init_dns_container(struct dns_encaps_object* obj, struct sk_buff* skb_attach, uint16_t type) {
	struct dnshdr* container = (struct dnshdr *) (skb_transport_header(skb_attach) + sizeof(struct udphdr));

	/* Avoid skb_panic() if we don't have enough space, just tell to the calling stack to discard the packet */
	if ( skb_tailroom(skb_attach) < sizeof(struct dnshdr) )
		return DNS_PKT_OOM; /* Not enough memory */

	container->id = 0;

	container->RD = 1;
	container->TC = 0;
	container->AA = 0;
	container->Opcode = 0; /* Standard query */
	container->QR = type;
	container->RCODE = 0; /* No error */
	container->CD = 0;
	container->AD = 0;
	container->Z = 0;
	container->RA = 1;

	container->qcount = 0;
	container->acount = 0; /* There is no answer attached yet */
	container->nscount = 0;
	container->arcount = 0;

	obj->skb = skb_attach;
	obj->mem_limit = skb_end_pointer(skb_attach);
	obj->header = container;
	obj->off_label = 0;
	obj->len += sizeof(struct dnshdr);

	obj->init = 1;

	skb_put(skb_attach, sizeof(struct dnshdr));

	return DNS_PKT_OK;
}

uint8_t skb_attach_dns_question(struct dns_encaps_object* obj, uint8_t* domain, uint16_t type, uint16_t class) {
	struct sk_buff* skb = obj->skb;
	struct dns_query_head* q_head;
	uint8_t* sv_off = skb_tail_pointer(skb);

	/* Sanity check on dns object */
	if ( !obj->init )
		return DNS_OBJ_UNINITIALIZED; /* Object wasn't initialized */

	obj->off_label = (uint16_t) (sv_off - (uint8_t *) obj->header);
	if ( !skb_encode_dns_label(obj, domain) )
		return DNS_PKT_OOM; /* Not enough memory */

	if ( skb_headroom(skb) < sizeof(struct dns_query_head) )
		return DNS_PKT_OOM; /* Not enough memory */

	obj->len += (skb_tail_pointer(skb) - sv_off) + sizeof(struct dns_query_head);

	q_head = (struct dns_query_head *) skb_tail_pointer(skb);
	q_head->type = htons(type);
	q_head->class = htons(class);
	skb_put(skb, sizeof(struct dns_query_head));

	obj->header->qcount++;

	printk(KERN_INFO "q_head at 0x%lx, q_head->type: %d (%d) , class: %d (%d)\n", (unsigned long) q_head, q_head->type, ntohs(q_head->type), q_head->class, ntohs(q_head->class));

	return DNS_PKT_OK;
}

uint8_t skb_attach_rr(struct dns_encaps_object* obj, uint16_t type, uint16_t class, uint32_t ttl, uint16_t rdata_len, uint8_t* rdata) {
	struct sk_buff* skb = obj->skb;
	struct dns_RR_head* rr_head;
	uint16_t needed_mem = sizeof(struct dns_RR_head) + rdata_len;

	/* Sanity check on dns object */
	if ( !obj->init )
		return DNS_OBJ_UNINITIALIZED; /* Object wasn't initialized */

	if ( skb_tailroom(skb) < needed_mem )
		return DNS_PKT_OOM; /* Not enough memory */

	rr_head = (struct dns_RR_head *) skb_tail_pointer(skb);
	printk(KERN_INFO "obj->off_label: %d\n", obj->off_label);
	rr_head->lptr = htons(obj->off_label) | 0x00C0;
	rr_head->type = htons(type);
	rr_head->class = htons(class);
	rr_head->ttl = htonl(ttl);
	rr_head->rdata_len = htons(rdata_len);

	memcpy(PTR_ARI_INC(rr_head), rdata, rdata_len);
	obj->len += needed_mem;
	printMem(rr_head, needed_mem);

	skb_put(skb, needed_mem);

	obj->header->acount++;

	return DNS_PKT_OK;
}

/*
typedef struct dns_RR_head {
	uint16_t pkt_label_ptr;
	uint16_t type;
	uint16_t class;
	uint32_t ttl;
	uint16_t rdata_len;
} dns_RR_head;

pkt_label_ptr: 	0xc0 0x0c
type:		0x00 0x01
class:		0x00 0x01
ttl:		0x00 0x03 0x00 0x00
rdata_len: 	0x00 0x3c
extra: 		0x00 0x04 0x00 0x4e
*/
void skb_dns_encaps_end(struct dns_encaps_object* obj) {
	struct udphdr* udp = (struct udphdr *) skb_transport_header(obj->skb);

	obj->header->qcount = htons(obj->header->qcount);
	obj->header->acount = htons(obj->header->acount);
	obj->header->nscount = htons(obj->header->nscount);
	obj->header->arcount = htons(obj->header->arcount);

	udp->len = htons(sizeof(struct udphdr) + obj->len);
	printk(KERN_INFO "raw_rr udp len: %d\n", ntohs(udp->len));
}

struct sk_buff* alloc_skb_dns_cache(uint8_t* rules) {
	struct sk_buff* skb;

	skb = alloc_skb(512, __GFP_NORETRY);
	if ( skb == NULL )
		goto fail;

	return skb;

fail:
	printk(KERN_INFO "Unable to alloc skb_dns_cache.\n");
	return NULL;
}

uint8_t create_raw_cache_rr(uint8_t* data) {
	struct sk_buff* skb = alloc_skb_dns_cache(data);
	struct dns_encaps_object obj;

	if ( !skb )
		return 0;

	obj.init = 0;
	skb_reserve(skb, sizeof(struct ethhdr) + sizeof(struct iphdr)); /* We will not have to push data at the start of buffer, but for good usage and great formatted skb, we do it anyway */

	if ( skb_make_udp(skb, 0, 0, NULL, 0) == NULL )
		goto fail;

	if ( skb_init_dns_container(&obj, skb, DNS_ANSWER_FLAG) != DNS_PKT_OK )
		goto fail;

	if ( skb_attach_dns_question(&obj, "txt.localduck", DNS_TXT_T, DNS_CLASS_IN) != DNS_PKT_OK )
		goto fail;

	if ( skb_attach_rr(&obj, DNS_TXT_T, DNS_CLASS_IN, CACHE_TTL_DEFAULT, strlen("\x1aLittle duck spawned here !"), "\x1aLittle duck spawned here !") != DNS_PKT_OK )
		goto fail;

	skb_dns_encaps_end(&obj);

	/* Cache skb is valid now */
	if ( !cache_enter(skb) )
		printk(KERN_INFO "Error while caching raw_cache_rr skb\n");

	return 1;

fail:
	printk(KERN_INFO "Unable to create raw cache RR.\n");
	return 0;
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
	//printk(KERN_INFO "[sk_destructor] skb_orphan called by ip_rcv spawned here :)\n");
}
#define SKB_LOOP_TRACE 	&sk_destructor

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

		if ( unlikely(ntohs(udp->source) == DNS_PORT) ) {
			struct dnshdr* dns = (struct dnshdr *) (PTR_ARI_INC(udp));
			struct sk_buff* cpy;

			/*
			 * Check for skb->destructor which must have the SKB_LOOP_TRACE reference if it comes from
			 * local dns answer.
			 */
			if ( likely(skb->destructor == SKB_LOOP_TRACE) ) {
				//printk(KERN_INFO "[nf_in_hook] seeing SKB_LOOP_PACKET :)\n");
				goto skb_continue;
			}

			/* Caching happens here */
			if ( ntohs(dns->qcount) > 1 )
				goto skb_continue; /* Non-standard query */

			//printk(KERN_INFO "Response with id: 0x%x\n", dns->id);
			/**
			   For avoiding security issue, we must check if id is valid.
			   If it doesn't match with an awaiting answer, we give up.
			 */
			if ( !await_candidate(dns) )
				goto skb_continue;

			//printk(KERN_INFO "Caching response... :)\n");
			/* Create a private copy */
			cpy = skb_copy(skb, __GFP_NOFAIL); /* Ensure that memory for copy will be allocated */
			//printk(KERN_INFO "original data at 0x%lx, cache private data at 0x%lx\n", (unsigned long) skb->head, (unsigned long) cpy->head);

			/* Cache answer, if answer is received  */
			cache_enter(cpy);

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
		if ( unlikely(ntohs(udp->dest) == DNS_PORT) ) {
			struct dnshdr* dns = (struct dnshdr *) (PTR_ARI_INC(udp));

			//printk(KERN_INFO "[MS Delivering] Received following DNS skb\n");
			//print_skb(skb);

			if ( ntohs(dns->qcount) > 1 )
				goto skb_continue; /* We don't handle DNS request with > 1 query ( almost every DNS server doesn't handle that anyway ) */

			/*if ( unlikely(q_dns.qtype != DNS_TYPE_A) )
				goto skb_continue; */

			if ( (lookup = cache_lookup(skb)) ) {
				uint16_t sv_id = dns->id;
				struct udphdr* lk_udp = (struct udphdr *) skb_transport_header(lookup);

				//printk(KERN_INFO "Cache hit.\n");
				printk(KERN_INFO "sv_id: 0x%x, lk_udp len: %d\n", sv_id, ntohs(lk_udp->len));
				if ( skb_make_net_packet(skb, ntohl(ip->daddr), ntohl(ip->saddr), ntohs(udp->dest), ntohs(udp->source), (uint8_t *) (PTR_ARI_INC(lk_udp)), ntohs(lk_udp->len) - sizeof(struct udphdr)) == NULL )
					goto skb_continue; /* Avoid kernel bug */

				//printk(KERN_INFO "[Cache hit] Sending UDP packet from 0x%lx:%d to 0x%lx:%d with data %s\n", (unsigned long) htonl(ip->saddr), ntohs(udp->source), (unsigned long) htonl(ip->daddr), ntohs(udp->dest), (char *) (udp + 1));
				/* Fix id */
				((struct dnshdr *) (skb_transport_header(skb) + sizeof(struct udphdr)))->id = sv_id;

				/*
				 * We need to ensure that if there was an owner to this buffer, we
				 * called his destructor before using it to identify our local packet.
				 */
				skb_orphan(skb);

				/*
				 * Attach this buffer to SKB_LOOP_TRACE destructor which will be trigered by skb_deliver => ip_rcv => skb_oprhan
				 * destructor will be checked by our ingress packet handler to know if packet is eligible for caching or not.
				 */
				skb->destructor = SKB_LOOP_TRACE;

				/* Send local cache packet to layer stack */
				netif_receive_skb(skb);
				//printk(KERN_INFO "[MS Delivering] netif_receive_skb returned\n");

				/* Tell to forget about this skb, we use it now */
				return NF_STOLEN;
			}
			else {
				//printk(KERN_INFO "syn_await with 0x%x\n", dns->id);
				/* Log this packet for being cached at server response and let it pass through, [in] handler will do the job */
				syn_await(dns);
				goto skb_continue;
			}
		}
	}

skb_continue:
		return NF_ACCEPT;
}

void init_memory(void) {
	memset(cache, 0x00, sizeof(cache));
	memset(types, 0x00, sizeof(types));
}

int init_module(void) {
	unsigned char* buf = "hello";

	struct netlink_kernel_cfg netl_sk_cfg = {
		.input = cmd_input,
	};

	#ifdef NET_SKBUFF_DATA_USES_OFFSET
		printk(KERN_INFO "[mini-cache] Kernel use net sk_buff offset.\n");
	#else
		printk(KERN_INFO "[mini-cache] Kernel use net sk_buff absolute addresses.\n");
	#endif

	printk(KERN_INFO "Creating Panda netlink socket...\n");

	if ( !(netl_sk = netlink_kernel_create(&init_net, NET_PANDA, &netl_sk_cfg)) ) {
		printk(KERN_INFO "Error while netlink socket creation, abort...\n");
		return -10;
	}

	printk(KERN_INFO "[mini-cache] Init cache...\n");
	init_memory();
	store_types();

	printk(KERN_INFO "[mini-cache] buf at 0x%lx\n", (unsigned long) buf);
	if ( !create_raw_cache_rr(buf) )
		printk(KERN_INFO "Unable to create raw cache RR.\n");

	printk(KERN_INFO "[mini-cache] Finding a net_device ...\n");
	valid_dev = find_valid_net_device();
	printk(KERN_INFO "[mini-cache] net_device found: 0x%lx [%s]\n", (unsigned long) valid_dev, valid_dev->name);

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
	netlink_kernel_release(netl_sk);
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
