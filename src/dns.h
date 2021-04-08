#define DNS_PORT 53

#define DNS_A_T 		1
#define DNS_NS_T 		2
#define DNS_MD_T		3
#define DNS_MF_T		4
#define DNS_CNAME_T 		5
#define DNS_SOA_T 		6
#define DNS_MB_T 		7
#define DNS_MG_T 		8
#define DNS_MR_T 		9
#define DNS_NULL_T 		10
#define DNS_WKS_T		11
#define DNS_PTR_T 		12
#define DNS_HINFO_T 		13
#define DNS_MINFO_T 		14
#define DNS_MX_T 		15
#define DNS_TXT_T 		16
#define DNS_RP_T 		17
#define DNS_AFSDB_T		18
#define DNS_X25_T 		19
#define DNS_ISDN_T 		20
#define DNS_RT_T 		21
#define DNS_NSAP_T 		22
#define DNS_NSAP_PTR_T 		23
#define DNS_SIG_T 		24
#define DNS_KEY_T 		25
#define DNS_PX_T 		26
#define DNS_GPOS_T 		27
#define DNS_AAAA_T		28
#define DNS_LOC_T 		29
#define DNS_NXT_T 		30
#define DNS_EID_T 		31
#define DNS_NIMLOC_T 		32
#define DNS_SRV_T 		33
#define DNS_ATMA_T		34
#define DNS_NAPTR_T		35
#define DNS_KX_T 		36
#define DNS_CERT_T		37
#define DNS_A6_T 		38
#define DNS_DNAME_T		39
#define DNS_SINK_T 		40
#define DNS_OPT_T 		41
#define DNS_APL_T		42
#define DNS_DS_T 		43
#define DNS_SSHFP_T 		44
#define DNS_IPSECKEY_T 		45
#define DNS_RRSIG_T 		46
#define DNS_NSEC_T 		47
#define DNS_DNSKEY_T 		48
#define DNS_DHCID_T		49
#define DNS_NSEC3_T 		50
#define DNS_NSEC3PARAM_T	51
#define DNS_TLSA_T 		52
#define DNS_SMIMEA_T		53
//#define UNASSIGNED		54
#define DNS_HIP_T 		55
#define DNS_NINFO_T 		56
#define DNS_RKEY_T 		57
#define DNS_TALINK_T 		58
#define DNS_CDS_T 		59
#define DNS_CDNSKEY_T		60
#define DNS_OPENPGPKEY_T	61
#define DNS_CSYNC_T		62
//#define UNASSIGNED		63-98
#define DNS_SPF_T 		99
#define DNS_UINFO_T 		100
#define DNS_UID_T 		101
#define DNS_GID_T 		102
#define DNS_UNSPEC_T 		103
#define DNS_NID_T 		104
#define DNS_L32_T 		105
#define DNS_L64_T		106
#define DNS_LP_T 		107
#define DNS_EUI48		108
#define DNS_EUI64		109
//#define UNASSIGNED		110-248
#define DNS_TKEY_T 		249
#define DNS_TSIG_T 		250
#define DNS_IXFR_T 		251
#define DNS_AXFR_T 		252
#define DNS_MAILB_T 		253
#define DNS_MAILA_T 		254
#define DNS_ANY_T 		255
#define DNS_URI_T 		256
#define DNS_CAA_T		257
#define DNS_AVC_T 		258
//#define UNASSIGNED 		259-32767
#define DNS_TA_T 		32768
#define DNS_DLV_T 		32769
//#define UNASSIGNED		32770-65279
//#define PRIVATE_USE		65280-65534
//#define RESERVED		65534-65535

#define DNS_CLASS_IN	0x01

#define DNS_QUERY_FLAG 	0x00
#define DNS_ANSWER_FLAG	0x01

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

typedef struct dns_query_head {
	uint16_t type;
	uint16_t class;
} dns_query_head;

typedef struct __attribute__((__packed__)) dns_RR_head {
	uint16_t pkt_label_ptr;
	uint16_t type;
	uint16_t class;
	uint32_t ttl;
	uint16_t rdata_len;
} dns_RR_head;
