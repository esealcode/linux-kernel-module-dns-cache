#include "dns.h"

#define NET_PANDA 31

#define PLOAD_SIZE 1024

typedef uint8_t         success_status;
typedef uint8_t         kpb_success;

typedef struct dnshdr           struct_kp_cache_header;
typedef struct dns_query_head   struct_kp_cache_query;
typedef struct dns_RR_head      struct_kp_cache_rr;


struct __attribute__((__packed__)) cmd_buffer
{
        uint8_t         cmd_id;
        /* kp_buffer data */
};


struct __attribute__((__packed__)) kp_cache_opt_rr
{
        uint8_t         isptr;
        uint16_t        type;
        uint16_t        udp_payload_size;
        uint8_t         hbit_ext_rcode;
        uint8_t         EDNS0_ver;
        uint16_t        Z;
        uint16_t        data_len;
        /*                      RDATA
                                  +
           Domain if isptr is false, terminated by a null byte
        */
};

struct label
{
        struct label            *next;
        uint16_t                len;
        uint8_t                 lb[256];
};

struct kp_cache_cmd
{
        uint16_t                *tot_qu;
        uint16_t                *tot_an;
        uint16_t                *tot_autRR;
        uint16_t                *tot_addRR;
        struct kp_buff          *header;
        struct kp_buff          *query;
        struct kp_buff          *add;
        struct kp_buff          *auth;
};
