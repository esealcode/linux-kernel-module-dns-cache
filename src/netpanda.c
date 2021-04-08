#include <sys/socket.h>
#include <linux/netlink.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include "termcodes.h"

#define KPB_FAIL        0
#define KPB_SUCCESS     1

typedef success_status  uint8_t
typedef kpb_success     uint8_t

#define NET_PANDA 31

#define PLOAD_SIZE 1024

typedef struct dnshdr           struct_kp_cache_header;
typedef struct dns_query_head   struct_kp_cache_query;
typedef struct dns_RR_head      struct_kp_cache_rr;

/* Simple implementation of a buffer easy to manipulate */
struct kp_buff {
        struct kp_buff  *prev;
        struct kp_buff  *next;
        uint8_t         *head;
        uint8_t         *data;
        uint8_t         *tail;
        uint8_t         *end;
        uint8_t         *cur;
        uint32_t        len;
};

struct __attribute__((__packed__)) cmd_buffer {
        uint8_t         cmd_id;
        /* kp_buffer data */
};


struct __attribute__((__packed__)) kp_cache_opt_rr {
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

struct label {
        struct label            *next;
        uint16_t                len;
        uint8_t                 lb[256];
};

struct kp_cache_cmd {
        uint16_t                *tot_qu;
        uint16_t                *tot_an;
        uint16_t                *tot_autRR;
        uint16_t                *tot_addRR;
        struct kp_buff          *header;
        struct kp_buff          *query;
        struct kp_buff          *add;
        struct kp_buff          *auth;
};

unsigned long pad_pw64(unsigned long x) {
        /* Only for 64 bits */
        unsigned char s = 1;

        while ( s < 64 ) {
                x |= x >> s;
                s <<= 1;
        }

        return ++x;
}

unsigned int pad_pw32(unsigned int x) {
        /* Only for 32 bits */
        /* Only for 64 bits */
        unsigned char s = 1;

        while ( s < 32 ) {
                x |= x >> s;
                s <<= 1;
        }

        return ++x;
}

/* kp_buff methods */
struct kp_buff* kpb_alloc(uint32_t size) {
        struct kp_buff *kpb = (struct kp_buff *) malloc(sizeof(struct kp_buff));
        if ( kpb == NULL )
                return NULL;

        kpb->head = (uint8_t *) malloc(size);
        if ( kpb->head == NULL ) {
                free(kpb);
                return NULL;
        }

        kpb->tail       = kpb->head;
        kpb->data       = kpb->head;
        kpb->cur        = kpb->data;
        kpb->end        = kpb->head + size;
        kpb->len        = 0;

        return kpb;
}

uint8_t* kpb_head(struct kp_buff* kpb) {
        return kpb->head;
}

uint8_t* kpb_data(struct kp_buff* kpb) {
        return kpb->data;
}

uint8_t* kpb_tail(struct kp_buff* kpb) {
        return kpb->tail;
}

uint8_t* kpb_end(struct kp_buff* kpb) {
        return kpb->end;
}

uint8_t* kpb_cur(struct kp_buff* kpb) {
        return kpb->cur;
}

uint32_t kpb_len(struct kp_buff* kpb) {
        return kpb->len;
}

uint32_t kpb_real_size(struct kp_buff* kpb) {
        return (uint32_t) (kpb_end(kpb) - kpb_head(kpb));
}

uint32_t kpb_tailroom(struct kp_buff* kpb) {
        return (uint32_t) (kpb_end(kpb) - kpb_tail(kpb));
}

uint32_t kpb_headroom(struct kp_buff* kpb) {
        return (uint32_t) (kpb_data(kpb) - kpb_head(kpb));
}

uint32_t kpb_szchunk_left(struct kp_buff* kpb) {
        return (uint32_t) (kpb_tail(kpb) - kpb_cur(kpb));
}

void kpb_set_head(struct kp_buff* kpb, uint8_t* set) {
        kpb->head = set;
}

void kpb_set_data(struct kp_buff* kpb, uint8_t* set) {
        kpb->data = set;
}

void kpb_set_tail(struct kp_buff* kpb, uint8_t* set) {
        kpb->tail = set;
}

void kpb_set_end(struct kp_buff* kpb, uint8_t* set) {
        kpb->end = set;
}

void kpb_inc_cur(struct kp_buff* kpb, uint32_t i) {
        kpb->cur += i;
}

void kpb_rst_cur(struct kp_buff* kpb) {
        kpb->cur = kpb_data(kpb);
}

void kpb_set_len(struct kp_buff* kpb, uint32_t len) {
        kpb->len = len;
}

kpb_success kpb_put(struct kp_buff* kpb, uint32_t u) {
        kpb_set_tail(kpb, kpb_tail(kpb) + u);
        kpb_set_len(kpb, kpb_len(kpb) + u);
        if ( kpb_end(kpb) < kpb_tail(kpb) )
                return KPB_FAIL;
        return KPB_SUCCESS;
}

kpb_success kpb_shrink(struct kp_buff* kpb, uint32_t u) {
        kpb_set_tail(kpb, kpb_tail(kpb) - u);
        kpb_set_len(kpb, kpb_len(kpb) - u);
        if ( kpb_head(kpb) > kpb_tail(kpb) )
                return KPB_FAIL;
        return KPB_SUCCESS;
}

void kpb_reset(struct kp_buff* kpb) {
        kpb_set_data(kpb, kpb_head(kpb));
        kpb_set_tail(kpb, kpb_head(kpb));
        kpb_set_len(kpb, 0);
}

kpb_success kpb_expand(struct kp_buff* kpb, uint32_t ex) {
        uint32_t new_sz = (kpb_end(kpb) - kpb_head(kpb)) + ex;
        uint32_t data_off = kpb_data(kpb) - kpb_head(kpb);

        uint8_t* nzone = (uint8_t *) realloc(kpb_head(kpb), new_sz);
        if ( nzone == NULL )
                return KPB_FAIL;

        kpb_set_head(kpb, nzone);
        kpb_set_data(kpb, nzone + data_off);
        kpb_set_tail(kpb, nzone + kpb_len(kpb));
        kpb_set_end(kpb, kpb_head(kpb) + new_sz);

        return KPB_SUCCESS;
}

kpb_success kpb_bind(struct kp_buff* kdst, struct kp_buff* ksrc) {
        int o = kpb_len(ksrc) - kpb_tailroom(kdst);
        if ( o > 0 ) {
                /* Reallocation needed, pad_pw32 is used to pad to next power of 2 to avoid future extra realloc(), if padding grows too large, realloc() will fail anyway */
                if ( kpb_expand(kdst, pad_pw32(o)) == KPB_FAIL )
                        return KPB_FAIL;
        }

        memcpy(kpb_tail(kdst), kpb_data(ksrc), kpb_len(ksrc));
        return KPB_SUCCESS;
}

void kpb_zero_memory(struct kp_buff* kpb) {
        memset(kpb_head(kpb), 0x00, kpb_real_size(kpb));
}

void kpb_free(struct kp_buff* kpb) {
        free(kpb_head(kpb));
        free(kpb);
}

success_status kp_set_cache_header(struct kp_cache_cmd* k) {
        struct kp_buff* kpb = (struct kp_buff *) kpb_alloc(sizeof(struct_kp_cache_header));
        struct_kp_cache_header* h;
        if ( kpb == NULL )
                return 0;
        /* Header just need to be set to 0 */
        kpb_zero_memory(kpb);

        k->header = kpb;

        h = (struct_kp_cache_header *) kpb_data(kpb);

        /* Set interface ref */
        k->tot_qu = &h->tot_qu;
        k->tot_an = &h->tot_an;
        k->tot_autRR = &h->tot_autRR;
        k->tot_addRR = &h->tot_addRR;

        return 1;
}

success_status kp_set_cache_qu( struct kp_cache_cmd* k,
                                uint8_t* dom,
                                uint16_t type,
                                uint16_t class) {
        uint16_t label_len              = strlen(dom) + 2;
        uint16_t prefetch_length        = sizeof(struct_kp_cache_query) + label_len;
        struct kp_buff* kpb             = NULL;
        struct_kp_cache_query* kpq      = NULL;

        /* Default behavior, only one query accepted */
        if ( k->query )
                kpb_free(k->query);

        kpb = (struct kp_buff *) kpb_alloc(prefetch_length);
        if ( kpb == NULL )
                return 0;

        kpq = (struct_kp_cache_query *) kpb_data(kpb);

        kpq->type       = htons(type);
        kpq->class      = htons(class);

        k->query        = kpb; /* Set the reference */
        return 1;
}

success_status kp_append_cache_stdrr(   struct kp_cache_cmd* k,
                                        uint8_t* name,
                                        uint16_t type,
                                        uint16_t class,
                                        uint32_t ttl,
                                        uint16_t rdata_len,
                                        uint8_t* rdata) {

}

uint8_t* read_dns_label(void* _label, uint8_t* dst, int length) {
        uint8_t* label = _label;
        uint8_t nbytes = 0;

        while ( *label ) {
                nbytes = *(label++);

                length -= nbytes + 1;
                if ( length < 0 )
                        return NULL;

                while ( nbytes-- )
                        *(dst++) = *(label++);

                *(dst++) = '.';
        }

        *dst = 0x00;
        return ++label;
}

uint8_t* write_dns_label(void* _src, uint8_t* dst, int length) {
        uint8_t* src = _src;
        uint8_t* sv;
        uint16_t prefetch_length = strlen(src) + 2; /* str length + 1 extra label length byte + null byte */

        if ( prefetch_length > length )
                return NULL;

        while ( *src ) {
                sv = dst++;
                while ( *src != '.' && *src != 0x00 )
                        *(dst++) = *(src++);
                *sv = dst - sv - 1;
                src++;
        }

        if ( *sv > 0 )
            *dst = 0x00;

        return src;
}

/*
        KernelPanda command header description:
         0  1  2  3  4  5  6  7  8
        +--+--+--+--+--+--+--+--+
        |          ID           |
        +--+--+--+--+--+--+--+--+
        |        Buffer         |
        +--+--+--+--+--+--+--+--+

        KernelPanda DNS Query cache header buffer description:

          0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |      Domain length    |                      type                     |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                     class                     |                    tot_qu                     |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                    tot_an                     |                   tot_autRR                   |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                   tot_addRR                   |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                                          Domain buffer                                        |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

       KernelPanda RR buffer description:
          0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |          isptr        |                      type                     |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                     class                     |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                                              TTL                                              |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                  rdata length                 |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                                             RDATA                                             |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                                     *Optional* domain name                                    |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

       KernelPanda additionnal/authority RR buffer description:
          0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |          isptr        |                      type                     |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |               udp_payload_size                |      hbit_ext_rcode   |        EDNS0_ver      |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                       Z                       |                    data_len                   |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                                             RDATA                                             |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                                     *Optional* domain name                                    |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

*/

int main (void) {
        struct sockaddr_nl src_addr, dest_addr;
        struct nlmsghdr *nlh = NULL;
        struct iovec iov;
        uint32_t sock_fd;
        struct msghdr u_msg;

        sock_fd = socket(PF_NETLINK, SOCK_RAW, NET_PANDA);
        if ( sock_fd < 0 )
                error("Error while creating socket.\n");

        memset(&src_addr, 0x00, sizeof(src_addr));
        src_addr.nl_family = AF_NETLINK;
        src_addr.nl_pid = getpid(); /* Self process id */

        bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr));

        memset(&dest_addr, 0x00, sizeof(dest_addr));
        dest_addr.nl_family = AF_NETLINK;
        dest_addr.nl_pid = 0; /* Destination Kernel */
        dest_addr.nl_groups = 0;

        nlh = (struct nlmsghdr *) calloc(1, NLMSG_SPACE(PLOAD_SIZE));
        if ( !nlh )
                error("Error while calloc() for nlh.\n");

        nlh->nlmsg_len = NLMSG_SPACE(PLOAD_SIZE);
        nlh->nlmsg_pid = getpid();
        nlh->nlmsg_flags = 0;

        strcpy(NLMSG_DATA(nlh), "Hello Panda ! *\\^.^/*\n");

        iov.iov_base = (void *) nlh;
        iov.iov_len = nlh->nlmsg_len;
        u_msg.msg_name = (void *) &dest_addr;
        u_msg.msg_namelen = sizeof(dest_addr);
        u_msg.msg_iov = &iov;
        u_msg.msg_iovlen = 1;

        printf("Sending command to Panda module...\n");
        sendmsg(sock_fd, &u_msg, 0);
        printf("Waiting now...\n");

        recvmsg(sock_fd, &u_msg, 0);
        printf("Panda: %s\n", (uint8_t *) NLMSG_DATA(nlh));
        close(sock_fd);

        return 1;
}
