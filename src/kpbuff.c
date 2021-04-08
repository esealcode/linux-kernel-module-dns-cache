#include "kpbuff.h"
#include <stdint.h>
#include <string.h>
#include <unistd.h>

/* kp_buff methods */
struct kp_buff* kpb_alloc(uint32_t size)
{
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

uint8_t* kpb_head(struct kp_buff* kpb)
{
        return kpb->head;
}

uint8_t* kpb_data(struct kp_buff* kpb)
{
        return kpb->data;
}

uint8_t* kpb_tail(struct kp_buff* kpb)
{
        return kpb->tail;
}

uint8_t* kpb_end(struct kp_buff* kpb)
{
        return kpb->end;
}

uint8_t* kpb_cur(struct kp_buff* kpb)
{
        return kpb->cur;
}

uint32_t kpb_len(struct kp_buff* kpb)
{
        return kpb->len;
}

uint32_t kpb_real_size(struct kp_buff* kpb)
{
        return (uint32_t) (kpb_end(kpb) - kpb_head(kpb));
}

uint32_t kpb_tailroom(struct kp_buff* kpb)
{
        return (uint32_t) (kpb_end(kpb) - kpb_tail(kpb));
}

uint32_t kpb_headroom(struct kp_buff* kpb)
{
        return (uint32_t) (kpb_data(kpb) - kpb_head(kpb));
}

uint32_t kpb_szchunk_left(struct kp_buff* kpb)
{
        return (uint32_t) (kpb_tail(kpb) - kpb_cur(kpb));
}

void kpb_set_head(struct kp_buff* kpb, uint8_t* set)
{
        kpb->head = set;
}

void kpb_set_data(struct kp_buff* kpb, uint8_t* set)
{
        kpb->data = set;
}

void kpb_set_tail(struct kp_buff* kpb, uint8_t* set)
{
        kpb->tail = set;
}

void kpb_set_end(struct kp_buff* kpb, uint8_t* set)
{
        kpb->end = set;
}

void kpb_inc_cur(struct kp_buff* kpb, uint32_t i)
{
        kpb->cur += i;
}

void kpb_rst_cur(struct kp_buff* kpb)
{
        kpb->cur = kpb_data(kpb);
}

void kpb_set_len(struct kp_buff* kpb, uint32_t len)
{
        kpb->len = len;
}

kpb_success kpb_put(struct kp_buff* kpb, uint32_t u)
{
        kpb_set_tail(kpb, kpb_tail(kpb) + u);
        kpb_set_len(kpb, kpb_len(kpb) + u);
        if ( kpb_end(kpb) < kpb_tail(kpb) )
                return KPB_FAIL;
        return KPB_SUCCESS;
}

kpb_success kpb_shrink(struct kp_buff* kpb, uint32_t u)
{
        kpb_set_tail(kpb, kpb_tail(kpb) - u);
        kpb_set_len(kpb, kpb_len(kpb) - u);
        if ( kpb_head(kpb) > kpb_tail(kpb) )
                return KPB_FAIL;
        return KPB_SUCCESS;
}

void kpb_reset(struct kp_buff* kpb)
{
        kpb_set_data(kpb, kpb_head(kpb));
        kpb_set_tail(kpb, kpb_head(kpb));
        kpb_set_len(kpb, 0);
}

kpb_success kpb_expand(struct kp_buff* kpb, uint32_t ex)
{
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

kpb_success kpb_bind(struct kp_buff* kdst, struct kp_buff* ksrc)
{
        int o = kpb_len(ksrc) - kpb_tailroom(kdst);
        if ( o > 0 ) {
                /* Reallocation needed, pad_pw32 is used to pad to next power of 2 to avoid future extra realloc(), if padding grows too large, realloc() will fail anyway */
                if ( kpb_expand(kdst, pad_pw32(o)) == KPB_FAIL )
                        return KPB_FAIL;
        }

        memcpy(kpb_tail(kdst), kpb_data(ksrc), kpb_len(ksrc));
        return KPB_SUCCESS;
}

void kpb_zero_memory(struct kp_buff* kpb)
{
        memset(kpb_head(kpb), 0x00, kpb_real_size(kpb));
}

void kpb_free(struct kp_buff* kpb)
{
        free(kpb_head(kpb));
        free(kpb);
}

success_status kp_set_cache_header(struct kp_cache_cmd* k)
{
        struct kp_buff* kpb = (struct kp_buff *) kpb_alloc(sizeof(struct_kp_cache_header));
        struct_kp_cache_header* h;
        if ( kpb == NULL )
                return 0;
        /* Header just need to be set to 0 */
        kpb_zero_memory(kpb);

        k->header = kpb;

        h = (struct_kp_cache_header *) kpb_data(kpb);

        /* Set interface ref */
        k->tot_qu = &h->qcount;
        k->tot_an = &h->acount;
        k->tot_autRR = &h->nscount;
        k->tot_addRR = &h->arcount;

        return 1;
}

struct kp_buff* kp_create_cache_query( struct_kp_cache_query* query)
{
        /*uint16_t label_len              = strlen(query->dom) + 2;
        uint16_t prefetch_length        = sizeof(struct_kp_cache_query) + label_len;
        struct kp_buff* kpb             = NULL;

        kpb = (struct kp_buff *) kpb_alloc(prefetch_length);
        if ( kpb == NULL )
                return NULL;

        kpb = (struct_kp_cache_query *) kpb_data(kpb);

        kpb->type       = htons(query->type);
        kpb->class      = htons(query->class);

        return kpb;*/
}

struct kp_buff* kp_create_cache_stdrr( struct_kp_cache_rr* stdrr, uint8_t* data )
{
        uint32_t prefetch_len           = sizeof(struct_kp_cache_rr) + stdrr->rdata_len;
        struct kp_buff* kpb             = NULL;

        kpb = (struct kp_buff *) kpb_alloc(prefetch_len);
        if ( kpb == NULL )
                return NULL;

        if ( stdrr->lptr )
                memcpy(kpb_data(kpb), stdrr, sizeof(struct_kp_cache_rr));
        else
                memcpy(kpb_data(kpb), (uint8_t *) stdrr + sizeof(uint16_t), sizeof(struct_kp_cache_rr) - sizeof(uint16_t));

        memcpy(stdrr + 1, data, stdrr->rdata_len);

        return kpb;
}

success_status kp_append_cache_query( struct kp_cache_cmd* k, struct_kp_cache_query* q )
{
        struct kp_buff* kpb = NULL;
        if ( k->query )
                kpb_free(k->query);

        kpb = kp_create_cache_query(q);
        if ( kpb == NULL )
                return 0;
        k->query = kpb;
        return 1;
}

success_status kp_append_cache_stdrr( struct kp_buff** queue, struct_kp_cache_rr* rr, uint8_t* data )
{
        struct kp_buff* kpb = kp_create_cache_stdrr(rr, data);
        if ( kpb == NULL )
                return 0;

        if ( *queue == NULL ) {
                kpb->next = NULL;
                kpb->prev = NULL;
        }
        else {
                kpb->next = *queue;
                (*queue)->prev = kpb;
        }

        *queue = kpb;
        return 1;
}
