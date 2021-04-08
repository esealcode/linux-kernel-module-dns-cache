#define KPB_FAIL        0
#define KPB_SUCCESS     1

/* Simple implementation of a buffer easy to manipulate */
struct kp_buff
{
        struct kp_buff  *prev;
        struct kp_buff  *next;
        uint8_t         *head;
        uint8_t         *data;
        uint8_t         *tail;
        uint8_t         *end;
        uint8_t         *cur;
        uint32_t        len;
};
