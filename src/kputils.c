#include <sys/socket.h>
#include <linux/netlink.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include "kputils.h"
#include "netpanda.h"

struct kp_link* kp_link_create(void)
{
        struct kp_link* lk = calloc(1, sizeof(struct kp_link));

        /*
            We create a socket with SOCK_DGRAM to use sendto()-recvfrom()
            library functions which will create msghdr and iovector structure for us,
            by doing that we'll just have to create an nlmsghdr structure accodring
            to NETLINK packet structure.
         */
        lk->sock_fd = socket(PF_NETLINK, SOCK_DGRAM, NET_PANDA);
        if ( lk->sock_fd < 0 ) {
                printf("Error while socket()\n");
                return NULL;
        }

        lk->src_addr.nl_family = AF_NETLINK;
        lk->src_addr.nl_pid = getpid();

        if ( bind(lk->sock_fd, (struct sockaddr *)&lk->src_addr, sizeof(lk->src_addr)) < 0 ) {
                close(lk->sock_fd);
                free(lk);
                return NULL;
        }

        lk->dst_addr.nl_family = AF_NETLINK;
        lk->dst_addr.nl_pid = 0; /* Kernel pid */
        lk->dst_addr.nl_groups = 0;

        return lk;
}

success_status kp_link_send(struct kp_link* lk, void* buf, size_t len)
{
        struct nlmsghdr* nlh;

        nlh = (struct nlmsghdr *) calloc(1, NLMSG_SPACE(PLOAD_SIZE));
        if ( !nlh )
                return 0;

        nlh->nlmsg_len = NLMSG_SPACE(PLOAD_SIZE);
        nlh->nlmsg_pid = getpid();
        nlh->nlmsg_flags = 0;
        memcpy(NLMSG_DATA(nlh), buf, len);

        uint8_t send_res = sendto(lk->sock_fd, nlh, nlh->nlmsg_len, 0, (struct sockaddr *) &lk->dst_addr, sizeof(lk->dst_addr));
        free(nlh);

        return send_res < 0 ? 0 : 1;
}

success_status kp_link_recv(struct kp_link* lk, void* buf, size_t len)
{
        uint32_t sz = sizeof(lk->dst_addr);
        ssize_t rcv = recvfrom(lk->sock_fd, buf, len, 0, (struct sockaddr *) &lk->dst_addr, &sz);
        if ( rcv < 0 )
                return 0;
        return 1;
}

success_status kp_link_close(struct kp_link* lk)
{
        close(lk->sock_fd);
        return 1;
}
