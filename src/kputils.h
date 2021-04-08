struct kp_link
{
        struct sockaddr_nl src_addr;
        struct sockaddr_nl dst_addr;
        uint32_t sock_fd;
        struct iovec iov;
        struct msghdr u_msg;
};
