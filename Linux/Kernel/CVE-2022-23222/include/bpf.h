#ifndef _BPF_H_
#define _BPF_H_

#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <linux/types.h>

/* Instruction classes */
#define BPF_CLASS(code) ((code) & 0x07)
#define		BPF_LD		0x00
#define		BPF_LDX		0x01
#define		BPF_ST		0x02
#define		BPF_STX		0x03
#define		BPF_ALU		0x04
#define		BPF_JMP		0x05
#define		BPF_RET		0x06
#define		BPF_MISC        0x07

/* ld/ldx fields */
#define BPF_SIZE(code)  ((code) & 0x18)
#define		BPF_W		0x00 /* 32-bit */
#define		BPF_H		0x08 /* 16-bit */
#define		BPF_B		0x10 /*  8-bit */
#define		BPF_DW		0x18 /* 64-bit */
#define BPF_MODE(code)  ((code) & 0xe0)
#define		BPF_IMM		0x00
#define		BPF_ABS		0x20
#define		BPF_IND		0x40
#define		BPF_MEM		0x60
#define		BPF_LEN		0x80
#define		BPF_MSH		0xa0

/* alu/jmp fields */
#define BPF_OP(code)    ((code) & 0xf0)
#define		BPF_ADD		0x00
#define		BPF_SUB		0x10
#define		BPF_MUL		0x20
#define		BPF_DIV		0x30
#define		BPF_OR		0x40
#define		BPF_AND		0x50
#define		BPF_LSH		0x60
#define		BPF_RSH		0x70
#define		BPF_NEG		0x80
#define		BPF_MOD		0x90
#define		BPF_XOR		0xa0

#define		BPF_JA		0x00
#define		BPF_JEQ		0x10
#define		BPF_JGT		0x20
#define		BPF_JGE		0x30
#define		BPF_JSET        0x40
#define BPF_SRC(code)   ((code) & 0x08)
#define		BPF_K		0x00
#define		BPF_X		0x08

/* Extended instruction set based on top of classic BPF */

/* instruction classes */
#define BPF_JMP32	0x06	/* jmp mode in word width */
#define BPF_ALU64	0x07	/* alu mode in double word width */

/* ld/ldx fields */
#define BPF_DW		0x18	/* double word (64-bit) */
#define BPF_ATOMIC	0xc0	/* atomic memory ops - op type in immediate */
#define BPF_XADD	0xc0	/* exclusive add - legacy name */

/* alu/jmp fields */
#define BPF_MOV		0xb0	/* mov reg to reg */
#define BPF_ARSH	0xc0	/* sign extending arithmetic shift right */

/* change endianness of a register */
#define BPF_END		0xd0	/* flags for endianness conversion: */
#define BPF_TO_LE	0x00	/* convert to little-endian */
#define BPF_TO_BE	0x08	/* convert to big-endian */
#define BPF_FROM_LE	BPF_TO_LE
#define BPF_FROM_BE	BPF_TO_BE

/* jmp encodings */
#define BPF_JNE		0x50	/* jump != */
#define BPF_JLT		0xa0	/* LT is unsigned, '<' */
#define BPF_JLE		0xb0	/* LE is unsigned, '<=' */
#define BPF_JSGT	0x60	/* SGT is signed '>', GT in x86 */
#define BPF_JSGE	0x70	/* SGE is signed '>=', GE in x86 */
#define BPF_JSLT	0xc0	/* SLT is signed, '<' */
#define BPF_JSLE	0xd0	/* SLE is signed, '<=' */
#define BPF_CALL	0x80	/* function call */
#define BPF_EXIT	0x90	/* function return */

/* atomic op type fields (stored in immediate) */
#define BPF_FETCH	0x01	/* not an opcode on its own, used to build others */
#define BPF_XCHG	(0xe0 | BPF_FETCH)	/* atomic exchange */
#define BPF_CMPXCHG	(0xf0 | BPF_FETCH)	/* atomic compare-and-write */

/* When BPF ldimm64's insn[0].src_reg != 0 then this can have
 * the following extensions:
 *
 * insn[0].src_reg:  BPF_PSEUDO_MAP_FD
 * insn[0].imm:      map fd
 * insn[1].imm:      0
 * insn[0].off:      0
 * insn[1].off:      0
 * ldimm64 rewrite:  address of map
 * verifier type:    CONST_PTR_TO_MAP
 */
#define BPF_PSEUDO_MAP_FD	1
/* insn[0].src_reg:  BPF_PSEUDO_MAP_VALUE
 * insn[0].imm:      map fd
 * insn[1].imm:      offset into value
 * insn[0].off:      0
 * insn[1].off:      0
 * ldimm64 rewrite:  address of map[0]+offset
 * verifier type:    PTR_TO_MAP_VALUE
 */
#define BPF_PSEUDO_MAP_VALUE	2
/* insn[0].src_reg:  BPF_PSEUDO_BTF_ID
 * insn[0].imm:      kernel btd id of VAR
 * insn[1].imm:      0
 * insn[0].off:      0
 * insn[1].off:      0
 * ldimm64 rewrite:  address of the kernel variable
 * verifier type:    PTR_TO_BTF_ID or PTR_TO_MEM, depending on whether the var
 *                   is struct/union.
 */
#define BPF_PSEUDO_BTF_ID	3

/* when bpf_call->src_reg == BPF_PSEUDO_CALL, bpf_call->imm == pc-relative
 * offset to another bpf function
 */
#define BPF_PSEUDO_CALL		1

/* Register numbers */
enum {
	BPF_REG_0 = 0,
	BPF_REG_1,
	BPF_REG_2,
	BPF_REG_3,
	BPF_REG_4,
	BPF_REG_5,
	BPF_REG_6,
	BPF_REG_7,
	BPF_REG_8,
	BPF_REG_9,
	BPF_REG_10,
	__MAX_BPF_REG,
};

/* BPF has 10 general purpose 64-bit registers and stack frame. */
#define MAX_BPF_REG	__MAX_BPF_REG

struct bpf_insn {
	__u8	code;		/* opcode */
	__u8	dst_reg:4;	/* dest register */
	__u8	src_reg:4;	/* source register */
	__s16	off;		/* signed offset */
	__s32	imm;		/* signed immediate constant */
};

enum bpf_cmd {
	BPF_MAP_CREATE,
	BPF_MAP_LOOKUP_ELEM,
	BPF_MAP_UPDATE_ELEM,
	BPF_MAP_DELETE_ELEM,
	BPF_MAP_GET_NEXT_KEY,
	BPF_PROG_LOAD,
	BPF_OBJ_PIN,
	BPF_OBJ_GET,
	BPF_PROG_ATTACH,
	BPF_PROG_DETACH,
	BPF_PROG_TEST_RUN,
	BPF_PROG_RUN = BPF_PROG_TEST_RUN,
	BPF_PROG_GET_NEXT_ID,
	BPF_MAP_GET_NEXT_ID,
	BPF_PROG_GET_FD_BY_ID,
	BPF_MAP_GET_FD_BY_ID,
	BPF_OBJ_GET_INFO_BY_FD,
	BPF_PROG_QUERY,
	BPF_RAW_TRACEPOINT_OPEN,
	BPF_BTF_LOAD,
	BPF_BTF_GET_FD_BY_ID,
	BPF_TASK_FD_QUERY,
	BPF_MAP_LOOKUP_AND_DELETE_ELEM,
	BPF_MAP_FREEZE,
	BPF_BTF_GET_NEXT_ID,
	BPF_MAP_LOOKUP_BATCH,
	BPF_MAP_LOOKUP_AND_DELETE_BATCH,
	BPF_MAP_UPDATE_BATCH,
	BPF_MAP_DELETE_BATCH,
	BPF_LINK_CREATE,
	BPF_LINK_UPDATE,
	BPF_LINK_GET_FD_BY_ID,
	BPF_LINK_GET_NEXT_ID,
	BPF_ENABLE_STATS,
	BPF_ITER_CREATE,
	BPF_LINK_DETACH,
	BPF_PROG_BIND_MAP,
};

enum bpf_map_type {
	BPF_MAP_TYPE_UNSPEC = 0,
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_ARRAY = 2,
	BPF_MAP_TYPE_PROG_ARRAY = 3,
	BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
	BPF_MAP_TYPE_PERCPU_HASH = 5,
	BPF_MAP_TYPE_PERCPU_ARRAY = 6,
	BPF_MAP_TYPE_STACK_TRACE = 7,
	BPF_MAP_TYPE_CGROUP_ARRAY = 8,
	BPF_MAP_TYPE_LRU_HASH = 9,
	BPF_MAP_TYPE_LRU_PERCPU_HASH = 10,
	BPF_MAP_TYPE_LPM_TRIE = 11,
	BPF_MAP_TYPE_ARRAY_OF_MAPS = 12,
	BPF_MAP_TYPE_HASH_OF_MAPS = 13,
	BPF_MAP_TYPE_DEVMAP = 14,
	BPF_MAP_TYPE_SOCKMAP = 15,
	BPF_MAP_TYPE_CPUMAP = 16,
	BPF_MAP_TYPE_XSKMAP = 17,
	BPF_MAP_TYPE_SOCKHASH = 18,
	BPF_MAP_TYPE_CGROUP_STORAGE = 19,
	BPF_MAP_TYPE_REUSEPORT_SOCKARRAY = 20,
	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE = 21,
	BPF_MAP_TYPE_QUEUE = 22,
	BPF_MAP_TYPE_STACK = 23,
	BPF_MAP_TYPE_SK_STORAGE = 24,
	BPF_MAP_TYPE_DEVMAP_HASH = 25,
	BPF_MAP_TYPE_STRUCT_OPS = 26,
	BPF_MAP_TYPE_RINGBUF = 27,
	BPF_MAP_TYPE_INODE_STORAGE = 28,
	BPF_MAP_TYPE_TASK_STORAGE = 29,
};

enum bpf_prog_type {
	BPF_PROG_TYPE_UNSPEC = 0,
	BPF_PROG_TYPE_SOCKET_FILTER = 1,
	BPF_PROG_TYPE_KPROBE = 2,
	BPF_PROG_TYPE_SCHED_CLS = 3,
	BPF_PROG_TYPE_SCHED_ACT = 4,
	BPF_PROG_TYPE_TRACEPOINT = 5,
	BPF_PROG_TYPE_XDP = 6,
	BPF_PROG_TYPE_PERF_EVENT = 7,
	BPF_PROG_TYPE_CGROUP_SKB = 8,
	BPF_PROG_TYPE_CGROUP_SOCK = 9,
	BPF_PROG_TYPE_LWT_IN = 10,
	BPF_PROG_TYPE_LWT_OUT = 11,
	BPF_PROG_TYPE_LWT_XMIT = 12,
	BPF_PROG_TYPE_SOCK_OPS = 13,
	BPF_PROG_TYPE_SK_SKB = 14,
	BPF_PROG_TYPE_CGROUP_DEVICE = 15,
	BPF_PROG_TYPE_SK_MSG = 16,
	BPF_PROG_TYPE_RAW_TRACEPOINT = 17,
	BPF_PROG_TYPE_CGROUP_SOCK_ADDR = 18,
	BPF_PROG_TYPE_LWT_SEG6LOCAL = 19,
	BPF_PROG_TYPE_LIRC_MODE2 = 20,
	BPF_PROG_TYPE_SK_REUSEPORT = 21,
	BPF_PROG_TYPE_FLOW_DISSECTOR = 22,
	BPF_PROG_TYPE_CGROUP_SYSCTL = 23,
	BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE = 24,
	BPF_PROG_TYPE_CGROUP_SOCKOPT = 25,
	BPF_PROG_TYPE_TRACING = 26,
	BPF_PROG_TYPE_STRUCT_OPS = 27,
	BPF_PROG_TYPE_EXT = 28,
	BPF_PROG_TYPE_LSM = 29,
	BPF_PROG_TYPE_SK_LOOKUP = 30,
	BPF_PROG_TYPE_SYSCALL = 31,
};

enum bpf_attach_type {
	BPF_CGROUP_INET_INGRESS = 0,
	BPF_CGROUP_INET_EGRESS = 1,
	BPF_CGROUP_INET_SOCK_CREATE = 2,
	BPF_CGROUP_SOCK_OPS = 3,
	BPF_SK_SKB_STREAM_PARSER = 4,
	BPF_SK_SKB_STREAM_VERDICT = 5,
	BPF_CGROUP_DEVICE = 6,
	BPF_SK_MSG_VERDICT = 7,
	BPF_CGROUP_INET4_BIND = 8,
	BPF_CGROUP_INET6_BIND = 9,
	BPF_CGROUP_INET4_CONNECT = 10,
	BPF_CGROUP_INET6_CONNECT = 11,
	BPF_CGROUP_INET4_POST_BIND = 12,
	BPF_CGROUP_INET6_POST_BIND = 13,
	BPF_CGROUP_UDP4_SENDMSG = 14,
	BPF_CGROUP_UDP6_SENDMSG = 15,
	BPF_LIRC_MODE2 = 16,
	BPF_FLOW_DISSECTOR = 17,
	BPF_CGROUP_SYSCTL = 18,
	BPF_CGROUP_UDP4_RECVMSG = 19,
	BPF_CGROUP_UDP6_RECVMSG = 20,
	BPF_CGROUP_GETSOCKOPT = 21,
	BPF_CGROUP_SETSOCKOPT = 22,
	BPF_TRACE_RAW_TP = 23,
	BPF_TRACE_FENTRY = 24,
	BPF_TRACE_FEXIT = 25,
	BPF_MODIFY_RETURN = 26,
	BPF_LSM_MAC = 27,
	BPF_TRACE_ITER = 28,
	BPF_CGROUP_INET4_GETPEERNAME = 29,
	BPF_CGROUP_INET6_GETPEERNAME = 30,
	BPF_CGROUP_INET4_GETSOCKNAME = 31,
	BPF_CGROUP_INET6_GETSOCKNAME = 32,
	BPF_XDP_DEVMAP = 33,
	BPF_CGROUP_INET_SOCK_RELEASE = 34,
	BPF_XDP_CPUMAP = 35,
	BPF_SK_LOOKUP = 36,
	BPF_XDP = 37,
	BPF_SK_SKB_VERDICT = 38,
	BPF_SK_REUSEPORT_SELECT = 39,
	BPF_SK_REUSEPORT_SELECT_OR_MIGRATE = 40,
	__MAX_BPF_ATTACH_TYPE = 41,
};

#define BPF_OBJ_NAME_LEN 16U

union bpf_attr {
	struct {
		__u32 map_type;
		__u32 key_size;
		__u32 value_size;
		__u32 max_entries;
		__u32 map_flags;
		__u32 inner_map_fd;
		__u32 numa_node;
		char map_name[BPF_OBJ_NAME_LEN];
		__u32 map_ifindex;
		__u32 btf_fd;
		__u32 btf_key_type_id;
		__u32 btf_value_type_id;
		__u32 btf_vmlinux_value_type_id;
	};
	struct {
		__u32 map_fd;
		__u64 key;
		union {
			__u64 value;
			__u64 next_key;
		};
		__u64 flags;
	};
	struct {
		__u64 in_batch;
		__u64 out_batch;
		__u64 keys;
		__u64 values;
		__u32 count;
		__u32 map_fd;
		__u64 elem_flags;
		__u64 flags;
	} batch;
	struct {
		__u32 prog_type;
		__u32 insn_cnt;
		__u64 insns;
		__u64 license;
		__u32 log_level;
		__u32 log_size;
		__u64 log_buf;
		__u32 kern_version;
		__u32 prog_flags;
		char prog_name[BPF_OBJ_NAME_LEN];
		__u32 prog_ifindex;
		__u32 expected_attach_type;
		__u32 prog_btf_fd;
		__u32 func_info_rec_size;
		__u64 func_info;
		__u32 func_info_cnt;
		__u32 line_info_rec_size;
		__u64 line_info;
		__u32 line_info_cnt;
		__u32 attach_btf_id;
		union {
			__u32 attach_prog_fd;
			__u32 attach_btf_obj_fd;
		};
		__u64 fd_array;
	};
	struct {
		__u64 pathname;
		__u32 bpf_fd;
		__u32 file_flags;
	};
	struct {
		__u32 target_fd;
		__u32 attach_bpf_fd;
		__u32 attach_type;
		__u32 attach_flags;
		__u32 replace_bpf_fd;
	};
	struct {
		__u32 prog_fd;
		__u32 retval;
		__u32 data_size_in;
		__u32 data_size_out;
		__u64 data_in;
		__u64 data_out;
		__u32 repeat;
		__u32 duration;
		__u32 ctx_size_in;
		__u32 ctx_size_out;
		__u64 ctx_in;
		__u64 ctx_out;
		__u32 flags;
		__u32 cpu;
	} test;
	struct {
		union {
			__u32 start_id;
			__u32 prog_id;
			__u32 map_id;
			__u32 btf_id;
			__u32 link_id;
		};
		__u32 next_id;
		__u32 open_flags;
	};
	struct {
		__u32 bpf_fd;
		__u32 info_len;
		__u64 info;
	} info;
	struct {
		__u32 target_fd;
		__u32 attach_type;
		__u32 query_flags;
		__u32 attach_flags;
		__u64 prog_ids;
		__u32 prog_cnt;
	} query;
	struct {
		__u64 name;
		__u32 prog_fd;
	} raw_tracepoint;
	struct {
		__u64 btf;
		__u64 btf_log_buf;
		__u32 btf_size;
		__u32 btf_log_size;
		__u32 btf_log_level;
	};
	struct {
		__u32 pid;
		__u32 fd;
		__u32 flags;
		__u32 buf_len;
		__u64 buf;
		__u32 prog_id;
		__u32 fd_type;
		__u64 probe_offset;
		__u64 probe_addr;
	} task_fd_query;
	struct {
		__u32 prog_fd;
		union {
			__u32 target_fd;
			__u32 target_ifindex;
		};
		__u32 attach_type;
		__u32 flags;
		union {
			__u32 target_btf_id;
			struct {
				__u64 iter_info;
				__u32 iter_info_len;
			};
		};
	} link_create;
	struct {
		__u32 link_fd;
		__u32 new_prog_fd;
		__u32 flags;
		__u32 old_prog_fd;
	} link_update;
	struct {
		__u32 link_fd;
	} link_detach;
	struct {
		__u32 type;
	} enable_stats;
	struct {
		__u32 link_fd;
		__u32 flags;
	} iter_create;
	struct {
		__u32 prog_fd;
		__u32 map_fd;
		__u32 flags;
	} prog_bind_map;
};

#define BPF_TAG_SIZE	8

struct bpf_prog_info {
	__u32 type;
	__u32 id;
	__u8  tag[BPF_TAG_SIZE];
	__u32 jited_prog_len;
	__u32 xlated_prog_len;
	__aligned_u64 jited_prog_insns;
	__aligned_u64 xlated_prog_insns;
	__u64 load_time;	/* ns since boottime */
	__u32 created_by_uid;
	__u32 nr_map_ids;
	__aligned_u64 map_ids;
	char name[BPF_OBJ_NAME_LEN];
	__u32 ifindex;
	__u32 gpl_compatible:1;
	__u32 :31; /* alignment pad */
	__u64 netns_dev;
	__u64 netns_ino;
	__u32 nr_jited_ksyms;
	__u32 nr_jited_func_lens;
	__aligned_u64 jited_ksyms;
	__aligned_u64 jited_func_lens;
	__u32 btf_id;
	__u32 func_info_rec_size;
	__aligned_u64 func_info;
	__u32 nr_func_info;
	__u32 nr_line_info;
	__aligned_u64 line_info;
	__aligned_u64 jited_line_info;
	__u32 nr_jited_line_info;
	__u32 line_info_rec_size;
	__u32 jited_line_info_rec_size;
	__u32 nr_prog_tags;
	__aligned_u64 prog_tags;
	__u64 run_time_ns;
	__u64 run_cnt;
	__u64 recursion_misses;
} __attribute__((aligned(8)));

struct bpf_map_info {
	__u32 type;
	__u32 id;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	__u32 map_flags;
	char  name[BPF_OBJ_NAME_LEN];
	__u32 ifindex;
	__u32 btf_vmlinux_value_type_id;
	__u64 netns_dev;
	__u64 netns_ino;
	__u32 btf_id;
	__u32 btf_key_type_id;
	__u32 btf_value_type_id;
} __attribute__((aligned(8)));

struct bpf_btf_info {
	__aligned_u64 btf;
	__u32 btf_size;
	__u32 id;
	__aligned_u64 name;
	__u32 name_len;
	__u32 kernel_btf;
} __attribute__((aligned(8)));

struct bpf_link_info {
	__u32 type;
	__u32 id;
	__u32 prog_id;
	union {
		struct {
			__aligned_u64 tp_name; /* in/out: tp_name buffer ptr */
			__u32 tp_name_len;     /* in/out: tp_name buffer len */
		} raw_tracepoint;
		struct {
			__u32 attach_type;
			__u32 target_obj_id; /* prog_id for PROG_EXT, otherwise btf object id */
			__u32 target_btf_id; /* BTF type id inside the object */
		} tracing;
		struct {
			__u64 cgroup_id;
			__u32 attach_type;
		} cgroup;
		struct {
			__aligned_u64 target_name; /* in/out: target_name buffer ptr */
			__u32 target_name_len;	   /* in/out: target_name buffer len */
			union {
				struct {
					__u32 map_id;
				} map;
			};
		} iter;
		struct  {
			__u32 netns_ino;
			__u32 attach_type;
		} netns;
		struct {
			__u32 ifindex;
		} xdp;
	};
} __attribute__((aligned(8)));

enum bpf_func_id {
	BPF_FUNC_unspec = 0,
	BPF_FUNC_map_lookup_elem = 1,
	BPF_FUNC_map_update_elem = 2,
	BPF_FUNC_map_delete_elem = 3,
	BPF_FUNC_probe_read = 4,
	BPF_FUNC_ktime_get_ns = 5,
	BPF_FUNC_trace_printk = 6,
	BPF_FUNC_get_prandom_u32 = 7,
	BPF_FUNC_get_smp_processor_id = 8,
	BPF_FUNC_skb_store_bytes = 9,
	BPF_FUNC_l3_csum_replace = 10,
	BPF_FUNC_l4_csum_replace = 11,
	BPF_FUNC_tail_call = 12,
	BPF_FUNC_clone_redirect = 13,
	BPF_FUNC_get_current_pid_tgid = 14,
	BPF_FUNC_get_current_uid_gid = 15,
	BPF_FUNC_get_current_comm = 16,
	BPF_FUNC_get_cgroup_classid = 17,
	BPF_FUNC_skb_vlan_push = 18,
	BPF_FUNC_skb_vlan_pop = 19,
	BPF_FUNC_skb_get_tunnel_key = 20,
	BPF_FUNC_skb_set_tunnel_key = 21,
	BPF_FUNC_perf_event_read = 22,
	BPF_FUNC_redirect = 23,
	BPF_FUNC_get_route_realm = 24,
	BPF_FUNC_perf_event_output = 25,
	BPF_FUNC_skb_load_bytes = 26,
	BPF_FUNC_get_stackid = 27,
	BPF_FUNC_csum_diff = 28,
	BPF_FUNC_skb_get_tunnel_opt = 29,
	BPF_FUNC_skb_set_tunnel_opt = 30,
	BPF_FUNC_skb_change_proto = 31,
	BPF_FUNC_skb_change_type = 32,
	BPF_FUNC_skb_under_cgroup = 33,
	BPF_FUNC_get_hash_recalc = 34,
	BPF_FUNC_get_current_task = 35,
	BPF_FUNC_probe_write_user = 36,
	BPF_FUNC_current_task_under_cgroup = 37,
	BPF_FUNC_skb_change_tail = 38,
	BPF_FUNC_skb_pull_data = 39,
	BPF_FUNC_csum_update = 40,
	BPF_FUNC_set_hash_invalid = 41,
	BPF_FUNC_get_numa_node_id = 42,
	BPF_FUNC_skb_change_head = 43,
	BPF_FUNC_xdp_adjust_head = 44,
	BPF_FUNC_probe_read_str = 45,
	BPF_FUNC_get_socket_cookie = 46,
	BPF_FUNC_get_socket_uid = 47,
	BPF_FUNC_set_hash = 48,
	BPF_FUNC_setsockopt = 49,
	BPF_FUNC_skb_adjust_room = 50,
	BPF_FUNC_redirect_map = 51,
	BPF_FUNC_sk_redirect_map = 52,
	BPF_FUNC_sock_map_update = 53,
	BPF_FUNC_xdp_adjust_meta = 54,
	BPF_FUNC_perf_event_read_value = 55,
	BPF_FUNC_perf_prog_read_value = 56,
	BPF_FUNC_getsockopt = 57,
	BPF_FUNC_override_return = 58,
	BPF_FUNC_sock_ops_cb_flags_set = 59,
	BPF_FUNC_msg_redirect_map = 60,
	BPF_FUNC_msg_apply_bytes = 61,
	BPF_FUNC_msg_cork_bytes = 62,
	BPF_FUNC_msg_pull_data = 63,
	BPF_FUNC_bind = 64,
	BPF_FUNC_xdp_adjust_tail = 65,
	BPF_FUNC_skb_get_xfrm_state = 66,
	BPF_FUNC_get_stack = 67,
	BPF_FUNC_skb_load_bytes_relative = 68,
	BPF_FUNC_fib_lookup = 69,
	BPF_FUNC_sock_hash_update = 70,
	BPF_FUNC_msg_redirect_hash = 71,
	BPF_FUNC_sk_redirect_hash = 72,
	BPF_FUNC_lwt_push_encap = 73,
	BPF_FUNC_lwt_seg6_store_bytes = 74,
	BPF_FUNC_lwt_seg6_adjust_srh = 75,
	BPF_FUNC_lwt_seg6_action = 76,
	BPF_FUNC_rc_repeat = 77,
	BPF_FUNC_rc_keydown = 78,
	BPF_FUNC_skb_cgroup_id = 79,
	BPF_FUNC_get_current_cgroup_id = 80,
	BPF_FUNC_get_local_storage = 81,
	BPF_FUNC_sk_select_reuseport = 82,
	BPF_FUNC_skb_ancestor_cgroup_id = 83,
	BPF_FUNC_sk_lookup_tcp = 84,
	BPF_FUNC_sk_lookup_udp = 85,
	BPF_FUNC_sk_release = 86,
	BPF_FUNC_map_push_elem = 87,
	BPF_FUNC_map_pop_elem = 88,
	BPF_FUNC_map_peek_elem = 89,
	BPF_FUNC_msg_push_data = 90,
	BPF_FUNC_msg_pop_data = 91,
	BPF_FUNC_rc_pointer_rel = 92,
	BPF_FUNC_spin_lock = 93,
	BPF_FUNC_spin_unlock = 94,
	BPF_FUNC_sk_fullsock = 95,
	BPF_FUNC_tcp_sock = 96,
	BPF_FUNC_skb_ecn_set_ce = 97,
	BPF_FUNC_get_listener_sock = 98,
	BPF_FUNC_skc_lookup_tcp = 99,
	BPF_FUNC_tcp_check_syncookie = 100,
	BPF_FUNC_sysctl_get_name = 101,
	BPF_FUNC_sysctl_get_current_value = 102,
	BPF_FUNC_sysctl_get_new_value = 103,
	BPF_FUNC_sysctl_set_new_value = 104,
	BPF_FUNC_strtol = 105,
	BPF_FUNC_strtoul = 106,
	BPF_FUNC_sk_storage_get = 107,
	BPF_FUNC_sk_storage_delete = 108,
	BPF_FUNC_send_signal = 109,
	BPF_FUNC_tcp_gen_syncookie = 110,
	BPF_FUNC_skb_output = 111,
	BPF_FUNC_probe_read_user = 112,
	BPF_FUNC_probe_read_kernel = 113,
	BPF_FUNC_probe_read_user_str = 114,
	BPF_FUNC_probe_read_kernel_str = 115,
	BPF_FUNC_tcp_send_ack = 116,
	BPF_FUNC_send_signal_thread = 117,
	BPF_FUNC_jiffies64 = 118,
	BPF_FUNC_read_branch_records = 119,
	BPF_FUNC_get_ns_current_pid_tgid = 120,
	BPF_FUNC_xdp_output = 121,
	BPF_FUNC_get_netns_cookie = 122,
	BPF_FUNC_get_current_ancestor_cgroup_id = 123,
	BPF_FUNC_sk_assign = 124,
	BPF_FUNC_ktime_get_boot_ns = 125,
	BPF_FUNC_seq_printf = 126,
	BPF_FUNC_seq_write = 127,
	BPF_FUNC_sk_cgroup_id = 128,
	BPF_FUNC_sk_ancestor_cgroup_id = 129,
	BPF_FUNC_ringbuf_output = 130,
	BPF_FUNC_ringbuf_reserve = 131,
	BPF_FUNC_ringbuf_submit = 132,
	BPF_FUNC_ringbuf_discard = 133,
	BPF_FUNC_ringbuf_query = 134,
	BPF_FUNC_csum_level = 135,
	BPF_FUNC_skc_to_tcp6_sock = 136,
	BPF_FUNC_skc_to_tcp_sock = 137,
	BPF_FUNC_skc_to_tcp_timewait_sock = 138,
	BPF_FUNC_skc_to_tcp_request_sock = 139,
	BPF_FUNC_skc_to_udp6_sock = 140,
	BPF_FUNC_get_task_stack = 141,
	BPF_FUNC_load_hdr_opt = 142,
	BPF_FUNC_store_hdr_opt = 143,
	BPF_FUNC_reserve_hdr_opt = 144,
	BPF_FUNC_inode_storage_get = 145,
	BPF_FUNC_inode_storage_delete = 146,
	BPF_FUNC_d_path = 147,
	BPF_FUNC_copy_from_user = 148,
	BPF_FUNC_snprintf_btf = 149,
	BPF_FUNC_seq_printf_btf = 150,
	BPF_FUNC_skb_cgroup_classid = 151,
	BPF_FUNC_redirect_neigh = 152,
	BPF_FUNC_per_cpu_ptr = 153,
	BPF_FUNC_this_cpu_ptr = 154,
	BPF_FUNC_redirect_peer = 155,
	BPF_FUNC_task_storage_get = 156,
	BPF_FUNC_task_storage_delete = 157,
	BPF_FUNC_get_current_task_btf = 158,
	BPF_FUNC_bprm_opts_set = 159,
	BPF_FUNC_ktime_get_coarse_ns = 160,
	BPF_FUNC_ima_inode_hash = 161,
	BPF_FUNC_sock_from_file = 162,
	BPF_FUNC_check_mtu = 163,
	BPF_FUNC_for_each_map_elem = 164,
	BPF_FUNC_snprintf = 165,
	BPF_FUNC_sys_bpf = 166,
	BPF_FUNC_btf_find_by_name_kind = 167,
	BPF_FUNC_sys_close = 168,
	BPF_FUNC_timer_init = 169,
	BPF_FUNC_timer_set_callback = 170,
	BPF_FUNC_timer_start = 171,
	BPF_FUNC_timer_cancel = 172,
	BPF_FUNC_get_func_ip = 173,
	__BPF_FUNC_MAX_ID = 174,
};

static __always_inline int
bpf(int cmd, union bpf_attr *attr, unsigned int size)
{
    return syscall(__NR_bpf, cmd, attr, size);
}

static __always_inline int
bpf_create_map(enum bpf_map_type map_type, unsigned int key_size,
                unsigned int value_size, unsigned int max_entries)
{
    union bpf_attr attr = 
    {
        .map_type = map_type,
        .key_size = key_size,
        .value_size = value_size,
        .max_entries = max_entries,
    };

    return bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
}

static __always_inline int
bpf_create_map_with_name(enum bpf_map_type map_type, unsigned int key_size,
                unsigned int value_size, unsigned int max_entries, const char* name)
{
    union bpf_attr attr = 
    {
        .map_type = map_type,
        .key_size = key_size,
        .value_size = value_size,
        .max_entries = max_entries,
    };

	strncpy(attr.map_name, name, 0x10);

    return bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
}

static __always_inline int
bpf_lookup_elem(int fd, const void *key, void *value)
{
    union bpf_attr attr = {
        .map_fd = fd,
        .key    = (uint64_t)(key),
        .value  = (uint64_t)(value),
    };

    return bpf(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

static __always_inline int
bpf_update_elem(int fd, const void *key, const void *value,
                uint64_t flags)
{
    union bpf_attr attr = {
        .map_fd = fd,
        .key    = (uint64_t)(key),
        .value  = (uint64_t)(value),
        .flags  = flags,
    };

    return bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

static __always_inline int
bpf_delete_elem(int fd, const void *key)
{
    union bpf_attr attr = {
        .map_fd = fd,
        .key    = (uint64_t)(key),
    };

    return bpf(BPF_MAP_DELETE_ELEM, &attr, sizeof(attr));
}

static __always_inline int
bpf_obj_get_info_by_fd(int fd, struct bpf_map_info *info)
{
	union bpf_attr attr = {
		.info.bpf_fd = fd,
		.info.info = (__u64)info,
		.info.info_len = sizeof(struct bpf_map_info),
	};

	return bpf(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr));
}

#define LOG_BUF_SIZE 1024*1024
char bpf_log_buf[LOG_BUF_SIZE];

static __always_inline int
bpf_prog_load(enum bpf_prog_type type, const struct bpf_insn *insns,
                int insn_cnt, const char *license)
{
    union bpf_attr attr = {
        .prog_type = type,
        .insns     = (uint64_t)(insns),
        .insn_cnt  = insn_cnt,
        .license   = (uint64_t)(license),
        .log_buf   = (uint64_t)(bpf_log_buf),
        .log_size  = LOG_BUF_SIZE,
        .log_level = 3,
    };

    return bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
}

static __always_inline int
bpf_prog_test_run(int prog_fd, int repeat, void *data, uint32_t size,
                    void *data_out, unsigned int *size_out,
                    uint32_t *retval, uint32_t *duration)
{
    union bpf_attr attr;
    int ret;

    memset(&attr, 0, sizeof(attr));
    attr.test.prog_fd = prog_fd;
    attr.test.data_in = (uint64_t)(data);
    attr.test.data_out = (uint64_t)(data_out);
    attr.test.data_size_in = size;
    attr.test.repeat = repeat;

    ret = bpf(BPF_PROG_TEST_RUN, &attr, sizeof(attr));
    if (size_out)
        *size_out = attr.test.data_size_out;
    if (retval)
        *retval = attr.test.retval;
    if (duration)
        *duration = attr.test.duration;
    return ret;
}

static __always_inline int
bpf_prog_skb_run(int prog_fd, const void *data, size_t size)
{
    int err, socks[2] = {};

    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, socks) != 0)
        return errno;
    
    if (setsockopt(socks[0], SOL_SOCKET, SO_ATTACH_BPF,
                    &prog_fd, sizeof(prog_fd)) != 0)
    {
        err = errno;
        goto abort;
    }

    if (write(socks[1], data, size) != size)
    {
        err = -1;
        goto abort;
    }

    err = 0;
    
abort:
    close(socks[0]);
    close(socks[1]);
    return err;
}

/* ALU ops on registers, bpf_add|sub|...: dst_reg += src_reg */

#define BPF_ALU64_REG(OP, DST, SRC)                \
    ((struct bpf_insn) {                    \
        .code  = BPF_ALU64 | BPF_OP(OP) | BPF_X,    \
        .dst_reg = DST,                    \
        .src_reg = SRC,                    \
        .off   = 0,                    \
        .imm   = 0 })

#define BPF_ALU32_REG(OP, DST, SRC)                \
    ((struct bpf_insn) {                    \
        .code  = BPF_ALU | BPF_OP(OP) | BPF_X,        \
        .dst_reg = DST,                    \
        .src_reg = SRC,                    \
        .off   = 0,                    \
        .imm   = 0 })

/* ALU ops on immediates, bpf_add|sub|...: dst_reg += imm32 */

#define BPF_ALU64_IMM(OP, DST, IMM)                \
    ((struct bpf_insn) {                    \
        .code  = BPF_ALU64 | BPF_OP(OP) | BPF_K,    \
        .dst_reg = DST,                    \
        .src_reg = 0,                    \
        .off   = 0,                    \
        .imm   = IMM })

#define BPF_ALU32_IMM(OP, DST, IMM)                \
    ((struct bpf_insn) {                    \
        .code  = BPF_ALU | BPF_OP(OP) | BPF_K,        \
        .dst_reg = DST,                    \
        .src_reg = 0,                    \
        .off   = 0,                    \
        .imm   = IMM })

/* Short form of mov, dst_reg = src_reg */

#define BPF_MOV64_REG(DST, SRC)                    \
    ((struct bpf_insn) {                    \
        .code  = BPF_ALU64 | BPF_MOV | BPF_X,        \
        .dst_reg = DST,                    \
        .src_reg = SRC,                    \
        .off   = 0,                    \
        .imm   = 0 })

#define BPF_MOV32_REG(DST, SRC)                    \
    ((struct bpf_insn) {                    \
        .code  = BPF_ALU | BPF_MOV | BPF_X,        \
        .dst_reg = DST,                    \
        .src_reg = SRC,                    \
        .off   = 0,                    \
        .imm   = 0 })

/* Short form of mov, dst_reg = imm32 */

#define BPF_MOV64_IMM(DST, IMM)                    \
    ((struct bpf_insn) {                    \
        .code  = BPF_ALU64 | BPF_MOV | BPF_K,        \
        .dst_reg = DST,                    \
        .src_reg = 0,                    \
        .off   = 0,                    \
        .imm   = IMM })

#define BPF_MOV32_IMM(DST, IMM)                    \
    ((struct bpf_insn) {                    \
        .code  = BPF_ALU | BPF_MOV | BPF_K,        \
        .dst_reg = DST,                    \
        .src_reg = 0,                    \
        .off   = 0,                    \
        .imm   = IMM })

/* BPF_LD_IMM64 macro encodes single 'load 64-bit immediate' insn */
#define BPF_LD_IMM64(DST, IMM)                    \
    BPF_LD_IMM64_RAW(DST, 0, IMM)

#define BPF_LD_IMM64_RAW(DST, SRC, IMM)                \
    ((struct bpf_insn) {                    \
        .code  = BPF_LD | BPF_DW | BPF_IMM,        \
        .dst_reg = DST,                    \
        .src_reg = SRC,                    \
        .off   = 0,                    \
        .imm   = (__u32) (IMM) }),            \
    ((struct bpf_insn) {                    \
        .code  = 0, /* zero is reserved opcode */    \
        .dst_reg = 0,                    \
        .src_reg = 0,                    \
        .off   = 0,                    \
        .imm   = ((__u64) (IMM)) >> 32 })

#ifndef BPF_PSEUDO_MAP_FD
# define BPF_PSEUDO_MAP_FD    1
#endif

/* pseudo BPF_LD_IMM64 insn used to refer to process-local map_fd */
#define BPF_LD_MAP_FD(DST, MAP_FD)                \
    BPF_LD_IMM64_RAW(DST, BPF_PSEUDO_MAP_FD, MAP_FD)


/* Direct packet access, R0 = *(uint *) (skb->data + imm32) */

#define BPF_LD_ABS(SIZE, IMM)                    \
    ((struct bpf_insn) {                    \
        .code  = BPF_LD | BPF_SIZE(SIZE) | BPF_ABS,    \
        .dst_reg = 0,                    \
        .src_reg = 0,                    \
        .off   = 0,                    \
        .imm   = IMM })

/* Memory load, dst_reg = *(uint *) (src_reg + off16) */

#define BPF_LDX_MEM(SIZE, DST, SRC, OFF)            \
    ((struct bpf_insn) {                    \
        .code  = BPF_LDX | BPF_SIZE(SIZE) | BPF_MEM,    \
        .dst_reg = DST,                    \
        .src_reg = SRC,                    \
        .off   = OFF,                    \
        .imm   = 0 })

/* Memory store, *(uint *) (dst_reg + off16) = src_reg */

#define BPF_STX_MEM(SIZE, DST, SRC, OFF)            \
    ((struct bpf_insn) {                    \
        .code  = BPF_STX | BPF_SIZE(SIZE) | BPF_MEM,    \
        .dst_reg = DST,                    \
        .src_reg = SRC,                    \
        .off   = OFF,                    \
        .imm   = 0 })

/*
 * Atomic operations:
 *
 *   BPF_ADD                  *(uint *) (dst_reg + off16) += src_reg
 *   BPF_AND                  *(uint *) (dst_reg + off16) &= src_reg
 *   BPF_OR                   *(uint *) (dst_reg + off16) |= src_reg
 *   BPF_XOR                  *(uint *) (dst_reg + off16) ^= src_reg
 *   BPF_ADD | BPF_FETCH      src_reg = atomic_fetch_add(dst_reg + off16, src_reg);
 *   BPF_AND | BPF_FETCH      src_reg = atomic_fetch_and(dst_reg + off16, src_reg);
 *   BPF_OR | BPF_FETCH       src_reg = atomic_fetch_or(dst_reg + off16, src_reg);
 *   BPF_XOR | BPF_FETCH      src_reg = atomic_fetch_xor(dst_reg + off16, src_reg);
 *   BPF_XCHG                 src_reg = atomic_xchg(dst_reg + off16, src_reg)
 *   BPF_CMPXCHG              r0 = atomic_cmpxchg(dst_reg + off16, r0, src_reg)
 */

#define BPF_ATOMIC_OP(SIZE, OP, DST, SRC, OFF)            \
    ((struct bpf_insn) {                    \
        .code  = BPF_STX | BPF_SIZE(SIZE) | BPF_ATOMIC,    \
        .dst_reg = DST,                    \
        .src_reg = SRC,                    \
        .off   = OFF,                    \
        .imm   = OP })

/* Legacy alias */
#define BPF_STX_XADD(SIZE, DST, SRC, OFF) BPF_ATOMIC_OP(SIZE, BPF_ADD, DST, SRC, OFF)

/* Memory store, *(uint *) (dst_reg + off16) = imm32 */

#define BPF_ST_MEM(SIZE, DST, OFF, IMM)                \
    ((struct bpf_insn) {                    \
        .code  = BPF_ST | BPF_SIZE(SIZE) | BPF_MEM,    \
        .dst_reg = DST,                    \
        .src_reg = 0,                    \
        .off   = OFF,                    \
        .imm   = IMM })

/* Conditional jumps against registers, if (dst_reg 'op' src_reg) goto pc + off16 */

#define BPF_JMP_REG(OP, DST, SRC, OFF)                \
    ((struct bpf_insn) {                    \
        .code  = BPF_JMP | BPF_OP(OP) | BPF_X,        \
        .dst_reg = DST,                    \
        .src_reg = SRC,                    \
        .off   = OFF,                    \
        .imm   = 0 })

/* Like BPF_JMP_REG, but with 32-bit wide operands for comparison. */

#define BPF_JMP32_REG(OP, DST, SRC, OFF)            \
    ((struct bpf_insn) {                    \
        .code  = BPF_JMP32 | BPF_OP(OP) | BPF_X,    \
        .dst_reg = DST,                    \
        .src_reg = SRC,                    \
        .off   = OFF,                    \
        .imm   = 0 })

/* Conditional jumps against immediates, if (dst_reg 'op' imm32) goto pc + off16 */

#define BPF_JMP_IMM(OP, DST, IMM, OFF)                \
    ((struct bpf_insn) {                    \
        .code  = BPF_JMP | BPF_OP(OP) | BPF_K,        \
        .dst_reg = DST,                    \
        .src_reg = 0,                    \
        .off   = OFF,                    \
        .imm   = IMM })

/* Like BPF_JMP_IMM, but with 32-bit wide operands for comparison. */

#define BPF_JMP32_IMM(OP, DST, IMM, OFF)            \
    ((struct bpf_insn) {                    \
        .code  = BPF_JMP32 | BPF_OP(OP) | BPF_K,    \
        .dst_reg = DST,                    \
        .src_reg = 0,                    \
        .off   = OFF,                    \
        .imm   = IMM })

/* Raw code statement block */

#define BPF_RAW_INSN(CODE, DST, SRC, OFF, IMM)            \
    ((struct bpf_insn) {                    \
        .code  = CODE,                    \
        .dst_reg = DST,                    \
        .src_reg = SRC,                    \
        .off   = OFF,                    \
        .imm   = IMM })

/* Program exit */

#define BPF_EXIT_INSN()                        \
    ((struct bpf_insn) {                    \
        .code  = BPF_JMP | BPF_EXIT,            \
        .dst_reg = 0,                    \
        .src_reg = 0,                    \
        .off   = 0,                    \
        .imm   = 0 })

#endif /* _BPF_H_ */