#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdexcept>

#include <cstdio>
#include <cstdlib>

#include <unistd.h>
#include <sched.h>

#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>

#include <libmnl/libmnl.h>

#include <libnftnl/table.h>
#include <libnftnl/chain.h>
#include <libnftnl/rule.h>
#include <libnftnl/object.h>
#include <libnftnl/set.h>
#include <libnftnl/expr.h>

#define ERROR(msg)                     \
    {                                  \
        perror("[-] " msg);            \
        throw std::runtime_error(msg); \
    }
#define INFO(fmt, ...)                                   \
    {                                                    \
        fprintf(stderr, "[*] " fmt "\n", ##__VA_ARGS__); \
    }

inline void hexdump(const std::string &s)
{
    for (unsigned char c: s) printf("%02x ", c);
    putchar('\n');
}

class NFExpr
{
public:
    NFExpr(const char *name) : ptr(nftnl_expr_alloc(name)) {}
    virtual ~NFExpr()
    {
        if (ptr != nullptr)
        {
            nftnl_expr_free(ptr);
            ptr = nullptr;
        }
    }

public:
    nftnl_expr *ptr;

public:
    friend class NFRule;
};

class NFImmediate : public NFExpr
{
public:
    NFImmediate() : NFExpr("immediate") {}
    NFImmediate &set_dreg(uint32_t dreg)
    {
        nftnl_expr_set_u32(ptr, NFTNL_EXPR_IMM_DREG, dreg);
        return *this;
    }
    NFImmediate &set_verdict(uint32_t verdict)
    {
        nftnl_expr_set_u32(ptr, NFTNL_EXPR_IMM_VERDICT, verdict);
        return *this;
    }
    NFImmediate &set_chain(const char *chain)
    {
        nftnl_expr_set_str(ptr, NFTNL_EXPR_IMM_CHAIN, chain);
        return *this;
    }
};

class NFObjRef : public NFExpr
{
public:
    NFObjRef() : NFExpr("objref") {}
    NFObjRef &set_set_id(uint32_t set_id)
    {
        nftnl_expr_set_u32(ptr, NFTNL_EXPR_OBJREF_SET_ID, set_id);
        return *this;
    }
    NFObjRef &set_set_name(const char *set_name)
    {
        nftnl_expr_set_str(ptr, NFTNL_EXPR_OBJREF_SET_NAME, set_name);
        return *this;
    }
    NFObjRef &set_set_sreg(uint32_t set_sreg)
    {
        nftnl_expr_set_u32(ptr, NFTNL_EXPR_OBJREF_SET_SREG, set_sreg);
        return *this;
    }
    NFObjRef &set_imm_name(const char *imm_name)
    {
        nftnl_expr_set_str(ptr, NFTNL_EXPR_OBJREF_IMM_NAME, imm_name);
        return *this;
    }
    NFObjRef &set_imm_type(uint32_t imm_type)
    {
        nftnl_expr_set_u32(ptr, NFTNL_EXPR_OBJREF_IMM_TYPE, imm_type);
        return *this;
    }
};

class NFTable
{
public:
    NFTable() : ptr(nftnl_table_alloc()) {}
    ~NFTable()
    {
        if (ptr != nullptr)
        {
            nftnl_table_free(ptr);
            ptr = nullptr;
        }
    }
    NFTable &set_name(const char *name)
    {
        nftnl_table_set_str(ptr, NFTNL_TABLE_NAME, name);
        return *this;
    }
    NFTable &set_family(uint32_t family)
    {
        nftnl_table_set_u32(ptr, NFTNL_TABLE_FAMILY, family);
        return *this;
    }

public:
    friend class NFBatch;
    nftnl_table *ptr;
};

class NFChain
{
public:
    NFChain() : ptr(nftnl_chain_alloc()) {}
    ~NFChain()
    {
        if (ptr != nullptr)
        {
            nftnl_chain_free(ptr);
            ptr = nullptr;
        }
    }
    NFChain &set_table(const char *table)
    {
        nftnl_chain_set_str(ptr, NFTNL_CHAIN_TABLE, table);
        return *this;
    }
    NFChain &set_name(const char *name)
    {
        nftnl_chain_set_str(ptr, NFTNL_CHAIN_NAME, name);
        return *this;
    }
    NFChain &set_flags(uint32_t flags)
    {
        nftnl_chain_set_u32(ptr, NFTNL_CHAIN_FLAGS, flags);
        return *this;
    }
    NFChain &set_hooknum(uint32_t hooknum)
    {
        nftnl_chain_set_u32(ptr, NFTNL_CHAIN_HOOKNUM, hooknum);
        return *this;
    }
    NFChain &set_priority(uint32_t priority)
    {
        nftnl_chain_set_u32(ptr, NFTNL_CHAIN_PRIO, priority);
        return *this;
    }

public:
    friend class NFBatch;
    nftnl_chain *ptr;
};

class NFRule
{
public:
    NFRule() : ptr(nftnl_rule_alloc()) {}
    ~NFRule()
    {
        if (ptr != nullptr)
        {
            nftnl_rule_free(ptr);
            ptr = nullptr;
        }
    }
    NFRule &set_table(const char *table)
    {
        nftnl_rule_set_str(ptr, NFTNL_RULE_TABLE, table);
        return *this;
    }
    NFRule &set_chain(const char *chain)
    {
        nftnl_rule_set_str(ptr, NFTNL_RULE_CHAIN, chain);
        return *this;
    }
    NFRule &set_family(uint32_t family)
    {
        nftnl_rule_set_u32(ptr, NFTNL_RULE_FAMILY, family);
        return *this;
    }
    NFRule &set_id(uint32_t id)
    {
        nftnl_rule_set_u32(ptr, NFTNL_RULE_ID, id);
        return *this;
    }
    NFRule &add_expr(NFExpr &expr)
    {
        nftnl_rule_add_expr(ptr, expr.ptr);
        expr.ptr = nullptr;
        return *this;
    }
    NFRule &set_udata(const void *udata, uint32_t udlen)
    {
        nftnl_rule_set_data(ptr, NFTNL_RULE_USERDATA, udata, udlen);
        return *this;
    }
    NFRule &set_handle(uint32_t handle)
    {
        nftnl_rule_set_u32(ptr, NFTNL_RULE_HANDLE, handle);
        return *this;
    }

public:
    friend class NFBatch;
    friend class NFChain;
    nftnl_rule *ptr;
};

class NFObject
{
public:
    NFObject() : ptr(nftnl_obj_alloc()) {}
    ~NFObject()
    {
        if (ptr != nullptr)
        {
            nftnl_obj_free(ptr);
            ptr = nullptr;
        }
    }
    NFObject &set_name(const char *name)
    {
        nftnl_obj_set_str(ptr, NFTNL_OBJ_NAME, name);
        return *this;
    }
    NFObject &set_family(uint32_t family)
    {
        nftnl_obj_set_u32(ptr, NFTNL_OBJ_FAMILY, family);
        return *this;
    }
    NFObject &set_table(const char *table)
    {
        nftnl_obj_set_str(ptr, NFTNL_OBJ_TABLE, table);
        return *this;
    }
    NFObject &set_type(uint32_t type)
    {
        nftnl_obj_set_u32(ptr, NFTNL_OBJ_TYPE, type);
        return *this;
    }
    NFObject &set_udata(const void *udata, uint32_t udlen)
    {
        nftnl_obj_set_data(ptr, NFTNL_OBJ_USERDATA, udata, udlen);
        return *this;
    }

public:
    nftnl_obj *ptr;
};

class NFSet
{
public:
    NFSet() : ptr(nftnl_set_alloc()) {}
    virtual ~NFSet()
    {
        if (ptr != nullptr)
        {
            nftnl_set_free(ptr);
            ptr = nullptr;
        }
    }
    NFSet &set_table(const char *table)
    {
        nftnl_set_set_str(ptr, NFTNL_SET_TABLE, table);
        return *this;
    }
    NFSet &set_name(const char *name)
    {
        nftnl_set_set_str(ptr, NFTNL_SET_NAME, name);
        return *this;
    }
    NFSet &set_family(uint32_t family)
    {
        nftnl_set_set_u32(ptr, NFTNL_SET_FAMILY, family);
        return *this;
    }
    NFSet &set_key_len(uint32_t len)
    {
        nftnl_set_set_u32(ptr, NFTNL_SET_KEY_LEN, len);
        return *this;
    }
    NFSet &set_id(uint32_t id)
    {
        nftnl_set_set_u32(ptr, NFTNL_SET_ID, id);
        return *this;
    }
    NFSet &set_udata(const void *udata, uint32_t udlen)
    {
        nftnl_set_set_data(ptr, NFTNL_SET_USERDATA, udata, udlen);
        return *this;
    }
    NFSet &set_flags(uint32_t flags)
    {
        nftnl_set_set_u32(ptr, NFTNL_SET_FLAGS, flags);
        return *this;
    }
    NFSet &set_obj_type(uint32_t obj_type)
    {
        nftnl_set_set_u32(ptr, NFTNL_SET_OBJ_TYPE, obj_type);
        return *this;
    }

public:
    friend class NFBatch;
    nftnl_set *ptr;
};

class MNLSocket
{
public:
    MNLSocket(int bus) : ptr(mnl_socket_open(bus))
    {
        if (ptr == nullptr)
            ERROR("mnl_socket_open");

        if (mnl_socket_bind(ptr, 0, MNL_SOCKET_AUTOPID) < 0)
            ERROR("mnl_socket_bind");
    }
    ~MNLSocket()
    {
        if (ptr != nullptr)
        {
            mnl_socket_close(ptr);
            ptr = nullptr;
        }
    }
    int send(const void *buf, size_t size)
    {
        return mnl_socket_sendto(ptr, buf, size);
    }
    int recv(void *buf, size_t size)
    {
        return mnl_socket_recvfrom(ptr, buf, size);
    }
    unsigned int portid()
    {
        return mnl_socket_get_portid(ptr);
    }
    void run_cb(uint32_t seq, mnl_cb_t cb, void *cb_data)
    {
        int ret;
        char buf[MNL_SOCKET_BUFFER_SIZE];
        do
        {
            if ((ret = recv(buf, sizeof(buf))) < 0)
                ERROR("nl.recv");
        } while ((ret = mnl_cb_run(buf, ret, seq, portid(), cb, cb_data)) > 0);
        if (ret < 0)
            ERROR("mnl_cb_run");
    }

public:
    mnl_socket *ptr;
};

class MNLBatch
{
public:
    MNLBatch() : ptr(mnl_nlmsg_batch_start(buf, sizeof(buf))) {}
    ~MNLBatch()
    {
        if (ptr != nullptr)
        {
            mnl_nlmsg_batch_stop(ptr);
            ptr = nullptr;
        }
    }
    bool next()
    {
        return mnl_nlmsg_batch_next(ptr);
    }
    void *current()
    {
        return mnl_nlmsg_batch_current(ptr);
    }
    void *head()
    {
        return mnl_nlmsg_batch_head(ptr);
    }
    size_t size()
    {
        return mnl_nlmsg_batch_size(ptr);
    }

private:
    char buf[4096];
    mnl_nlmsg_batch *ptr;
};

class NFBatch
{
public:
    NFBatch &start()
    {
        nftnl_batch_begin((char *)current(), 0);
        next();
        start_seq = cur_seq = 1;
        return *this;
    }
    void end()
    {
        nftnl_batch_end((char *)current(), cur_seq);
        next();
    }
    bool next()
    {
        return mnl.next();
    }
    void *current()
    {
        return mnl.current();
    }
    void *head()
    {
        return mnl.head();
    }
    size_t size()
    {
        return mnl.size();
    }
    NFBatch &add(const NFTable &table)
    {
        auto nlh = nftnl_nlmsg_build_hdr((char *)current(), NFT_MSG_NEWTABLE, NFPROTO_INET, NLM_F_ACK | NLM_F_CREATE, cur_seq++);
        nftnl_table_nlmsg_build_payload(nlh, table.ptr);
        next();
        return *this;
    }
    NFBatch &del(const NFTable &table)
    {
        auto nlh = nftnl_nlmsg_build_hdr((char *)current(), NFT_MSG_DELTABLE, NFPROTO_INET, NLM_F_ACK, cur_seq++);
        nftnl_table_nlmsg_build_payload(nlh, table.ptr);
        next();
        return *this;
    }
    NFBatch &add(const NFChain &chain)
    {
        auto nlh = nftnl_nlmsg_build_hdr((char *)current(), NFT_MSG_NEWCHAIN, NFPROTO_INET, NLM_F_ACK | NLM_F_CREATE, cur_seq++);
        nftnl_chain_nlmsg_build_payload(nlh, chain.ptr);
        next();
        return *this;
    }
    NFBatch &del(const NFChain &chain)
    {
        auto nlh = nftnl_nlmsg_build_hdr((char *)current(), NFT_MSG_DELCHAIN, NFPROTO_INET, NLM_F_ACK, cur_seq++);
        nftnl_chain_nlmsg_build_payload(nlh, chain.ptr);
        next();
        return *this;
    }
    NFBatch &add(const NFRule &rule)
    {
        auto nlh = nftnl_nlmsg_build_hdr((char *)current(), NFT_MSG_NEWRULE, NFPROTO_INET, NLM_F_ACK | NLM_F_CREATE, cur_seq++);
        nftnl_rule_nlmsg_build_payload(nlh, rule.ptr);
        next();
        return *this;
    }
    NFBatch &del(const NFRule &rule)
    {
        auto nlh = nftnl_nlmsg_build_hdr((char *)current(), NFT_MSG_DELRULE, NFPROTO_INET, NLM_F_ACK, cur_seq++);
        nftnl_rule_nlmsg_build_payload(nlh, rule.ptr);
        next();
        return *this;
    }
    NFBatch &add(const NFObject &object)
    {
        auto nlh = nftnl_nlmsg_build_hdr((char *)current(), NFT_MSG_NEWOBJ, NFPROTO_INET, NLM_F_ACK | NLM_F_CREATE, cur_seq++);
        nftnl_obj_nlmsg_build_payload(nlh, object.ptr);
        next();
        return *this;
    }
    NFBatch &del(const NFObject &object)
    {
        auto nlh = nftnl_nlmsg_build_hdr((char *)current(), NFT_MSG_DELOBJ, NFPROTO_INET, NLM_F_ACK, cur_seq++);
        nftnl_obj_nlmsg_build_payload(nlh, object.ptr);
        next();
        return *this;
    }
    NFBatch &add(const NFSet &set)
    {
        auto nlh = nftnl_nlmsg_build_hdr((char *)current(), NFT_MSG_NEWSET, NFPROTO_INET, NLM_F_ACK | NLM_F_CREATE, cur_seq++);
        nftnl_set_nlmsg_build_payload(nlh, set.ptr);
        next();
        return *this;
    }
    NFBatch &del(const NFSet &set)
    {
        auto nlh = nftnl_nlmsg_build_hdr((char *)current(), NFT_MSG_DELSET, NFPROTO_INET, NLM_F_ACK, cur_seq++);
        nftnl_set_nlmsg_build_payload(nlh, set.ptr);
        next();
        return *this;
    }
    void send(MNLSocket &nl)
    {
        if (nl.send(head(), size()) < 0)
            ERROR("nl.send");
    }
    void run_all_cb(MNLSocket &nl)
    {
        for (; start_seq < cur_seq; ++start_seq)
            nl.run_cb(start_seq, nullptr, nullptr);
    }

private:
    uint32_t start_seq;
    uint32_t cur_seq;
    MNLBatch mnl;
};

class NFDumper
{
public:
    static void dump(const NFRule &rule, MNLSocket &nl, mnl_cb_t cb, void *cb_data)
    {
        nlmsghdr *nlh;
        char buf[MNL_SOCKET_BUFFER_SIZE];

        nlh = nftnl_nlmsg_build_hdr(buf, NFT_MSG_GETRULE, NFPROTO_INET, NLM_F_DUMP, 0x1337);
        nftnl_rule_nlmsg_build_payload(nlh, rule.ptr);

        if (nl.send(nlh, nlh->nlmsg_len) < 0)
            ERROR("nl.send");

        nl.run_cb(0x1337, cb, cb_data);
    }
};
