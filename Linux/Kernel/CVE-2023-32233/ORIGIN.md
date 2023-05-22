# Use-After-Free in Netfilter nf_tables when processing batch requests


## Vulnerability Details

The affected code originates from the official Linux kernel from
https://kernel.org/ and is part of the Netfilter nf_tables component
(net/netfilter/nf_tables_api.c).

Netfilter nf_tables allows to update its configuration as an atomic
operation. When using this feature, the user-mode clients send batch requests
containing a list of basic operations. Netfilter nf_tables then processes all
the operations within the batch as single transaction. When processing the
batch, Netfilter nf_tables then checks the configuration state updates to
ensure that each successive basic operation is valid and this also accounts
for the state updates from all the previous operations within the batch.
However, the currently implemented check is insufficient.

In our specific scenario we start with a Netfilter nf_tables configuration
that has an `nft_rule` with `lookup` expression on anonymous `nft_set`, and
where the anonymous `nft_set` contains some elements. Next, we send a batch
request containing the following two basic operations:

1. `NFT_MSG_DELRULE` operation to delete the `nft_rule`.  
    Note that this also implicitly deletes the `lookup` expression and the
    anonymous `nft_set`.
2. `NFT_MSG_DELSETELEM` operation to delete any of the elements of the
    deleted anonymous `nft_set`.

The current version of Netfilter nf_tables accepts the above batch request.
It then calls nf_tables_commit_release() that appends released resources to
`nf_tables_destroy_list`. The `nf_tables_destroy_list` is then processed by
nf_tables_trans_destroy_work() that first deallocates resources related to
`NFT_MSG_DELRULE` operation by calling:

    nft_commit_release()
        nf_tables_rule_destroy()
            nf_tables_expr_destroy()
                expr->ops->destroy() that points to nft_lookup_destroy()
                    nf_tables_destroy_set()
                        nft_set_destroy()
                            kvfree() that deallocates memory used by `nft_set`

before processing `NFT_MSG_DELSETELEM` operation, where reference to the
deallocated `nft_set` is accessed via nft_trans_elem_set() during the
following calls:

    nft_commit_release()
        nf_tables_set_elem_destroy()
            nft_set_elem_ext()

Within nft_set_elem_ext() above, the memory location of the deallocated
`nft_set` is accessed to determine location of `nft_set_ext`:

    static inline struct nft_set_ext *nft_set_elem_ext(const struct nft_set *set,
                                                       void *elem)
    {
            return elem + set->ops->elemsize;
    }

for the operations that follow. So whenever the value of `set->ops->elemsize`
gets corrupted, certain unexpected memory location could be interpreted as
list of `nft_expr` to be destroyed:

    static void nf_tables_set_elem_destroy(const struct nft_ctx *ctx,
                                           const struct nft_set *set, void *elem)
    {
            struct nft_set_ext *ext = nft_set_elem_ext(set, elem);
    
            if (nft_set_ext_exists(ext, NFT_SET_EXT_EXPRESSIONS))
                    nft_set_elem_expr_destroy(ctx, nft_set_ext_expr(ext));


## Exploitation Techniques

Exploiting the above vulnerability requires winning a race with
nf_tables_trans_destroy_work() that executes from background worker thread
from the Linux kernel. This seems to complicate practical exploitation even
before we consider existing mitigations, such as hardening of kernel slab
allocator, Kernel Address Space Layout Randomization (KASLR) and especially
Control-Flow Integrity. However, the attached PoC proves that it is still
possible to achieve reasonably reliable exploitation in practice.

In order to exploit the vulnerability we need to modify content of memory
from `nft_set` after it is deallocated under nf_tables_rule_destroy(), but
before it is used under nf_tables_set_elem_destroy(). Both
nf_tables_rule_destroy() and nf_tables_set_elem_destroy() are called within
single invocation of nf_tables_trans_destroy_work() that executes from
background worker thread from the Linux kernel. Further, the deallcated
memory chunk is usually available for reuse only from the same CPU core.

When racing with nf_tables_trans_destroy_work(), we improve our chances by
adding a controlled delay for the background worker thread between it calls
nf_tables_rule_destroy() and nf_tables_set_elem_destroy(). For that we insert
an additional operation to destroy another `nft_set` containing a large
number of elements. Additionally, we keep all the other CPU cores busy, such
that the background worker thread is likely to be scheduled on a specific CPU
core, so we can attempt to allocate a new structure from the same CPU core
just after it deallocates `nft_set` under nf_tables_rule_destroy(). Our goal
is to allocate a new `nft_set` of different type to reuse memory location of
the `nft_set` deallocated under nf_tables_rule_destroy().

The new `nft_set` type is selected to use a different value for
`set->ops->elemsize`. So when the background worker thread finally calls
nf_tables_set_elem_destroy() to process `NFT_MSG_DELSETELEM` operation, it
interprets its `elem` argument incorrectly, such that the corrupted
`nft_set_ext *ext` is a few bytes after the correct location. This means that
certain user-controlled data field of the original `nft_set_ext` are now
interpreted as headers, resulting with type confusion.

One way to abuse this type confusion is by crafting the corrupted
`nft_set_ext` headers with offsets values such that
nf_tables_set_elem_destroy() interprets content of any adjacent memory blocks
as the list of `nft_expr` to destroy via the following calls:

    nft_set_elem_expr_destroy()
        __nft_set_elem_expr_destroy()
            nf_tables_expr_destroy()
                expr->ops->destroy()

At this point of exploitation, we do not yet have details of the kernel
memory layout. So it is not possible to craft absolute pointer addresses.
However, when crafting the corrupted `nft_set_ext` headers we can still use
out-of-range offsets, such that `expr->ops->destroy()` is called on certain
valid `nft_expr` in the adjacent memory chunks.

For this we spray `nft_log` expressions, with controlled NFTA_LOG_PREFIX.
That `nft_log->prefix` is then deallocated by nft_log_destroy() once
`expr->ops->destroy()` is called:

    static void nft_log_destroy(const struct nft_ctx *ctx,
                                const struct nft_expr *expr)
    {
            struct nft_log *priv = nft_expr_priv(expr);
            struct nf_loginfo *li = &priv->loginfo;
    
            if (priv->prefix != nft_log_null_prefix)
                    kfree(priv->prefix);

Note that we can still access and even again deallocate this memory via the
other reference from the sprayed `nft_log` expression.

Additionally, we can also control the size of `nft_log->prefix`, such that it
can be allocated from any of the slabs kmalloc-{8, ..., 192}. Finally, the
refereed memory is interpreted as a string of characters by the kernel, so no
need to worry about corruptions when we overlay different objects over it.
This is essentially game over.

One inconvenience is that any NULL characters terminate `nft_log->prefix`, so
we cannot read past NULL bytes when leaking memory content. This is addressed
in the next step, where we allocate `nft_object->udata` to reuse
`nft_log->prefix` memory chunk and destroy the `nft_log` expression. This
deallocates `nft_object->udata` memory, but now we can still use the
`nft_object->udata` dangling pointer to leak memory content without
restrictions on NULL bytes.

Looking for suitable structures for the following steps, we decided on
`nft_expr` allocated from nft_dynset_new(). These live in the same slabs as
`nft_log->prefix` and `nft_object->udata`. And also, we have reasonable
control over the allocation size, such that later we could easily switch
between slabs of different size if needed.

To use these structures, we create packet filter with `nft_dynset`
expression. And when we send any packets over the loopback interface,
`nft_dynset` expression calls nft_dynset_new() to create new elements for the
associated `nft_set`. The created elements are stateful expressions of the
following types:

* `nft_counter` to obtain the location of `nf_tables.ko` in kernel memory.  
    The structure includes a pointer to `nft_counter_ops` in `nf_tables.ko`
    kernel module. We leak this pointer by reading `nft_object->udata`.
* `nft_quota` for arbitrary memory read and write.  
    We can repeatedly deallocate and reallocate `nft_object->udata` to modify
    the `nft_quota->consumed` pointer. Next, we perform `NFT_MSG_GETSETELEM`
    operation that calls nft_quota_do_dump() to read the content of the
    referenced memory and passes the result as `NFTA_QUOTA_CONSUMED`
    attribute in the result. As for writes, we simply send packets over the
    loopback interface, where nft_quota_do_eval() calls:

        static inline bool nft_overquota(struct nft_quota *priv,
                                         const struct sk_buff *skb)
        {
                return atomic64_add_return(skb->len, priv->consumed) >=

    to modify `nft_quota->consumed`.

We use the above arbitrary memory read to obtain base address of the kernel
core. And then we proceed to modify "sbin" substring of "/sbin/modprobe"
pathname, so it is replaced with "/tmp". The resulting pathname
"//tmp/modprobe" is then used by the kernel to start a process with root
privileges, where we control the file content.

Note that we didn't put any intentional effort to bypass Control-Flow
Integrity. However, for each of the exploitation steps, we consciously picked
the most flexible and the most robust primitives. Turns-out, that our
selection somehow avoided any of the primitives that could potentially be
blocked by Control-Flow Integrity. We are now curious to confirm with testing
that the resulting exploit really works against systems with Control-Flow
Integrity mitigations.
