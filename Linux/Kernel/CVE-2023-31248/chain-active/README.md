## CVE-2023-31248

`nft_chain` can be looked up by name, handle or ID. Let's go through the functions that do the job.

Lookup by name:

```c
static struct nft_chain *nft_chain_lookup(struct net *net,
					  struct nft_table *table,
					  const struct nlattr *nla, u8 genmask)
{
	char search[NFT_CHAIN_MAXNAMELEN + 1];
	struct rhlist_head *tmp, *list;
	struct nft_chain *chain;

	if (nla == NULL)
		return ERR_PTR(-EINVAL);

	nla_strscpy(search, nla, sizeof(search));

	WARN_ON(!rcu_read_lock_held() &&
		!lockdep_commit_lock_is_held(net));

	chain = ERR_PTR(-ENOENT);
	rcu_read_lock();
	list = rhltable_lookup(&table->chains_ht, search, nft_chain_ht_params);
	if (!list)
		goto out_unlock;

	rhl_for_each_entry_rcu(chain, tmp, list, rhlhead) {
		if (nft_active_genmask(chain, genmask))
			goto out_unlock;
	}
	chain = ERR_PTR(-ENOENT);
out_unlock:
	rcu_read_unlock();
	return chain;
}
```

Lookup by handle:

```c
static struct nft_chain *
nft_chain_lookup_byhandle(const struct nft_table *table, u64 handle, u8 genmask)
{
	struct nft_chain *chain;

	list_for_each_entry(chain, &table->chains, list) {
		if (chain->handle == handle &&
		    nft_active_genmask(chain, genmask))
			return chain;
	}

	return ERR_PTR(-ENOENT);
}
```

Lookup by ID:

```c
static struct nft_chain *nft_chain_lookup_byid(const struct net *net,
					       const struct nft_table *table,
					       const struct nlattr *nla)
{
	struct nftables_pernet *nft_net = nft_pernet(net);
	u32 id = ntohl(nla_get_be32(nla));
	struct nft_trans *trans;

	list_for_each_entry(trans, &nft_net->commit_list, list) {
		struct nft_chain *chain = trans->ctx.chain;

		if (trans->msg_type == NFT_MSG_NEWCHAIN &&
		    chain->table == table &&
		    id == nft_trans_chain_id(trans))
			return chain;
	}
	return ERR_PTR(-ENOENT);
}
```

In both `nft_chain_lookup` and `nft_chain_lookup_byhandle`, they check if the chain is active by calling `nft_active_genmask`. A chain will be deactivated if the user send a `DELETE` message for that chain. This check ensures that another object will not be able to refer to a deactivated chain. However in `nft_chain_lookup_byid`, the check will not be conducted. That means we can refer to a deactivated chain. But at cleanup stage, if `chain->use` is not `0`, a warning will be issued and the chain won't be freed. We must find a way to make a reference to a deactivated chain while still satisfy the condition to free it.

Netfilter transaction will not free the deleted objects when commiting. Instead, Netfilter will run a deferred task to delete it later. Therefore, we can achieve Use-After-Free condition like this:

Batch 1:

- Create table
- Create chain `victim`
- Mark chain `victim` as deleted
- Create chain `attack`
- Create rule belong to `attack` chain, with a `nft_immediate` expression refer to `victim` by ID => `victim->use == 1`
- Commit the batch => Cleanup task will be queued

Batch 2:

- Mark the rule we created in the previous batch as deleted => `victim->use == 0`
- Wait for the cleanup task to complete => `victim` will be freed
- Fail the batch using some invalid input => the rule will not be marked as deleted anymore

The `nft_immediate` expression in the rule still refer to the freed chain. We have achieved Use-After-Free condition. From here we can spray fake chain object to leak (using `nft_immediate` dump function) or to execute code (need to create fake rule and fake expression as well to call expression ops). This primitive can be used multiple times reliably.
