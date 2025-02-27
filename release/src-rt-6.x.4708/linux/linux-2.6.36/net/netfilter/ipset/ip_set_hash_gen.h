/* Copyright (C) 2013 Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef _IP_SET_HASH_GEN_H
#define _IP_SET_HASH_GEN_H

#include <linux/rcupdate.h>
#include <linux/jhash.h>
#include <linux/netfilter/ipset/ip_set_timeout.h>
#ifndef rcu_dereference_bh
#define rcu_dereference_bh(p)	rcu_dereference(p)
#endif

#define rcu_dereference_bh_nfnl(p)	rcu_dereference_bh_check(p, 1)

#define CONCAT(a, b)		a##b
#define TOKEN(a, b)		CONCAT(a, b)

/* Hashing which uses arrays to resolve clashing. The hash table is resized
 * (doubled) when searching becomes too long.
 * Internally jhash is used with the assumption that the size of the
 * stored data is a multiple of sizeof(u32). If storage supports timeout,
 * the timeout field must be the last one in the data structure - that field
 * is ignored when computing the hash key.
 *
 * Readers and resizing
 *
 * Resizing can be triggered by userspace command only, and those
 * are serialized by the nfnl mutex. During resizing the set is
 * read-locked, so the only possible concurrent operations are
 * the kernel side readers. Those must be protected by proper RCU locking.
 */

/* Number of elements to store in an initial array block */
#define AHASH_INIT_SIZE			4
/* Max number of elements to store in an array block */
#define AHASH_MAX_SIZE			(3*AHASH_INIT_SIZE)

/* Max number of elements can be tuned */
#ifdef IP_SET_HASH_WITH_MULTI
#define AHASH_MAX(h)			((h)->ahash_max)

static inline u8
tune_ahash_max(u8 curr, u32 multi)
{
	u32 n;

	if (multi < curr)
		return curr;

	n = curr + AHASH_INIT_SIZE;
	/* Currently, at listing one hash bucket must fit into a message.
	 * Therefore we have a hard limit here.
	 */
	return n > curr && n <= 64 ? n : curr;
}
#define TUNE_AHASH_MAX(h, multi)	\
	((h)->ahash_max = tune_ahash_max((h)->ahash_max, multi))
#else
#define AHASH_MAX(h)			AHASH_MAX_SIZE
#define TUNE_AHASH_MAX(h, multi)
#endif

/* A hash bucket */
struct hbucket {
	void *value;		/* the array of the values */
	u8 size;		/* size of the array */
	u8 pos;			/* position of the first free entry */
};

/* The hash table: the table size stored here in order to make resizing easy */
struct htable {
	u8 htable_bits;		/* size of hash table == 2^htable_bits */
	struct hbucket bucket[0]; /* hashtable buckets */
};

#define hbucket(h, i)		(&((h)->bucket[i]))

/* Book-keeping of the prefixes added to the set */
struct net_prefixes {
	u8 cidr;		/* the different cidr values in the set */
	u32 nets;		/* number of elements per cidr */
};

/* Compute the hash table size */
static size_t
htable_size(u8 hbits)
{
	size_t hsize;

	/* We must fit both into u32 in jhash and size_t */
	if (hbits > 31)
		return 0;
	hsize = jhash_size(hbits);
	if ((((size_t)-1) - sizeof(struct htable))/sizeof(struct hbucket)
	    < hsize)
		return 0;

	return hsize * sizeof(struct hbucket) + sizeof(struct htable);
}

/* Compute htable_bits from the user input parameter hashsize */
static u8
htable_bits(u32 hashsize)
{
	/* Assume that hashsize == 2^htable_bits */
	u8 bits = fls(hashsize - 1);
	if (jhash_size(bits) != hashsize)
		/* Round up to the first 2^n value */
		bits = fls(hashsize);

	return bits;
}

/* Destroy the hashtable part of the set */
static void
ahash_destroy(struct htable *t)
{
	struct hbucket *n;
	u32 i;

	for (i = 0; i < jhash_size(t->htable_bits); i++) {
		n = hbucket(t, i);
		if (n->size)
			/* FIXME: use slab cache */
			kfree(n->value);
	}

	ip_set_free(t);
}

static int
hbucket_elem_add(struct hbucket *n, u8 ahash_max, size_t dsize)
{
	if (n->pos >= n->size) {
		void *tmp;

		if (n->size >= ahash_max)
			/* Trigger rehashing */
			return -EAGAIN;

		tmp = kzalloc((n->size + AHASH_INIT_SIZE) * dsize,
			      GFP_ATOMIC);
		if (!tmp)
			return -ENOMEM;
		if (n->size) {
			memcpy(tmp, n->value, n->size * dsize);
			kfree(n->value);
		}
		n->value = tmp;
		n->size += AHASH_INIT_SIZE;
	}
	return 0;
}

#ifdef IP_SET_HASH_WITH_NETS
#ifdef IP_SET_HASH_WITH_NETS_PACKED
/* When cidr is packed with nomatch, cidr - 1 is stored in the entry */
#define CIDR(cidr)		(cidr + 1)
#else
#define CIDR(cidr)		(cidr)
#endif

#define SET_HOST_MASK(family)	(family == AF_INET ? 32 : 128)

#ifdef IP_SET_HASH_WITH_MULTI
#define NETS_LENGTH(family)	(SET_HOST_MASK(family) + 1)
#else
#define NETS_LENGTH(family)	SET_HOST_MASK(family)
#endif

#else
#define NETS_LENGTH(family)	0
#endif /* IP_SET_HASH_WITH_NETS */

#define ext_timeout(e, h)	\
(unsigned long *)(((void *)(e)) + (h)->offset[IPSET_OFFSET_TIMEOUT])

#endif /* _IP_SET_HASH_GEN_H */

/* Family dependent templates */

#undef ahash_data
#undef mtype_data_equal
#undef mtype_do_data_match
#undef mtype_data_set_flags
#undef mtype_data_reset_flags
#undef mtype_data_netmask
#undef mtype_data_list
#undef mtype_data_next
#undef mtype_elem

#undef mtype_add_cidr
#undef mtype_del_cidr
#undef mtype_ahash_memsize
#undef mtype_flush
#undef mtype_destroy
#undef mtype_gc_init
#undef mtype_same_set
#undef mtype_kadt
#undef mtype_uadt
#undef mtype

#undef mtype_add
#undef mtype_del
#undef mtype_test_cidrs
#undef mtype_test
#undef mtype_expire
#undef mtype_resize
#undef mtype_head
#undef mtype_list
#undef mtype_gc
#undef mtype_gc_init
#undef mtype_variant
#undef mtype_data_match

#undef HKEY

#define mtype_data_equal	TOKEN(MTYPE, _data_equal)
#ifdef IP_SET_HASH_WITH_NETS
#define mtype_do_data_match	TOKEN(MTYPE, _do_data_match)
#else
#define mtype_do_data_match(d)	1
#endif
#define mtype_data_set_flags	TOKEN(MTYPE, _data_set_flags)
#define mtype_data_reset_flags	TOKEN(MTYPE, _data_reset_flags)
#define mtype_data_netmask	TOKEN(MTYPE, _data_netmask)
#define mtype_data_list		TOKEN(MTYPE, _data_list)
#define mtype_data_next		TOKEN(MTYPE, _data_next)
#define mtype_elem		TOKEN(MTYPE, _elem)
#define mtype_add_cidr		TOKEN(MTYPE, _add_cidr)
#define mtype_del_cidr		TOKEN(MTYPE, _del_cidr)
#define mtype_ahash_memsize	TOKEN(MTYPE, _ahash_memsize)
#define mtype_flush		TOKEN(MTYPE, _flush)
#define mtype_destroy		TOKEN(MTYPE, _destroy)
#define mtype_gc_init		TOKEN(MTYPE, _gc_init)
#define mtype_same_set		TOKEN(MTYPE, _same_set)
#define mtype_kadt		TOKEN(MTYPE, _kadt)
#define mtype_uadt		TOKEN(MTYPE, _uadt)
#define mtype			MTYPE

#define mtype_elem		TOKEN(MTYPE, _elem)
#define mtype_add		TOKEN(MTYPE, _add)
#define mtype_del		TOKEN(MTYPE, _del)
#define mtype_test_cidrs	TOKEN(MTYPE, _test_cidrs)
#define mtype_test		TOKEN(MTYPE, _test)
#define mtype_expire		TOKEN(MTYPE, _expire)
#define mtype_resize		TOKEN(MTYPE, _resize)
#define mtype_head		TOKEN(MTYPE, _head)
#define mtype_list		TOKEN(MTYPE, _list)
#define mtype_gc		TOKEN(MTYPE, _gc)
#define mtype_variant		TOKEN(MTYPE, _variant)
#define mtype_data_match	TOKEN(MTYPE, _data_match)

#ifndef HKEY_DATALEN
#define HKEY_DATALEN		sizeof(struct mtype_elem)
#endif

#define HKEY(data, initval, htable_bits)			\
(jhash2((u32 *)(data), HKEY_DATALEN/sizeof(u32), initval)	\
	& jhash_mask(htable_bits))

#ifndef htype
#define htype			HTYPE

/* The generic hash structure */
struct htype {
	struct htable __rcu *table; /* the hash table */
	u32 maxelem;		/* max elements in the hash */
	u32 elements;		/* current element (vs timeout) */
	u32 initval;		/* random jhash init value */
	u32 timeout;		/* timeout value, if enabled */
	size_t dsize;		/* data struct size */
	size_t offset[IPSET_OFFSET_MAX]; /* Offsets to extensions */
	struct timer_list gc;	/* garbage collection when timeout enabled */
	struct mtype_elem next; /* temporary storage for uadd */
#ifdef IP_SET_HASH_WITH_MULTI
	u8 ahash_max;		/* max elements in an array block */
#endif
#ifdef IP_SET_HASH_WITH_NETMASK
	u8 netmask;		/* netmask value for subnets to store */
#endif
#ifdef IP_SET_HASH_WITH_RBTREE
	struct rb_root rbtree;
#endif
#ifdef IP_SET_HASH_WITH_NETS
	struct net_prefixes nets[0]; /* book-keeping of prefixes */
#endif
};
#endif

#ifdef IP_SET_HASH_WITH_NETS
/* Network cidr size book keeping when the hash stores different
 * sized networks */
static void
mtype_add_cidr(struct htype *h, u8 cidr, u8 nets_length)
{
	int i, j;

	/* Add in increasing prefix order, so larger cidr first */
	for (i = 0, j = -1; i < nets_length && h->nets[i].nets; i++) {
		if (j != -1)
			continue;
		else if (h->nets[i].cidr < cidr)
			j = i;
		else if (h->nets[i].cidr == cidr) {
			h->nets[i].nets++;
			return;
		}
	}
	if (j != -1) {
		for (; i > j; i--) {
			h->nets[i].cidr = h->nets[i - 1].cidr;
			h->nets[i].nets = h->nets[i - 1].nets;
		}
	}
	h->nets[i].cidr = cidr;
	h->nets[i].nets = 1;
}

static void
mtype_del_cidr(struct htype *h, u8 cidr, u8 nets_length)
{
	u8 i, j, net_end = nets_length - 1;

	for (i = 0; i < nets_length; i++) {
	        if (h->nets[i].cidr != cidr)
	                continue;
                if (h->nets[i].nets > 1 || i == net_end ||
                    h->nets[i + 1].nets == 0) {
                        h->nets[i].nets--;
                        return;
                }
                for (j = i; j < net_end && h->nets[j].nets; j++) {
		        h->nets[j].cidr = h->nets[j + 1].cidr;
		        h->nets[j].nets = h->nets[j + 1].nets;
                }
                h->nets[j].nets = 0;
                return;
	}
}
#endif

/* Calculate the actual memory size of the set data */
static size_t
mtype_ahash_memsize(const struct htype *h, const struct htable *t,
		    u8 nets_length)
{
	u32 i;
	size_t memsize = sizeof(*h)
			 + sizeof(*t)
#ifdef IP_SET_HASH_WITH_NETS
			 + sizeof(struct net_prefixes) * nets_length
#endif
			 + jhash_size(t->htable_bits) * sizeof(struct hbucket);

	for (i = 0; i < jhash_size(t->htable_bits); i++)
		memsize += t->bucket[i].size * h->dsize;

	return memsize;
}

/* Flush a hash type of set: destroy all elements */
static void
mtype_flush(struct ip_set *set)
{
	struct htype *h = set->data;
	struct htable *t;
	struct hbucket *n;
	u32 i;

	t = rcu_dereference_bh_nfnl(h->table);
	for (i = 0; i < jhash_size(t->htable_bits); i++) {
		n = hbucket(t, i);
		if (n->size) {
			n->size = n->pos = 0;
			/* FIXME: use slab cache */
			kfree(n->value);
		}
	}
#ifdef IP_SET_HASH_WITH_NETS
	memset(h->nets, 0, sizeof(struct net_prefixes)
			   * NETS_LENGTH(set->family));
#endif
	h->elements = 0;
}

/* Destroy a hash type of set */
static void
mtype_destroy(struct ip_set *set)
{
	struct htype *h = set->data;

	if (set->extensions & IPSET_EXT_TIMEOUT)
		del_timer_sync(&h->gc);

	ahash_destroy(rcu_dereference_bh_nfnl(h->table));
#ifdef IP_SET_HASH_WITH_RBTREE
	rbtree_destroy(&h->rbtree);
#endif
	kfree(h);

	set->data = NULL;
}

static void
mtype_gc_init(struct ip_set *set, void (*gc)(unsigned long ul_set))
{
	struct htype *h = set->data;

	init_timer(&h->gc);
	h->gc.data = (unsigned long) set;
	h->gc.function = gc;
	h->gc.expires = jiffies + IPSET_GC_PERIOD(h->timeout) * HZ;
	add_timer(&h->gc);
	pr_debug("gc initialized, run in every %u\n",
		 IPSET_GC_PERIOD(h->timeout));
}

static bool
mtype_same_set(const struct ip_set *a, const struct ip_set *b)
{
	const struct htype *x = a->data;
	const struct htype *y = b->data;

	/* Resizing changes htable_bits, so we ignore it */
	return x->maxelem == y->maxelem &&
	       x->timeout == y->timeout &&
#ifdef IP_SET_HASH_WITH_NETMASK
	       x->netmask == y->netmask &&
#endif
	       a->extensions == b->extensions;
}

/* Get the ith element from the array block n */
#define ahash_data(n, i, dsize)	\
	((struct mtype_elem *)((n)->value + ((i) * (dsize))))

/* Delete expired elements from the hashtable */
static void
mtype_expire(struct htype *h, u8 nets_length, size_t dsize)
{
	struct htable *t;
	struct hbucket *n;
	struct mtype_elem *data;
	u32 i;
	int j;

	rcu_read_lock_bh();
	t = rcu_dereference_bh(h->table);
	for (i = 0; i < jhash_size(t->htable_bits); i++) {
		n = hbucket(t, i);
		for (j = 0; j < n->pos; j++) {
			data = ahash_data(n, j, dsize);
			if (ip_set_timeout_expired(ext_timeout(data, h))) {
				pr_debug("expired %u/%u\n", i, j);
#ifdef IP_SET_HASH_WITH_NETS
				mtype_del_cidr(h, CIDR(data->cidr),
					       nets_length);
#endif
				if (j != n->pos - 1)
					/* Not last one */
					memcpy(data,
					       ahash_data(n, n->pos - 1, dsize),
					       dsize);
				n->pos--;
				h->elements--;
			}
		}
		if (n->pos + AHASH_INIT_SIZE < n->size) {
			void *tmp = kzalloc((n->size - AHASH_INIT_SIZE)
					    * dsize,
					    GFP_ATOMIC);
			if (!tmp)
				/* Still try to delete expired elements */
				continue;
			n->size -= AHASH_INIT_SIZE;
			memcpy(tmp, n->value, n->size * dsize);
			kfree(n->value);
			n->value = tmp;
		}
	}
	rcu_read_unlock_bh();
}

static void
mtype_gc(unsigned long ul_set)
{
	struct ip_set *set = (struct ip_set *) ul_set;
	struct htype *h = set->data;

	pr_debug("called\n");
	write_lock_bh(&set->lock);
	mtype_expire(h, NETS_LENGTH(set->family), h->dsize);
	write_unlock_bh(&set->lock);

	h->gc.expires = jiffies + IPSET_GC_PERIOD(h->timeout) * HZ;
	add_timer(&h->gc);
}

/* Resize a hash: create a new hash table with doubling the hashsize
 * and inserting the elements to it. Repeat until we succeed or
 * fail due to memory pressures. */
static int
mtype_resize(struct ip_set *set, bool retried)
{
	struct htype *h = set->data;
	struct htable *t, *orig = rcu_dereference_bh_nfnl(h->table);
	u8 htable_bits = orig->htable_bits;
#ifdef IP_SET_HASH_WITH_NETS
	u8 flags;
#endif
	struct mtype_elem *data;
	struct mtype_elem *d;
	struct hbucket *n, *m;
	u32 i, j;
	int ret;

	/* Try to cleanup once */
	if (SET_WITH_TIMEOUT(set) && !retried) {
		i = h->elements;
		write_lock_bh(&set->lock);
		mtype_expire(set->data, NETS_LENGTH(set->family),
			     h->dsize);
		write_unlock_bh(&set->lock);
		if (h->elements < i)
			return 0;
	}

retry:
	ret = 0;
	htable_bits++;
	pr_debug("attempt to resize set %s from %u to %u, t %p\n",
		 set->name, orig->htable_bits, htable_bits, orig);
	if (!htable_bits) {
		/* In case we have plenty of memory :-) */
		pr_warning("Cannot increase the hashsize of set %s further\n",
			   set->name);
		return -IPSET_ERR_HASH_FULL;
	}
	t = ip_set_alloc(sizeof(*t)
			 + jhash_size(htable_bits) * sizeof(struct hbucket));
	if (!t)
		return -ENOMEM;
	t->htable_bits = htable_bits;

	read_lock_bh(&set->lock);
	for (i = 0; i < jhash_size(orig->htable_bits); i++) {
		n = hbucket(orig, i);
		for (j = 0; j < n->pos; j++) {
			data = ahash_data(n, j, h->dsize);
#ifdef IP_SET_HASH_WITH_NETS
			flags = 0;
			mtype_data_reset_flags(data, &flags);
#endif
			m = hbucket(t, HKEY(data, h->initval, htable_bits));
			ret = hbucket_elem_add(m, AHASH_MAX(h), h->dsize);
			if (ret < 0) {
#ifdef IP_SET_HASH_WITH_NETS
				mtype_data_reset_flags(data, &flags);
#endif
				read_unlock_bh(&set->lock);
				ahash_destroy(t);
				if (ret == -EAGAIN)
					goto retry;
				return ret;
			}
			d = ahash_data(m, m->pos++, h->dsize);
			memcpy(d, data, h->dsize);
#ifdef IP_SET_HASH_WITH_NETS
			mtype_data_reset_flags(d, &flags);
#endif
		}
	}

	rcu_assign_pointer(h->table, t);
	read_unlock_bh(&set->lock);

	/* Give time to other readers of the set */
	synchronize_rcu_bh();

	pr_debug("set %s resized from %u (%p) to %u (%p)\n", set->name,
		 orig->htable_bits, orig, t->htable_bits, t);
	ahash_destroy(orig);

	return 0;
}

/* Add an element to a hash and update the internal counters when succeeded,
 * otherwise report the proper error code. */
static int
mtype_add(struct ip_set *set, void *value, const struct ip_set_ext *ext,
	  struct ip_set_ext *mext, u32 flags)
{
	struct htype *h = set->data;
	struct htable *t;
	const struct mtype_elem *d = value;
	struct mtype_elem *data;
	struct hbucket *n;
	int i, ret = 0;
	int j = AHASH_MAX(h) + 1;
	bool flag_exist = flags & IPSET_FLAG_EXIST;
	u32 key, multi = 0;

	if (SET_WITH_TIMEOUT(set) && h->elements >= h->maxelem)
		/* FIXME: when set is full, we slow down here */
		mtype_expire(h, NETS_LENGTH(set->family), h->dsize);

	if (h->elements >= h->maxelem) {
		if (net_ratelimit())
			pr_warning("Set %s is full, maxelem %u reached\n",
				   set->name, h->maxelem);
		return -IPSET_ERR_HASH_FULL;
	}

	rcu_read_lock_bh();
	t = rcu_dereference_bh(h->table);
	key = HKEY(value, h->initval, t->htable_bits);
	n = hbucket(t, key);
	for (i = 0; i < n->pos; i++) {
		data = ahash_data(n, i, h->dsize);
		if (mtype_data_equal(data, d, &multi)) {
			if (flag_exist ||
			    (SET_WITH_TIMEOUT(set) &&
			     ip_set_timeout_expired(ext_timeout(data, h)))) {
				/* Just the extensions could be overwritten */
				j = i;
				goto reuse_slot;
			} else {
				ret = -IPSET_ERR_EXIST;
				goto out;
			}
		}
		/* Reuse first timed out entry */
		if (SET_WITH_TIMEOUT(set) &&
		    ip_set_timeout_expired(ext_timeout(data, h)) &&
		    j != AHASH_MAX(h) + 1)
			j = i;
	}
reuse_slot:
	if (j != AHASH_MAX(h) + 1) {
		/* Fill out reused slot */
		data = ahash_data(n, j, h->dsize);
#ifdef IP_SET_HASH_WITH_NETS
		mtype_del_cidr(h, CIDR(data->cidr), NETS_LENGTH(set->family));
		mtype_add_cidr(h, CIDR(d->cidr), NETS_LENGTH(set->family));
#endif
	} else {
		/* Use/create a new slot */
		TUNE_AHASH_MAX(h, multi);
		ret = hbucket_elem_add(n, AHASH_MAX(h), h->dsize);
		if (ret != 0) {
			if (ret == -EAGAIN)
				mtype_data_next(&h->next, d);
			goto out;
		}
		data = ahash_data(n, n->pos++, h->dsize);
#ifdef IP_SET_HASH_WITH_NETS
		mtype_add_cidr(h, CIDR(d->cidr), NETS_LENGTH(set->family));
#endif
		h->elements++;
	}
	memcpy(data, d, sizeof(struct mtype_elem));
#ifdef IP_SET_HASH_WITH_NETS
	mtype_data_set_flags(data, flags);
#endif
	if (SET_WITH_TIMEOUT(set))
		ip_set_timeout_set(ext_timeout(data, h), ext->timeout);

out:
	rcu_read_unlock_bh();
	return ret;
}

/* Delete an element from the hash: swap it with the last element
 * and free up space if possible.
 */
static int
mtype_del(struct ip_set *set, void *value, const struct ip_set_ext *ext,
	  struct ip_set_ext *mext, u32 flags)
{
	struct htype *h = set->data;
	struct htable *t;
	const struct mtype_elem *d = value;
	struct mtype_elem *data;
	struct hbucket *n;
	int i, ret = -IPSET_ERR_EXIST;
	u32 key, multi = 0;

	rcu_read_lock_bh();
	t = rcu_dereference_bh(h->table);
	key = HKEY(value, h->initval, t->htable_bits);
	n = hbucket(t, key);
	for (i = 0; i < n->pos; i++) {
		data = ahash_data(n, i, h->dsize);
		if (!mtype_data_equal(data, d, &multi))
			continue;
		if (SET_WITH_TIMEOUT(set) &&
		    ip_set_timeout_expired(ext_timeout(data, h)))
			goto out;
		if (i != n->pos - 1)
			/* Not last one */
			memcpy(data, ahash_data(n, n->pos - 1, h->dsize),
			       h->dsize);

		n->pos--;
		h->elements--;
#ifdef IP_SET_HASH_WITH_NETS
		mtype_del_cidr(h, CIDR(d->cidr), NETS_LENGTH(set->family));
#endif
		if (n->pos + AHASH_INIT_SIZE < n->size) {
			void *tmp = kzalloc((n->size - AHASH_INIT_SIZE)
					    * h->dsize,
					    GFP_ATOMIC);
			if (!tmp) {
				ret = 0;
				goto out;
			}
			n->size -= AHASH_INIT_SIZE;
			memcpy(tmp, n->value, n->size * h->dsize);
			kfree(n->value);
			n->value = tmp;
		}
		ret = 0;
		goto out;
	}

out:
	rcu_read_unlock_bh();
	return ret;
}

static inline int
mtype_data_match(struct mtype_elem *data, const struct ip_set_ext *ext,
		 struct ip_set_ext *mext, struct ip_set *set, u32 flags)
{
	return mtype_do_data_match(data);
}

#ifdef IP_SET_HASH_WITH_NETS
/* Special test function which takes into account the different network
 * sizes added to the set */
static int
mtype_test_cidrs(struct ip_set *set, struct mtype_elem *d,
		 const struct ip_set_ext *ext,
		 struct ip_set_ext *mext, u32 flags)
{
	struct htype *h = set->data;
	struct htable *t = rcu_dereference_bh(h->table);
	struct hbucket *n;
	struct mtype_elem *data;
	int i, j = 0;
	u32 key, multi = 0;
	u8 nets_length = NETS_LENGTH(set->family);

	pr_debug("test by nets\n");
	for (; j < nets_length && h->nets[j].nets && !multi; j++) {
		mtype_data_netmask(d, h->nets[j].cidr);
		key = HKEY(d, h->initval, t->htable_bits);
		n = hbucket(t, key);
		for (i = 0; i < n->pos; i++) {
			data = ahash_data(n, i, h->dsize);
			if (!mtype_data_equal(data, d, &multi))
				continue;
			if (SET_WITH_TIMEOUT(set)) {
				if (!ip_set_timeout_expired(
							ext_timeout(data, h)))
					return mtype_data_match(data, ext,
								mext, set,
								flags);
#ifdef IP_SET_HASH_WITH_MULTI
				multi = 0;
#endif
			} else
				return mtype_data_match(data, ext,
							mext, set, flags);
		}
	}
	return 0;
}
#endif

/* Test whether the element is added to the set */
static int
mtype_test(struct ip_set *set, void *value, const struct ip_set_ext *ext,
	   struct ip_set_ext *mext, u32 flags)
{
	struct htype *h = set->data;
	struct htable *t;
	struct mtype_elem *d = value;
	struct hbucket *n;
	struct mtype_elem *data;
	int i, ret = 0;
	u32 key, multi = 0;

	rcu_read_lock_bh();
	t = rcu_dereference_bh(h->table);
#ifdef IP_SET_HASH_WITH_NETS
	/* If we test an IP address and not a network address,
	 * try all possible network sizes */
	if (CIDR(d->cidr) == SET_HOST_MASK(set->family)) {
		ret = mtype_test_cidrs(set, d, ext, mext, flags);
		goto out;
	}
#endif

	key = HKEY(d, h->initval, t->htable_bits);
	n = hbucket(t, key);
	for (i = 0; i < n->pos; i++) {
		data = ahash_data(n, i, h->dsize);
		if (mtype_data_equal(data, d, &multi) &&
		    !(SET_WITH_TIMEOUT(set) &&
		      ip_set_timeout_expired(ext_timeout(data, h)))) {
			ret = mtype_data_match(data, ext, mext, set, flags);
			goto out;
		}
	}
out:
	rcu_read_unlock_bh();
	return ret;
}

/* Reply a HEADER request: fill out the header part of the set */
static int
mtype_head(struct ip_set *set, struct sk_buff *skb)
{
	const struct htype *h = set->data;
	const struct htable *t;
	struct nlattr *nested;
	size_t memsize;

	t = rcu_dereference_bh_nfnl(h->table);
	memsize = mtype_ahash_memsize(h, t, NETS_LENGTH(set->family));

	nested = ipset_nest_start(skb, IPSET_ATTR_DATA);
	if (!nested)
		goto nla_put_failure;
	if (nla_put_net32(skb, IPSET_ATTR_HASHSIZE,
			  htonl(jhash_size(t->htable_bits))) ||
	    nla_put_net32(skb, IPSET_ATTR_MAXELEM, htonl(h->maxelem)))
		goto nla_put_failure;
#ifdef IP_SET_HASH_WITH_NETMASK
	if (h->netmask != HOST_MASK &&
	    nla_put_u8(skb, IPSET_ATTR_NETMASK, h->netmask))
		goto nla_put_failure;
#endif
	if (nla_put_net32(skb, IPSET_ATTR_REFERENCES, htonl(set->ref - 1)) ||
	    nla_put_net32(skb, IPSET_ATTR_MEMSIZE, htonl(memsize)) ||
	    ((set->extensions & IPSET_EXT_TIMEOUT) &&
	     nla_put_net32(skb, IPSET_ATTR_TIMEOUT, htonl(h->timeout))))
		goto nla_put_failure;
	ipset_nest_end(skb, nested);

	return 0;
nla_put_failure:
	return -EMSGSIZE;
}

/* Reply a LIST/SAVE request: dump the elements of the specified set */
static int
mtype_list(const struct ip_set *set,
	   struct sk_buff *skb, struct netlink_callback *cb)
{
	const struct htype *h = set->data;
	const struct htable *t = rcu_dereference_bh_nfnl(h->table);
	struct nlattr *atd, *nested;
	const struct hbucket *n;
	const struct mtype_elem *e;
	u32 first = cb->args[2];
	/* We assume that one hash bucket fills into one page */
	void *incomplete;
	int i;

	atd = ipset_nest_start(skb, IPSET_ATTR_ADT);
	if (!atd)
		return -EMSGSIZE;
	pr_debug("list hash set %s\n", set->name);
	for (; cb->args[2] < jhash_size(t->htable_bits); cb->args[2]++) {
		incomplete = skb_tail_pointer(skb);
		n = hbucket(t, cb->args[2]);
		pr_debug("cb->args[2]: %lu, t %p n %p\n", cb->args[2], t, n);
		for (i = 0; i < n->pos; i++) {
			e = ahash_data(n, i, h->dsize);
			if (SET_WITH_TIMEOUT(set) &&
			    ip_set_timeout_expired(ext_timeout(e, h)))
				continue;
			pr_debug("list hash %lu hbucket %p i %u, data %p\n",
				 cb->args[2], n, i, e);
			nested = ipset_nest_start(skb, IPSET_ATTR_DATA);
			if (!nested) {
				if (cb->args[2] == first) {
					nla_nest_cancel(skb, atd);
					return -EMSGSIZE;
				} else
					goto nla_put_failure;
			}
			if (mtype_data_list(skb, e))
				goto nla_put_failure;
			if (SET_WITH_TIMEOUT(set) &&
			    nla_put_net32(skb, IPSET_ATTR_TIMEOUT,
					  htonl(ip_set_timeout_get(
						ext_timeout(e, h)))))
				goto nla_put_failure;
			ipset_nest_end(skb, nested);
		}
	}
	ipset_nest_end(skb, atd);
	/* Set listing finished */
	cb->args[2] = 0;

	return 0;

nla_put_failure:
	nlmsg_trim(skb, incomplete);
	if (unlikely(first == cb->args[2])) {
		pr_warning("Can't list set %s: one bucket does not fit into "
			   "a message. Please report it!\n", set->name);
		cb->args[2] = 0;
		return -EMSGSIZE;
	}
	ipset_nest_end(skb, atd);
	return 0;
}

static int
TOKEN(MTYPE, _kadt)(struct ip_set *set, const struct sk_buff *skb,
	      const struct xt_action_param *par,
	      enum ipset_adt adt, struct ip_set_adt_opt *opt);

static int
TOKEN(MTYPE, _uadt)(struct ip_set *set, struct nlattr *tb[],
	      enum ipset_adt adt, u32 *lineno, u32 flags, bool retried);

static const struct ip_set_type_variant mtype_variant = {
	.kadt	= mtype_kadt,
	.uadt	= mtype_uadt,
	.adt	= {
		[IPSET_ADD] = mtype_add,
		[IPSET_DEL] = mtype_del,
		[IPSET_TEST] = mtype_test,
	},
	.destroy = mtype_destroy,
	.flush	= mtype_flush,
	.head	= mtype_head,
	.list	= mtype_list,
	.resize	= mtype_resize,
	.same_set = mtype_same_set,
};

#ifdef IP_SET_EMIT_CREATE
static int
TOKEN(HTYPE, _create)(struct ip_set *set, struct nlattr *tb[], u32 flags)
{
	u32 hashsize = IPSET_DEFAULT_HASHSIZE, maxelem = IPSET_DEFAULT_MAXELEM;
	u8 hbits;
#ifdef IP_SET_HASH_WITH_NETMASK
	u8 netmask;
#endif
	size_t hsize;
	struct HTYPE *h;
	struct htable *t;

	if (!(set->family == NFPROTO_IPV4 || set->family == NFPROTO_IPV6))
		return -IPSET_ERR_INVALID_FAMILY;
#ifdef IP_SET_HASH_WITH_NETMASK
	netmask = set->family == NFPROTO_IPV4 ? 32 : 128;
	pr_debug("Create set %s with family %s\n",
		 set->name, set->family == NFPROTO_IPV4 ? "inet" : "inet6");
#endif

	if (unlikely(!ip_set_optattr_netorder(tb, IPSET_ATTR_HASHSIZE) ||
		     !ip_set_optattr_netorder(tb, IPSET_ATTR_MAXELEM) ||
		     !ip_set_optattr_netorder(tb, IPSET_ATTR_TIMEOUT) ||
		     !ip_set_optattr_netorder(tb, IPSET_ATTR_CADT_FLAGS)))
		return -IPSET_ERR_PROTOCOL;

	if (tb[IPSET_ATTR_HASHSIZE]) {
		hashsize = ip_set_get_h32(tb[IPSET_ATTR_HASHSIZE]);
		if (hashsize < IPSET_MIMINAL_HASHSIZE)
			hashsize = IPSET_MIMINAL_HASHSIZE;
	}

	if (tb[IPSET_ATTR_MAXELEM])
		maxelem = ip_set_get_h32(tb[IPSET_ATTR_MAXELEM]);

#ifdef IP_SET_HASH_WITH_NETMASK
	if (tb[IPSET_ATTR_NETMASK]) {
		netmask = nla_get_u8(tb[IPSET_ATTR_NETMASK]);

		if ((set->family == NFPROTO_IPV4 && netmask > 32) ||
		    (set->family == NFPROTO_IPV6 && netmask > 128) ||
		    netmask == 0)
			return -IPSET_ERR_INVALID_NETMASK;
	}
#endif

	hsize = sizeof(*h);
#ifdef IP_SET_HASH_WITH_NETS
	hsize += sizeof(struct net_prefixes) *
		(set->family == NFPROTO_IPV4 ? 32 : 128);
#endif
	h = kzalloc(hsize, GFP_KERNEL);
	if (!h)
		return -ENOMEM;

	h->maxelem = maxelem;
#ifdef IP_SET_HASH_WITH_NETMASK
	h->netmask = netmask;
#endif
	get_random_bytes(&h->initval, sizeof(h->initval));
	h->timeout = IPSET_NO_TIMEOUT;

	hbits = htable_bits(hashsize);
	hsize = htable_size(hbits);
	if (hsize == 0) {
		kfree(h);
		return -ENOMEM;
	}
	t = ip_set_alloc(hsize);
	if (!t) {
		kfree(h);
		return -ENOMEM;
	}
	t->htable_bits = hbits;
	rcu_assign_pointer(h->table, t);

	set->data = h;
	if (set->family ==  NFPROTO_IPV4)
		set->variant = &TOKEN(HTYPE, 4_variant);
	else
		set->variant = &TOKEN(HTYPE, 6_variant);

	if (tb[IPSET_ATTR_TIMEOUT]) {
		h->timeout = ip_set_timeout_uget(tb[IPSET_ATTR_TIMEOUT]);
		set->extensions |= IPSET_EXT_TIMEOUT;
		if (set->family == NFPROTO_IPV4) {
			h->dsize = sizeof(struct TOKEN(HTYPE, 4t_elem));
			h->offset[IPSET_OFFSET_TIMEOUT] =
				offsetof(struct TOKEN(HTYPE, 4t_elem),
					 timeout);
			TOKEN(HTYPE, 4_gc_init)(set, TOKEN(HTYPE, 4_gc));
		} else {
			h->dsize = sizeof(struct TOKEN(HTYPE, 6t_elem));
			h->offset[IPSET_OFFSET_TIMEOUT] =
				offsetof(struct TOKEN(HTYPE, 6t_elem),
					 timeout);
			TOKEN(HTYPE, 6_gc_init)(set, TOKEN(HTYPE, 6_gc));
		}
	} else {
		if (set->family == NFPROTO_IPV4)
			h->dsize = sizeof(struct TOKEN(HTYPE, 4_elem));
		else
			h->dsize = sizeof(struct TOKEN(HTYPE, 6_elem));
	}

	pr_debug("create %s hashsize %u (%u) maxelem %u: %p(%p)\n",
		 set->name, jhash_size(t->htable_bits),
		 t->htable_bits, h->maxelem, set->data, t);

	return 0;
}
#endif /* IP_SET_EMIT_CREATE */
