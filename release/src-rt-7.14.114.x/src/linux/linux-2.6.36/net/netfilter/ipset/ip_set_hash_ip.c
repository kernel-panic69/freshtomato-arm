/* Copyright (C) 2003-2013 Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

/* Kernel module implementing an IP set type: the hash:ip type */

#include <linux/jhash.h>
#include <linux/module.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/errno.h>
#include <linux/random.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/netlink.h>
#include <net/tcp.h>

#include <linux/netfilter.h>
#include <linux/netfilter/ipset/pfxlen.h>
#include <linux/netfilter/ipset/ip_set.h>
#include <linux/netfilter/ipset/ip_set_hash.h>

#define REVISION_MIN	0
#define REVISION_MAX	0

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>");
IP_SET_MODULE_DESC("hash:ip", REVISION_MIN, REVISION_MAX);
MODULE_ALIAS("ip_set_hash:ip");

/* Type specific function prefix */
#define HTYPE		hash_ip
#define IP_SET_HASH_WITH_NETMASK

/* IPv4 variants */

/* Member elements */
struct hash_ip4_elem {
	/* Zero valued IP addresses cannot be stored */
	__be32 ip;
};

struct hash_ip4t_elem {
	__be32 ip;
	unsigned long timeout;
};

/* Common functions */

static inline bool
hash_ip4_data_equal(const struct hash_ip4_elem *e1,
		    const struct hash_ip4_elem *e2,
		    u32 *multi)
{
	return e1->ip == e2->ip;
}

static inline bool
hash_ip4_data_list(struct sk_buff *skb, const struct hash_ip4_elem *e)
{
	if (nla_put_ipaddr4(skb, IPSET_ATTR_IP, e->ip))
		goto nla_put_failure;
	return 0;

nla_put_failure:
	return 1;
}

static inline void
hash_ip4_data_next(struct hash_ip4_elem *next, const struct hash_ip4_elem *e)
{
	next->ip = e->ip;
}

#define MTYPE		hash_ip4
#define PF		4
#define HOST_MASK	32
#include "ip_set_hash_gen.h"

static int
hash_ip4_kadt(struct ip_set *set, const struct sk_buff *skb,
	      const struct xt_action_param *par,
	      enum ipset_adt adt, struct ip_set_adt_opt *opt)
{
	const struct hash_ip *h = set->data;
	ipset_adtfn adtfn = set->variant->adt[adt];
	struct hash_ip4_elem e = {};
	struct ip_set_ext ext = IP_SET_INIT_KEXT(skb, opt, h);
	__be32 ip;

	ip4addrptr(skb, opt->flags & IPSET_DIM_ONE_SRC, &ip);
	ip &= ip_set_netmask(h->netmask);
	if (ip == 0)
		return -EINVAL;

	e.ip = ip;
	return adtfn(set, &e, &ext, &opt->ext, opt->cmdflags);
}

static int
hash_ip4_uadt(struct ip_set *set, struct nlattr *tb[],
	      enum ipset_adt adt, u32 *lineno, u32 flags, bool retried)
{
	const struct hash_ip *h = set->data;
	ipset_adtfn adtfn = set->variant->adt[adt];
	struct hash_ip4_elem e = {};
	struct ip_set_ext ext = IP_SET_INIT_UEXT(h);
	u32 ip, ip_to, hosts;
	int ret = 0;

	if (unlikely(!tb[IPSET_ATTR_IP] ||
		     !ip_set_optattr_netorder(tb, IPSET_ATTR_TIMEOUT)))
		return -IPSET_ERR_PROTOCOL;

	if (tb[IPSET_ATTR_LINENO])
		*lineno = nla_get_u32(tb[IPSET_ATTR_LINENO]);

	ret = ip_set_get_hostipaddr4(tb[IPSET_ATTR_IP], &ip) ||
	      ip_set_get_extensions(set, tb, &ext);
	if (ret)
		return ret;

	ip &= ip_set_hostmask(h->netmask);

	if (adt == IPSET_TEST) {
		e.ip = htonl(ip);
		if (e.ip == 0)
			return -IPSET_ERR_HASH_ELEM;
		return adtfn(set, &e, &ext, &ext, flags);
	}

	ip_to = ip;
	if (tb[IPSET_ATTR_IP_TO]) {
		ret = ip_set_get_hostipaddr4(tb[IPSET_ATTR_IP_TO], &ip_to);
		if (ret)
			return ret;
		if (ip > ip_to)
			swap(ip, ip_to);
	} else if (tb[IPSET_ATTR_CIDR]) {
		u8 cidr = nla_get_u8(tb[IPSET_ATTR_CIDR]);

		if (!cidr || cidr > 32)
			return -IPSET_ERR_INVALID_CIDR;
		ip_set_mask_from_to(ip, ip_to, cidr);
	}

	hosts = h->netmask == 32 ? 1 : 2 << (32 - h->netmask - 1);

	if (retried)
		ip = ntohl(h->next.ip);
	for (; !before(ip_to, ip); ip += hosts) {
		e.ip = htonl(ip);
		if (e.ip == 0)
			return -IPSET_ERR_HASH_ELEM;
		ret = adtfn(set, &e, &ext, &ext, flags);

		if (ret && !ip_set_eexist(ret, flags))
			return ret;
		else
			ret = 0;
	}
	return ret;
}

/* IPv6 variants */

/* Member elements */
struct hash_ip6_elem {
	union nf_inet_addr ip;
};

struct hash_ip6t_elem {
	union nf_inet_addr ip;
	unsigned long timeout;
};

/* Common functions */

static inline bool
hash_ip6_data_equal(const struct hash_ip6_elem *ip1,
		    const struct hash_ip6_elem *ip2,
		    u32 *multi)
{
	return ipv6_addr_equal(&ip1->ip.in6, &ip2->ip.in6);
}

static inline void
hash_ip6_netmask(union nf_inet_addr *ip, u8 prefix)
{
	ip6_netmask(ip, prefix);
}

static bool
hash_ip6_data_list(struct sk_buff *skb, const struct hash_ip6_elem *e)
{
	if (nla_put_ipaddr6(skb, IPSET_ATTR_IP, &e->ip.in6))
		goto nla_put_failure;
	return 0;

nla_put_failure:
	return 1;
}

static inline void
hash_ip6_data_next(struct hash_ip4_elem *next, const struct hash_ip6_elem *e)
{
}

#undef MTYPE
#undef PF
#undef HOST_MASK
#undef HKEY_DATALEN

#define MTYPE		hash_ip6
#define PF		6
#define HOST_MASK	128

#define IP_SET_EMIT_CREATE
#include "ip_set_hash_gen.h"

static int
hash_ip6_kadt(struct ip_set *set, const struct sk_buff *skb,
	      const struct xt_action_param *par,
	      enum ipset_adt adt, struct ip_set_adt_opt *opt)
{
	const struct hash_ip *h = set->data;
	ipset_adtfn adtfn = set->variant->adt[adt];
	struct hash_ip6_elem e = {};
	struct ip_set_ext ext = IP_SET_INIT_KEXT(skb, opt, h);

	ip6addrptr(skb, opt->flags & IPSET_DIM_ONE_SRC, &e.ip.in6);
	hash_ip6_netmask(&e.ip, h->netmask);
	if (ipv6_addr_any(&e.ip.in6))
		return -EINVAL;

	return adtfn(set, &e, &ext, &opt->ext, opt->cmdflags);
}

static int
hash_ip6_uadt(struct ip_set *set, struct nlattr *tb[],
	      enum ipset_adt adt, u32 *lineno, u32 flags, bool retried)
{
	const struct hash_ip *h = set->data;
	ipset_adtfn adtfn = set->variant->adt[adt];
	struct hash_ip6_elem e = {};
	struct ip_set_ext ext = IP_SET_INIT_UEXT(h);
	int ret;

	if (unlikely(!tb[IPSET_ATTR_IP] ||
		     !ip_set_optattr_netorder(tb, IPSET_ATTR_TIMEOUT) ||
		     tb[IPSET_ATTR_IP_TO] ||
		     tb[IPSET_ATTR_CIDR]))
		return -IPSET_ERR_PROTOCOL;

	if (tb[IPSET_ATTR_LINENO])
		*lineno = nla_get_u32(tb[IPSET_ATTR_LINENO]);

	ret = ip_set_get_ipaddr6(tb[IPSET_ATTR_IP], &e.ip) ||
	      ip_set_get_extensions(set, tb, &ext);
	if (ret)
		return ret;

	hash_ip6_netmask(&e.ip, h->netmask);
	if (ipv6_addr_any(&e.ip.in6))
		return -IPSET_ERR_HASH_ELEM;

	ret = adtfn(set, &e, &ext, &ext, flags);

	return ip_set_eexist(ret, flags) ? 0 : ret;
}

static struct ip_set_type hash_ip_type __read_mostly = {
	.name		= "hash:ip",
	.protocol	= IPSET_PROTOCOL,
	.features	= IPSET_TYPE_IP,
	.dimension	= IPSET_DIM_ONE,
	.family		= NFPROTO_UNSPEC,
	.revision_min	= REVISION_MIN,
	.revision_max	= REVISION_MAX,
	.create		= hash_ip_create,
	.create_policy	= {
		[IPSET_ATTR_HASHSIZE]	= { .type = NLA_U32 },
		[IPSET_ATTR_MAXELEM]	= { .type = NLA_U32 },
		[IPSET_ATTR_PROBES]	= { .type = NLA_U8 },
		[IPSET_ATTR_RESIZE]	= { .type = NLA_U8  },
		[IPSET_ATTR_TIMEOUT]	= { .type = NLA_U32 },
		[IPSET_ATTR_NETMASK]	= { .type = NLA_U8  },
	},
	.adt_policy	= {
		[IPSET_ATTR_IP]		= { .type = NLA_NESTED },
		[IPSET_ATTR_IP_TO]	= { .type = NLA_NESTED },
		[IPSET_ATTR_CIDR]	= { .type = NLA_U8 },
		[IPSET_ATTR_TIMEOUT]	= { .type = NLA_U32 },
		[IPSET_ATTR_LINENO]	= { .type = NLA_U32 },
	},
	.me		= THIS_MODULE,
};

static int __init
hash_ip_init(void)
{
	return ip_set_type_register(&hash_ip_type);
}

static void __exit
hash_ip_fini(void)
{
	ip_set_type_unregister(&hash_ip_type);
}

module_init(hash_ip_init);
module_exit(hash_ip_fini);
