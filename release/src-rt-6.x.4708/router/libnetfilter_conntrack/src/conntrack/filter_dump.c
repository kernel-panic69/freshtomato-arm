/*
 * (C) 2005-2012 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include "internal/internal.h"
#include <libmnl/libmnl.h>

static void
set_filter_dump_attr_mark(struct nfct_filter_dump *filter_dump,
			  const void *value)
{
	const struct nfct_filter_dump_mark *this = value;

	filter_dump->mark.val = this->val;
	filter_dump->mark.mask = this->mask;
}

static void
set_filter_dump_attr_status(struct nfct_filter_dump *filter_dump,
			    const void *value)
{
	const struct nfct_filter_dump_mark *this = value;

	filter_dump->status.val = this->val;
	filter_dump->status.mask = this->mask;
}

static void
set_filter_dump_attr_family(struct nfct_filter_dump *filter_dump,
			    const void *value)
{
	filter_dump->l3num = *((uint8_t *)value);
}

static void
set_filter_dump_attr_zone(struct nfct_filter_dump *filter_dump,
			    const void *value)
{
	filter_dump->zone = *((uint16_t *)value);
}

static void
set_filter_dump_attr_tuple(struct nfct_filter_dump *filter_dump,
			   const void *value)
{
	memcpy(&filter_dump->ct, value, sizeof(struct nf_conntrack));
}

const set_filter_dump_attr set_filter_dump_attr_array[NFCT_FILTER_DUMP_MAX] = {
	[NFCT_FILTER_DUMP_MARK]		= set_filter_dump_attr_mark,
	[NFCT_FILTER_DUMP_L3NUM]	= set_filter_dump_attr_family,
	[NFCT_FILTER_DUMP_STATUS]	= set_filter_dump_attr_status,
	[NFCT_FILTER_DUMP_ZONE]		= set_filter_dump_attr_zone,
	[NFCT_FILTER_DUMP_TUPLE]	= set_filter_dump_attr_tuple,
};

int __build_filter_dump(struct nfnlhdr *req, size_t size,
			const struct nfct_filter_dump *filter_dump)
{
	return nfct_nlmsg_build_filter(&req->nlh, filter_dump);
}

int __build_filter_flush(struct nfnlhdr *req, size_t size,
			const struct nfct_filter_dump *filter_dump)
{
	if (filter_dump->set & (1 << NFCT_FILTER_DUMP_TUPLE)) {
		errno = ENOTSUP;
		return -1;
	}
	return nfct_nlmsg_build_filter(&req->nlh, filter_dump);
}
