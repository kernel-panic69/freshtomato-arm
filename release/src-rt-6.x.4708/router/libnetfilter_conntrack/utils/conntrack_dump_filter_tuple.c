#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

static int cb(const struct nlmsghdr *nlh,
	      enum nf_conntrack_msg_type type,
	      struct nf_conntrack *ct,
	      void *data)
{
	char buf[1024];

	if (!(nlh->nlmsg_flags & NLM_F_DUMP_FILTERED))
	  {
	    fprintf(stderr, "No filtering in kernel, do filtering in userspace\n");
	    return NFCT_CB_FAILURE;
	  }

	nfct_snprintf(buf, sizeof(buf), ct, NFCT_T_UNKNOWN, NFCT_O_DEFAULT, NFCT_OF_SHOW_LAYER3 | NFCT_OF_TIMESTAMP);
	printf("%s\n", buf);

	return NFCT_CB_CONTINUE;
}

int main(void)
{
	int ret;
	struct nfct_handle *h;

	h = nfct_open(CONNTRACK, 0);
	if (!h) {
		perror("nfct_open");
		return -1;
	}
	struct nfct_filter_dump *filter_dump = nfct_filter_dump_create();
	if (filter_dump == NULL) {
		perror("nfct_filter_dump_alloc");
		return -1;
	}

	struct nf_conntrack	*ct;
	ct = nfct_new();
	if (!ct) {
		perror("nfct_new");
		return 0;
	}

	nfct_set_attr_u8(ct, ATTR_ORIG_L3PROTO, AF_INET);
	nfct_set_attr_u8(ct, ATTR_L4PROTO, IPPROTO_ICMP);
	nfct_set_attr_u32(ct, ATTR_ORIG_IPV4_DST, inet_addr("203.0.113.55"));
	nfct_filter_dump_set_attr(filter_dump, NFCT_FILTER_DUMP_TUPLE, ct);

	nfct_callback_register2(h, NFCT_T_ALL, cb, NULL);
	ret = nfct_query(h, NFCT_Q_DUMP_FILTER, filter_dump);

	nfct_filter_dump_destroy(filter_dump);

	printf("TEST: get conntrack ");
	if (ret == -1)
		printf("(%d)(%s)\n", ret, strerror(errno));
	else
		printf("(OK)\n");

	nfct_close(h);

	ret == -1 ? exit(EXIT_FAILURE) : exit(EXIT_SUCCESS);
}
