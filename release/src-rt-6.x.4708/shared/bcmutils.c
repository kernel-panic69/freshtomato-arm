/*
 * Driver O/S-independent utility routines
 *
 * Copyright (C) 2015, Broadcom Corporation. All Rights Reserved.
 * 
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 * $Id: bcmutils.c 419467 2013-08-21 09:19:48Z $
 */

#include <bcm_cfg.h>
#include <typedefs.h>
#include <bcmdefs.h>
#if defined(__FreeBSD__) || defined(__NetBSD__)
#include <sys/param.h>
#if __NetBSD_Version__ >= 500000003
#include <sys/stdarg.h>
#else
#include <machine/stdarg.h>
#endif
#else
#include <stdarg.h>
#endif /* NetBSD */
#ifdef BCMDRIVER

#include <osl.h>
#include <bcmutils.h>
#include <siutils.h>
#include <bcmnvram.h>

#else /* !BCMDRIVER */

#include <stdio.h>
#include <string.h>
#include <bcmutils.h>

#if defined(BCMEXTSUP)
#include <bcm_osl.h>
#endif


#endif /* !BCMDRIVER */

#if defined(_WIN32) || defined(NDIS) || defined(__vxworks) || defined(_CFE_)
#include <bcmstdlib.h>
#endif
#include <bcmendian.h>
#include <bcmdevs.h>
#include <proto/ethernet.h>
#include <proto/vlan.h>
#include <proto/bcmip.h>
#include <proto/802.1d.h>
#include <proto/802.11.h>
#ifdef BCMPERFSTATS
#include <bcmperf.h>
#endif
#include <proto/bcmipv6.h>
void *_bcmutils_dummy_fn = NULL;

#ifdef BCMDRIVER

#ifdef WLC_LOW
/* nvram vars cache */
static char *nvram_vars = NULL;
static int vars_len = -1;
#endif /* WLC_LOW */

int
BCMATTACHFN(pktpool_init)(osl_t *osh, pktpool_t *pktp, int *pplen, int plen, bool istx)
{
	int i, err = BCME_OK;
	void *p;
	int pktplen;

	ASSERT(pktp != NULL);
	ASSERT(osh != NULL);
	ASSERT(pplen != NULL);

	pktplen = *pplen;

	bzero(pktp, sizeof(pktpool_t));
	pktp->inited = TRUE;
	pktp->istx = istx ? TRUE : FALSE;
	pktp->plen = (uint16)plen;
	*pplen = 0;

	pktp->maxlen = PKTPOOL_LEN_MAX;
	if (pktplen > pktp->maxlen)
		pktplen = pktp->maxlen;

	for (i = 0; i < pktplen; i++) {
		p = PKTGET(osh, plen, pktp->istx);
		if (p == NULL) {
			/* Not able to allocate all requested pkts
			 * so just return what was actually allocated
			 * We can add to the pool later
			 */
			if (pktp->w == 0)
				err = BCME_NOMEM;

			goto exit;
		}

		PKTSETPOOL(osh, p, TRUE, pktp);
		pktp->q[i] = p;
		pktp->w++;
		pktp->len++;
#ifdef BCMDBG_POOL
		pktp->dbg_q[pktp->dbg_qlen++].p = p;
#endif
	}

exit:
	*pplen = pktp->w;
	pktp->len++; /* Add one for end */
	return err;
}

int
BCMATTACHFN(pktpool_deinit)(osl_t *osh, pktpool_t *pktp)
{
	int i;
	int cnt;

	ASSERT(osh != NULL);
	ASSERT(pktp != NULL);

	cnt = pktp->len;
	for (i = 0; i < cnt; i++) {
		if (pktp->q[i] != NULL) {
			PKTSETPOOL(osh, pktp->q[i], FALSE, NULL);
			PKTFREE(osh, pktp->q[i], pktp->istx);
			pktp->q[i] = NULL;
			pktp->len--;
		}
#ifdef BCMDBG_POOL
		if (pktp->dbg_q[i].p != NULL)
			pktp->dbg_q[i].p = NULL;
#endif
	}
	pktp->inited = FALSE;

	/* Are there still pending pkts? */
	ASSERT(pktpool_len(pktp) == 0);

	return 0;
}

int
pktpool_fill(osl_t *osh, pktpool_t *pktp, bool minimal)
{
	void *p;
	int err = 0;
	int len, psize, maxlen;

	ASSERT(pktpool_plen(pktp) != 0);

	maxlen = pktpool_maxlen(pktp);
	psize = minimal ? (maxlen >> 2) : maxlen;
	len = pktpool_len(pktp);
	for (; len < psize; len++) {
		p = PKTGET(osh, pktpool_plen(pktp), FALSE);
		if (p == NULL) {
			err = BCME_NOMEM;
			break;
		}

		if (pktpool_add(pktp, p) != BCME_OK) {
			PKTFREE(osh, p, FALSE);
			err = BCME_ERROR;
			break;
		}
	}

	return err;
}

uint16
pktpool_avail(pktpool_t *pktp)
{
	if (pktp->w == pktp->r)
		return 0;

	return (pktp->w > pktp->r) ? (pktp->w - pktp->r) : ((pktp->len) - (pktp->r - pktp->w));
}

static void *
pktpool_deq(pktpool_t *pktp)
{
	void *p;

	if (pktp->r == pktp->w)
		return NULL;

	p = pktp->q[pktp->r];
	ASSERT(p != NULL);

	pktp->q[pktp->r++] = NULL;
	pktp->r %= (pktp->len);

	return p;
}

static void
pktpool_enq(pktpool_t *pktp, void *p)
{
	uint16 next;

	ASSERT(p != NULL);

	next = (pktp->w + 1) % (pktp->len);
	if (next == pktp->r) {
	/* Should not happen; otherwise pkt leak */
		ASSERT(0);
		return;
	}

	ASSERT(pktp->q[pktp->w] == NULL);

	pktp->q[pktp->w] = p;
	pktp->w = next;
}

int
BCMATTACHFN(pktpool_avail_register)(pktpool_t *pktp, pktpool_cb_t cb, void *arg)
{
	int i;

	ASSERT(cb != NULL);

	i = pktp->cbcnt;
	if (i == PKTPOOL_CB_MAX)
		return BCME_ERROR;

	ASSERT(pktp->cbs[i].cb == NULL);
	pktp->cbs[i].cb = cb;
	pktp->cbs[i].arg = arg;
	pktp->cbcnt++;

	return 0;
}

int
BCMATTACHFN(pktpool_empty_register)(pktpool_t *pktp, pktpool_cb_t cb, void *arg)
{
	int i;

	ASSERT(cb != NULL);

	i = pktp->ecbcnt;
	if (i == PKTPOOL_CB_MAX)
		return BCME_ERROR;

	ASSERT(pktp->ecbs[i].cb == NULL);
	pktp->ecbs[i].cb = cb;
	pktp->ecbs[i].arg = arg;
	pktp->ecbcnt++;

	return 0;
}

static int
pktpool_empty_notify(pktpool_t *pktp)
{
	int i;

	pktp->empty = TRUE;
	for (i = 0; i < pktp->ecbcnt; i++) {
		ASSERT(pktp->ecbs[i].cb != NULL);
		pktp->ecbs[i].cb(pktp, pktp->ecbs[i].arg);
	}
	pktp->empty = FALSE;

	return 0;
}

#ifdef BCMDBG_POOL
int
pktpool_dbg_register(pktpool_t *pktp, pktpool_cb_t cb, void *arg)
{
	int i;

	ASSERT(cb);

	i = pktp->dbg_cbcnt;
	if (i == PKTPOOL_CB_MAX)
		return BCME_ERROR;

	ASSERT(pktp->dbg_cbs[i].cb == NULL);
	pktp->dbg_cbs[i].cb = cb;
	pktp->dbg_cbs[i].arg = arg;
	pktp->dbg_cbcnt++;

	return 0;
}

int pktpool_dbg_notify(pktpool_t *pktp);

int
pktpool_dbg_notify(pktpool_t *pktp)
{
	int i;

	for (i = 0; i < pktp->dbg_cbcnt; i++) {
		ASSERT(pktp->dbg_cbs[i].cb);
		pktp->dbg_cbs[i].cb(pktp, pktp->dbg_cbs[i].arg);
	}

	return 0;
}

int
pktpool_dbg_dump(pktpool_t *pktp)
{
	int i;

	printf("pool len=%d maxlen=%d\n",  pktp->dbg_qlen, pktp->maxlen);
	for (i = 0; i < pktp->dbg_qlen; i++) {
		ASSERT(pktp->dbg_q[i].p);
		printf("%d, p: 0x%x dur:%lu us state:%d\n", i,
			pktp->dbg_q[i].p, pktp->dbg_q[i].dur/100, PKTPOOLSTATE(pktp->dbg_q[i].p));
	}

	return 0;
}

int
pktpool_stats_dump(pktpool_t *pktp, pktpool_stats_t *stats)
{
	int i;
	int state;

	bzero(stats, sizeof(pktpool_stats_t));
	for (i = 0; i < pktp->dbg_qlen; i++) {
		ASSERT(pktp->dbg_q[i].p != NULL);

		state = PKTPOOLSTATE(pktp->dbg_q[i].p);
		switch (state) {
			case POOL_TXENQ:
				stats->enq++; break;
			case POOL_TXDH:
				stats->txdh++; break;
			case POOL_TXD11:
				stats->txd11++; break;
			case POOL_RXDH:
				stats->rxdh++; break;
			case POOL_RXD11:
				stats->rxd11++; break;
			case POOL_RXFILL:
				stats->rxfill++; break;
			case POOL_IDLE:
				stats->idle++; break;
		}
	}

	return 0;
}

int
pktpool_start_trigger(pktpool_t *pktp, void *p)
{
	uint32 cycles, i;

	if (!PKTPOOL(NULL, p))
		return 0;

	OSL_GETCYCLES(cycles);

	for (i = 0; i < pktp->dbg_qlen; i++) {
		ASSERT(pktp->dbg_q[i].p != NULL);

		if (pktp->dbg_q[i].p == p) {
			pktp->dbg_q[i].cycles = cycles;
			break;
		}
	}

	return 0;
}

int pktpool_stop_trigger(pktpool_t *pktp, void *p);
int
pktpool_stop_trigger(pktpool_t *pktp, void *p)
{
	uint32 cycles, i;

	if (!PKTPOOL(NULL, p))
		return 0;

	OSL_GETCYCLES(cycles);

	for (i = 0; i < pktp->dbg_qlen; i++) {
		ASSERT(pktp->dbg_q[i].p != NULL);

		if (pktp->dbg_q[i].p == p) {
			if (pktp->dbg_q[i].cycles == 0)
				break;

			if (cycles >= pktp->dbg_q[i].cycles)
				pktp->dbg_q[i].dur = cycles - pktp->dbg_q[i].cycles;
			else
				pktp->dbg_q[i].dur =
					(((uint32)-1) - pktp->dbg_q[i].cycles) + cycles + 1;

			pktp->dbg_q[i].cycles = 0;
			break;
		}
	}

	return 0;
}
#endif /* BCMDBG_POOL */

int
pktpool_avail_notify_normal(osl_t *osh, pktpool_t *pktp)
{
	ASSERT(pktp);
	pktp->availcb_excl = NULL;
	return 0;
}

int
pktpool_avail_notify_exclusive(osl_t *osh, pktpool_t *pktp, pktpool_cb_t cb)
{
	int i;

	ASSERT(pktp);
	ASSERT(pktp->availcb_excl == NULL);
	for (i = 0; i < pktp->cbcnt; i++) {
		if (cb == pktp->cbs[i].cb) {
			pktp->availcb_excl = &pktp->cbs[i];
			break;
		}
	}

	if (pktp->availcb_excl == NULL)
		return BCME_ERROR;
	else
		return 0;
}

static int
pktpool_avail_notify(pktpool_t *pktp)
{
	int i, k, idx;
	int avail;

	ASSERT(pktp);
	if (pktp->availcb_excl != NULL) {
		pktp->availcb_excl->cb(pktp, pktp->availcb_excl->arg);
		return 0;
	}

	k = pktp->cbcnt - 1;
	for (i = 0; i < pktp->cbcnt; i++) {
		avail = pktpool_avail(pktp);

		if (avail) {
			if (pktp->cbtoggle)
				idx = i;
			else
				idx = k--;

			ASSERT(pktp->cbs[idx].cb != NULL);
			pktp->cbs[idx].cb(pktp, pktp->cbs[idx].arg);
		}
	}

	/* Alternate between filling from head or tail
	 */
	pktp->cbtoggle ^= 1;

	return 0;
}

void *
pktpool_get(pktpool_t *pktp)
{
	void *p;

	p = pktpool_deq(pktp);

	if (p == NULL) {
		/* Notify and try to reclaim tx pkts */
		if (pktp->ecbcnt)
			pktpool_empty_notify(pktp);

		p = pktpool_deq(pktp);
	}

	return p;
}

void
pktpool_free(pktpool_t *pktp, void *p)
{
	ASSERT(p != NULL);

#ifdef BCMDBG_POOL
	/* pktpool_stop_trigger(pktp, p); */
#endif

	pktpool_enq(pktp, p);

	if (pktp->emptycb_disable)
		return;

	if (pktp->cbcnt) {
		if (pktp->empty == FALSE)
			pktpool_avail_notify(pktp);
	}
}

int
pktpool_add(pktpool_t *pktp, void *p)
{
	ASSERT(p != NULL);

	if (pktpool_len(pktp) == pktp->maxlen)
		return BCME_RANGE;

	ASSERT(pktpool_plen(pktp) == PKTLEN(NULL, p)); /* pkts in pool have same length */
	PKTSETPOOL(NULL, p, TRUE, pktp);

	pktp->len++;
	if (pktp->r > pktp->w) {
		/* Add to tail */
		ASSERT(pktp->q[pktp->len - 1] == NULL);
		pktp->q[pktp->len - 1] = p;
	} else
		pktpool_enq(pktp, p);

#ifdef BCMDBG_POOL
	pktp->dbg_q[pktp->dbg_qlen++].p = p;
#endif

	return 0;
}

int
pktpool_setmaxlen(pktpool_t *pktp, uint16 maxlen)
{
	if (maxlen > PKTPOOL_LEN_MAX)
		maxlen = PKTPOOL_LEN_MAX;

	/* if pool is already beyond maxlen, then just cap it
	 * since we currently do not reduce the pool len
	 * already allocated
	 */
	pktp->maxlen = (pktpool_len(pktp) > maxlen) ? pktpool_len(pktp) : maxlen;

	return pktp->maxlen;
}

void
pktpool_emptycb_disable(pktpool_t *pktp, bool disable)
{
	ASSERT(pktp);

	pktp->emptycb_disable = disable;
}

bool
pktpool_emptycb_disabled(pktpool_t *pktp)
{
	ASSERT(pktp);
	return pktp->emptycb_disable;
}

/* copy a pkt buffer chain into a buffer */
uint
pktcopy(osl_t *osh, void *p, uint offset, int len, uchar *buf)
{
	uint n, ret = 0;

	if (len < 0)
		len = 4096;	/* "infinite" */

	/* skip 'offset' bytes */
	for (; p && offset; p = PKTNEXT(osh, p)) {
		if (offset < (uint)PKTLEN(osh, p))
			break;
		offset -= PKTLEN(osh, p);
	}

	if (!p)
		return 0;

	/* copy the data */
	for (; p && len; p = PKTNEXT(osh, p)) {
		n = MIN((uint)PKTLEN(osh, p) - offset, (uint)len);
		bcopy(PKTDATA(osh, p) + offset, buf, n);
		buf += n;
		len -= n;
		ret += n;
		offset = 0;
	}

	return ret;
}

/* copy a buffer into a pkt buffer chain */
uint
pktfrombuf(osl_t *osh, void *p, uint offset, int len, uchar *buf)
{
	uint n, ret = 0;

	/* skip 'offset' bytes */
	for (; p && offset; p = PKTNEXT(osh, p)) {
		if (offset < (uint)PKTLEN(osh, p))
			break;
		offset -= PKTLEN(osh, p);
	}

	if (!p)
		return 0;

	/* copy the data */
	for (; p && len; p = PKTNEXT(osh, p)) {
		n = MIN((uint)PKTLEN(osh, p) - offset, (uint)len);
		bcopy(buf, PKTDATA(osh, p) + offset, n);
		buf += n;
		len -= n;
		ret += n;
		offset = 0;
	}

	return ret;
}

#ifdef NOTYET
/* copy data from one pkt buffer (chain) to another */
uint
pkt2pktcopy(osl_t *osh, void *p1, uint offs1, void *p2, uint offs2, int maxlen)
{
	uint8 *dp1, *dp2;
	uint len1, len2, copylen, totallen;

	for (; p1 && offs; p1 = PKTNEXT(osh, p1)) {
		if (offs1 < (uint)PKTLEN(osh, p1))
			break;
		offs1 -= PKTLEN(osh, p1);
	}
	for (; p2 && offs; p2 = PKTNEXT(osh, p2)) {
		if (offs2 < (uint)PKTLEN(osh, p2))
			break;
		offs2 -= PKTLEN(osh, p2);
	}

	/* Heck w/it, only need the above for now */
}
#endif /* NOTYET */


/* return total length of buffer chain */
uint BCMFASTPATH
pkttotlen(osl_t *osh, void *p)
{
	uint total;
	int len;

	total = 0;
	for (; p; p = PKTNEXT(osh, p)) {
		len = PKTLEN(osh, p);
#ifdef MACOSX
		if (len < 0) {
			/* Bad packet length, just drop and exit */
			printf("wl: pkttotlen bad (%p,%d)\n", p, len);
			break;
		}
#endif /* MACOSX */
		total += len;
	}

	return (total);
}

/* return the last buffer of chained pkt */
void *
pktlast(osl_t *osh, void *p)
{
	for (; PKTNEXT(osh, p); p = PKTNEXT(osh, p))
		;

	return (p);
}

/* count segments of a chained packet */
uint BCMFASTPATH
pktsegcnt(osl_t *osh, void *p)
{
	uint cnt;

	for (cnt = 0; p; p = PKTNEXT(osh, p))
		cnt++;

	return cnt;
}


/* count segments of a chained packet */
uint BCMFASTPATH
pktsegcnt_war(osl_t *osh, void *p)
{
	uint cnt;
	uint8 *pktdata;
	uint len, remain, align64;

	for (cnt = 0; p; p = PKTNEXT(osh, p)) {
		cnt++;
		len = PKTLEN(osh, p);
		if (len > 128) {
			pktdata = (uint8 *)PKTDATA(osh, p);	/* starting address of data */
			/* Check for page boundary straddle (2048B) */
			if (((uintptr)pktdata & ~0x7ff) != ((uintptr)(pktdata+len) & ~0x7ff))
				cnt++;

			align64 = (uint)((uintptr)pktdata & 0x3f);	/* aligned to 64B */
			align64 = (64 - align64) & 0x3f;
			len -= align64;		/* bytes from aligned 64B to end */
			/* if aligned to 128B, check for MOD 128 between 1 to 4B */
			remain = len % 128;
			if (remain > 0 && remain <= 4)
				cnt++;		/* add extra seg */
		}
	}

	return cnt;
}

uint8 * BCMFASTPATH
pktdataoffset(osl_t *osh, void *p,  uint offset)
{
	uint total = pkttotlen(osh, p);
	uint pkt_off = 0, len = 0;
	uint8 *pdata = (uint8 *) PKTDATA(osh, p);

	if (offset > total)
		return NULL;

	for (; p; p = PKTNEXT(osh, p)) {
		pdata = (uint8 *) PKTDATA(osh, p);
		pkt_off = offset - len;
		len += PKTLEN(osh, p);
		if (len > offset)
			break;
	}
	return (uint8*) (pdata+pkt_off);
}


/* given a offset in pdata, find the pkt seg hdr */
void *
pktoffset(osl_t *osh, void *p,  uint offset)
{
	uint total = pkttotlen(osh, p);
	uint len = 0;

	if (offset > total)
		return NULL;

	for (; p; p = PKTNEXT(osh, p)) {
		len += PKTLEN(osh, p);
		if (len > offset)
			break;
	}
	return p;
}

/*
 * osl multiple-precedence packet queue
 * hi_prec is always >= the number of the highest non-empty precedence
 */
void * BCMFASTPATH
pktq_penq(struct pktq *pq, int prec, void *p)
{
	struct pktq_prec *q;

	ASSERT(prec >= 0 && prec < pq->num_prec);
	ASSERT(PKTLINK(p) == NULL);         /* queueing chains not allowed */

	ASSERT(!pktq_full(pq));
	ASSERT(!pktq_pfull(pq, prec));

	q = &pq->q[prec];

	if (q->head)
		PKTSETLINK(q->tail, p);
	else
		q->head = p;

	q->tail = p;
	q->len++;

	pq->len++;

	if (pq->hi_prec < prec)
		pq->hi_prec = (uint8)prec;

	return p;
}

void * BCMFASTPATH
pktq_penq_head(struct pktq *pq, int prec, void *p)
{
	struct pktq_prec *q;

	ASSERT(prec >= 0 && prec < pq->num_prec);
	ASSERT(PKTLINK(p) == NULL);         /* queueing chains not allowed */

	ASSERT(!pktq_full(pq));
	ASSERT(!pktq_pfull(pq, prec));

	q = &pq->q[prec];

	if (q->head == NULL)
		q->tail = p;

	PKTSETLINK(p, q->head);
	q->head = p;
	q->len++;

	pq->len++;

	if (pq->hi_prec < prec)
		pq->hi_prec = (uint8)prec;

	return p;
}

void * BCMFASTPATH
pktq_pdeq(struct pktq *pq, int prec)
{
	struct pktq_prec *q;
	void *p;

	ASSERT(prec >= 0 && prec < pq->num_prec);

	q = &pq->q[prec];

	if ((p = q->head) == NULL)
		return NULL;

	if ((q->head = PKTLINK(p)) == NULL)
		q->tail = NULL;

	q->len--;

	pq->len--;

	PKTSETLINK(p, NULL);

	return p;
}

void * BCMFASTPATH
pktq_pdeq_prev(struct pktq *pq, int prec, void *prev_p)
{
	struct pktq_prec *q;
	void *p;

	ASSERT(prec >= 0 && prec < pq->num_prec);

	q = &pq->q[prec];

	if (prev_p == NULL)
		return NULL;

	if ((p = PKTLINK(prev_p)) == NULL)
		return NULL;

	if (q->tail == p)
		q->tail = prev_p;

	q->len--;

	pq->len--;

	PKTSETLINK(prev_p, PKTLINK(p));
	PKTSETLINK(p, NULL);

	return p;
}

void * BCMFASTPATH
pktq_pdeq_tail(struct pktq *pq, int prec)
{
	struct pktq_prec *q;
	void *p, *prev;

	ASSERT(prec >= 0 && prec < pq->num_prec);

	q = &pq->q[prec];

	if ((p = q->head) == NULL)
		return NULL;

	for (prev = NULL; p != q->tail; p = PKTLINK(p))
		prev = p;

	if (prev)
		PKTSETLINK(prev, NULL);
	else
		q->head = NULL;

	q->tail = prev;
	q->len--;

	pq->len--;

	return p;
}

void
pktq_pflush(osl_t *osh, struct pktq *pq, int prec, bool dir, ifpkt_cb_t fn, int arg)
{
	struct pktq_prec *q;
	void *p, *prev = NULL;

	q = &pq->q[prec];
	p = q->head;
	while (p) {
		if (fn == NULL || (*fn)(p, arg)) {
			bool head = (p == q->head);
			if (head)
				q->head = PKTLINK(p);
			else
				PKTSETLINK(prev, PKTLINK(p));
			PKTSETLINK(p, NULL);
			PKTFREE(osh, p, dir);
			q->len--;
			pq->len--;
			p = (head ? q->head : PKTLINK(prev));
		} else {
			prev = p;
			p = PKTLINK(p);
		}
	}

	if (q->head == NULL) {
		ASSERT(q->len == 0);
		q->tail = NULL;
	}
}

bool BCMFASTPATH
pktq_pdel(struct pktq *pq, void *pktbuf, int prec)
{
	struct pktq_prec *q;
	void *p;

	ASSERT(prec >= 0 && prec < pq->num_prec);

	if (!pktbuf)
		return FALSE;

	q = &pq->q[prec];

	if (q->head == pktbuf) {
		if ((q->head = PKTLINK(pktbuf)) == NULL)
			q->tail = NULL;
	} else {
		for (p = q->head; p && PKTLINK(p) != pktbuf; p = PKTLINK(p))
			;
		if (p == NULL)
			return FALSE;

		PKTSETLINK(p, PKTLINK(pktbuf));
		if (q->tail == pktbuf)
			q->tail = p;
	}

	q->len--;
	pq->len--;
	PKTSETLINK(pktbuf, NULL);
	return TRUE;
}

void
pktq_init(struct pktq *pq, int num_prec, int max_len)
{
	int prec;

	ASSERT(num_prec > 0 && num_prec <= PKTQ_MAX_PREC);

	/* pq is variable size; only zero out what's requested */
	bzero(pq, OFFSETOF(struct pktq, q) + (sizeof(struct pktq_prec) * num_prec));

	pq->num_prec = (uint16)num_prec;

	pq->max = (uint16)max_len;

	for (prec = 0; prec < num_prec; prec++)
		pq->q[prec].max = pq->max;
}

void
pktq_set_max_plen(struct pktq *pq, int prec, int max_len)
{
	ASSERT(prec >= 0 && prec < pq->num_prec);

	if (prec < pq->num_prec)
		pq->q[prec].max = (uint16)max_len;
}

void * BCMFASTPATH
pktq_deq(struct pktq *pq, int *prec_out)
{
	struct pktq_prec *q;
	void *p;
	int prec;

	if (pq->len == 0)
		return NULL;

	while ((prec = pq->hi_prec) > 0 && pq->q[prec].head == NULL)
		pq->hi_prec--;

	q = &pq->q[prec];

	if ((p = q->head) == NULL)
		return NULL;

	if ((q->head = PKTLINK(p)) == NULL)
		q->tail = NULL;

	q->len--;

	pq->len--;

	if (prec_out)
		*prec_out = prec;

	PKTSETLINK(p, NULL);

	return p;
}

void * BCMFASTPATH
pktq_deq_tail(struct pktq *pq, int *prec_out)
{
	struct pktq_prec *q;
	void *p, *prev;
	int prec;

	if (pq->len == 0)
		return NULL;

	for (prec = 0; prec < pq->hi_prec; prec++)
		if (pq->q[prec].head)
			break;

	q = &pq->q[prec];

	if ((p = q->head) == NULL)
		return NULL;

	for (prev = NULL; p != q->tail; p = PKTLINK(p))
		prev = p;

	if (prev)
		PKTSETLINK(prev, NULL);
	else
		q->head = NULL;

	q->tail = prev;
	q->len--;

	pq->len--;

	if (prec_out)
		*prec_out = prec;

	PKTSETLINK(p, NULL);

	return p;
}

void *
pktq_peek(struct pktq *pq, int *prec_out)
{
	int prec;

	if (pq->len == 0)
		return NULL;

	while ((prec = pq->hi_prec) > 0 && pq->q[prec].head == NULL)
		pq->hi_prec--;

	if (prec_out)
		*prec_out = prec;

	return (pq->q[prec].head);
}

void *
pktq_peek_tail(struct pktq *pq, int *prec_out)
{
	int prec;

	if (pq->len == 0)
		return NULL;

	for (prec = 0; prec < pq->hi_prec; prec++)
		if (pq->q[prec].head)
			break;

	if (prec_out)
		*prec_out = prec;

	return (pq->q[prec].tail);
}

void
pktq_flush(osl_t *osh, struct pktq *pq, bool dir, ifpkt_cb_t fn, int arg)
{
	int prec;

	/* Optimize flush, if pktq len = 0, just return.
	 * pktq len of 0 means pktq's prec q's are all empty.
	 */
	if (pq->len == 0) {
		return;
	}

	for (prec = 0; prec < pq->num_prec; prec++)
		pktq_pflush(osh, pq, prec, dir, fn, arg);
	if (fn == NULL)
		ASSERT(pq->len == 0);
}

/* Return sum of lengths of a specific set of precedences */
int
pktq_mlen(struct pktq *pq, uint prec_bmp)
{
	int prec, len;

	len = 0;

	for (prec = 0; prec <= pq->hi_prec; prec++)
		if (prec_bmp & (1 << prec))
			len += pq->q[prec].len;

	return len;
}

/* Priority peek from a specific set of precedences */
void * BCMFASTPATH
pktq_mpeek(struct pktq *pq, uint prec_bmp, int *prec_out)
{
	struct pktq_prec *q;
	void *p;
	int prec;

	if (pq->len == 0)
	{
		return NULL;
	}
	while ((prec = pq->hi_prec) > 0 && pq->q[prec].head == NULL)
		pq->hi_prec--;

	while ((prec_bmp & (1 << prec)) == 0 || pq->q[prec].head == NULL)
		if (prec-- == 0)
			return NULL;

	q = &pq->q[prec];

	if ((p = q->head) == NULL)
		return NULL;

	if (prec_out)
		*prec_out = prec;

	return p;
}
/* Priority dequeue from a specific set of precedences */
void * BCMFASTPATH
pktq_mdeq(struct pktq *pq, uint prec_bmp, int *prec_out)
{
	struct pktq_prec *q;
	void *p;
	int prec;

	if (pq->len == 0)
		return NULL;

	while ((prec = pq->hi_prec) > 0 && pq->q[prec].head == NULL)
		pq->hi_prec--;

	while ((pq->q[prec].head == NULL) || ((prec_bmp & (1 << prec)) == 0))
		if (prec-- == 0)
			return NULL;

	q = &pq->q[prec];

	if ((p = q->head) == NULL)
		return NULL;

	if ((q->head = PKTLINK(p)) == NULL)
		q->tail = NULL;

	q->len--;

	if (prec_out)
		*prec_out = prec;

	pq->len--;

	PKTSETLINK(p, NULL);

	return p;
}

#endif /* BCMDRIVER */

#if defined(BCMROMBUILD)
const unsigned char BCMROMDATA(bcm_ctype)[] = {
#else
const unsigned char bcm_ctype[] = {
#endif

	_BCM_C,_BCM_C,_BCM_C,_BCM_C,_BCM_C,_BCM_C,_BCM_C,_BCM_C,			/* 0-7 */
	_BCM_C, _BCM_C|_BCM_S, _BCM_C|_BCM_S, _BCM_C|_BCM_S, _BCM_C|_BCM_S, _BCM_C|_BCM_S, _BCM_C,
	_BCM_C,	/* 8-15 */
	_BCM_C,_BCM_C,_BCM_C,_BCM_C,_BCM_C,_BCM_C,_BCM_C,_BCM_C,			/* 16-23 */
	_BCM_C,_BCM_C,_BCM_C,_BCM_C,_BCM_C,_BCM_C,_BCM_C,_BCM_C,			/* 24-31 */
	_BCM_S|_BCM_SP,_BCM_P,_BCM_P,_BCM_P,_BCM_P,_BCM_P,_BCM_P,_BCM_P,		/* 32-39 */
	_BCM_P,_BCM_P,_BCM_P,_BCM_P,_BCM_P,_BCM_P,_BCM_P,_BCM_P,			/* 40-47 */
	_BCM_D,_BCM_D,_BCM_D,_BCM_D,_BCM_D,_BCM_D,_BCM_D,_BCM_D,			/* 48-55 */
	_BCM_D,_BCM_D,_BCM_P,_BCM_P,_BCM_P,_BCM_P,_BCM_P,_BCM_P,			/* 56-63 */
	_BCM_P, _BCM_U|_BCM_X, _BCM_U|_BCM_X, _BCM_U|_BCM_X, _BCM_U|_BCM_X, _BCM_U|_BCM_X,
	_BCM_U|_BCM_X, _BCM_U, /* 64-71 */
	_BCM_U,_BCM_U,_BCM_U,_BCM_U,_BCM_U,_BCM_U,_BCM_U,_BCM_U,			/* 72-79 */
	_BCM_U,_BCM_U,_BCM_U,_BCM_U,_BCM_U,_BCM_U,_BCM_U,_BCM_U,			/* 80-87 */
	_BCM_U,_BCM_U,_BCM_U,_BCM_P,_BCM_P,_BCM_P,_BCM_P,_BCM_P,			/* 88-95 */
	_BCM_P, _BCM_L|_BCM_X, _BCM_L|_BCM_X, _BCM_L|_BCM_X, _BCM_L|_BCM_X, _BCM_L|_BCM_X,
	_BCM_L|_BCM_X, _BCM_L, /* 96-103 */
	_BCM_L,_BCM_L,_BCM_L,_BCM_L,_BCM_L,_BCM_L,_BCM_L,_BCM_L, /* 104-111 */
	_BCM_L,_BCM_L,_BCM_L,_BCM_L,_BCM_L,_BCM_L,_BCM_L,_BCM_L, /* 112-119 */
	_BCM_L,_BCM_L,_BCM_L,_BCM_P,_BCM_P,_BCM_P,_BCM_P,_BCM_C, /* 120-127 */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,		/* 128-143 */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,		/* 144-159 */
	_BCM_S|_BCM_SP, _BCM_P, _BCM_P, _BCM_P, _BCM_P, _BCM_P, _BCM_P, _BCM_P, _BCM_P, _BCM_P,
	_BCM_P, _BCM_P, _BCM_P, _BCM_P, _BCM_P, _BCM_P,	/* 160-175 */
	_BCM_P, _BCM_P, _BCM_P, _BCM_P, _BCM_P, _BCM_P, _BCM_P, _BCM_P, _BCM_P, _BCM_P, _BCM_P,
	_BCM_P, _BCM_P, _BCM_P, _BCM_P, _BCM_P,	/* 176-191 */
	_BCM_U, _BCM_U, _BCM_U, _BCM_U, _BCM_U, _BCM_U, _BCM_U, _BCM_U, _BCM_U, _BCM_U, _BCM_U,
	_BCM_U, _BCM_U, _BCM_U, _BCM_U, _BCM_U,	/* 192-207 */
	_BCM_U, _BCM_U, _BCM_U, _BCM_U, _BCM_U, _BCM_U, _BCM_U, _BCM_P, _BCM_U, _BCM_U, _BCM_U,
	_BCM_U, _BCM_U, _BCM_U, _BCM_U, _BCM_L,	/* 208-223 */
	_BCM_L, _BCM_L, _BCM_L, _BCM_L, _BCM_L, _BCM_L, _BCM_L, _BCM_L, _BCM_L, _BCM_L, _BCM_L,
	_BCM_L, _BCM_L, _BCM_L, _BCM_L, _BCM_L,	/* 224-239 */
	_BCM_L, _BCM_L, _BCM_L, _BCM_L, _BCM_L, _BCM_L, _BCM_L, _BCM_P, _BCM_L, _BCM_L, _BCM_L,
	_BCM_L, _BCM_L, _BCM_L, _BCM_L, _BCM_L /* 240-255 */
};

ulong
BCMROMFN(bcm_strtoul)(const char *cp, char **endp, uint base)
{
	ulong result, last_result = 0, value;
	bool minus;

	minus = FALSE;

	while (bcm_isspace(*cp))
		cp++;

	if (cp[0] == '+')
		cp++;
	else if (cp[0] == '-') {
		minus = TRUE;
		cp++;
	}

	if (base == 0) {
		if (cp[0] == '0') {
			if ((cp[1] == 'x') || (cp[1] == 'X')) {
				base = 16;
				cp = &cp[2];
			} else {
				base = 8;
				cp = &cp[1];
			}
		} else
			base = 10;
	} else if (base == 16 && (cp[0] == '0') && ((cp[1] == 'x') || (cp[1] == 'X'))) {
		cp = &cp[2];
	}

	result = 0;

	while (bcm_isxdigit(*cp) &&
	       (value = bcm_isdigit(*cp) ? *cp-'0' : bcm_toupper(*cp)-'A'+10) < base) {
		result = result*base + value;
		/* Detected overflow */
		if (result < last_result && !minus)
			return (ulong)-1;
		last_result = result;
		cp++;
	}

	if (minus)
		result = (ulong)(-(long)result);

	if (endp)
		*endp = DISCARD_QUAL(cp, char);

	return (result);
}

int
BCMROMFN(bcm_atoi)(const char *s)
{
	return (int)bcm_strtoul(s, NULL, 10);
}

/* return pointer to location of substring 'needle' in 'haystack' */
char *
BCMROMFN(bcmstrstr)(const char *haystack, const char *needle)
{
	int len, nlen;
	int i;

	if ((haystack == NULL) || (needle == NULL))
		return DISCARD_QUAL(haystack, char);

	nlen = strlen(needle);
	len = strlen(haystack) - nlen + 1;

	for (i = 0; i < len; i++)
		if (memcmp(needle, &haystack[i], nlen) == 0)
			return DISCARD_QUAL(&haystack[i], char);
	return (NULL);
}

char *
BCMROMFN(bcmstrcat)(char *dest, const char *src)
{
	char *p;

	p = dest + strlen(dest);

	while ((*p++ = *src++) != '\0')
		;

	return (dest);
}

char *
BCMROMFN(bcmstrncat)(char *dest, const char *src, uint size)
{
	char *endp;
	char *p;

	p = dest + strlen(dest);
	endp = p + size;

	while (p != endp && (*p++ = *src++) != '\0')
		;

	return (dest);
}


/****************************************************************************
* Function:   bcmstrtok
*
* Purpose:
*  Tokenizes a string. This function is conceptually similiar to ANSI C strtok(),
*  but allows strToken() to be used by different strings or callers at the same
*  time. Each call modifies '*string' by substituting a NULL character for the
*  first delimiter that is encountered, and updates 'string' to point to the char
*  after the delimiter. Leading delimiters are skipped.
*
* Parameters:
*  string      (mod) Ptr to string ptr, updated by token.
*  delimiters  (in)  Set of delimiter characters.
*  tokdelim    (out) Character that delimits the returned token. (May
*                    be set to NULL if token delimiter is not required).
*
* Returns:  Pointer to the next token found. NULL when no more tokens are found.
*****************************************************************************
*/
char *
bcmstrtok(char **string, const char *delimiters, char *tokdelim)
{
	unsigned char *str;
	unsigned long map[8];
	int count;
	char *nextoken;

	if (tokdelim != NULL) {
		/* Prime the token delimiter */
		*tokdelim = '\0';
	}

	/* Clear control map */
	for (count = 0; count < 8; count++) {
		map[count] = 0;
	}

	/* Set bits in delimiter table */
	do {
		map[*delimiters >> 5] |= (1 << (*delimiters & 31));
	}
	while (*delimiters++);

	str = (unsigned char*)*string;

	/* Find beginning of token (skip over leading delimiters). Note that
	 * there is no token iff this loop sets str to point to the terminal
	 * null (*str == '\0')
	 */
	while (((map[*str >> 5] & (1 << (*str & 31))) && *str) || (*str == ' ')) {
		str++;
	}

	nextoken = (char*)str;

	/* Find the end of the token. If it is not the end of the string,
	 * put a null there.
	 */
	for (; *str; str++) {
		if (map[*str >> 5] & (1 << (*str & 31))) {
			if (tokdelim != NULL) {
				*tokdelim = *str;
			}

			*str++ = '\0';
			break;
		}
	}

	*string = (char*)str;

	/* Determine if a token has been found. */
	if (nextoken == (char *) str) {
		return NULL;
	}
	else {
		return nextoken;
	}
}


#define xToLower(C) \
	((C >= 'A' && C <= 'Z') ? (char)((int)C - (int)'A' + (int)'a') : C)


/****************************************************************************
* Function:   bcmstricmp
*
* Purpose:    Compare to strings case insensitively.
*
* Parameters: s1 (in) First string to compare.
*             s2 (in) Second string to compare.
*
* Returns:    Return 0 if the two strings are equal, -1 if t1 < t2 and 1 if
*             t1 > t2, when ignoring case sensitivity.
*****************************************************************************
*/
int
bcmstricmp(const char *s1, const char *s2)
{
	char dc, sc;

	while (*s2 && *s1) {
		dc = xToLower(*s1);
		sc = xToLower(*s2);
		if (dc < sc) return -1;
		if (dc > sc) return 1;
		s1++;
		s2++;
	}

	if (*s1 && !*s2) return 1;
	if (!*s1 && *s2) return -1;
	return 0;
}


/****************************************************************************
* Function:   bcmstrnicmp
*
* Purpose:    Compare to strings case insensitively, upto a max of 'cnt'
*             characters.
*
* Parameters: s1  (in) First string to compare.
*             s2  (in) Second string to compare.
*             cnt (in) Max characters to compare.
*
* Returns:    Return 0 if the two strings are equal, -1 if t1 < t2 and 1 if
*             t1 > t2, when ignoring case sensitivity.
*****************************************************************************
*/
int
bcmstrnicmp(const char* s1, const char* s2, int cnt)
{
	char dc, sc;

	while (*s2 && *s1 && cnt) {
		dc = xToLower(*s1);
		sc = xToLower(*s2);
		if (dc < sc) return -1;
		if (dc > sc) return 1;
		s1++;
		s2++;
		cnt--;
	}

	if (!cnt) return 0;
	if (*s1 && !*s2) return 1;
	if (!*s1 && *s2) return -1;
	return 0;
}

/* parse a xx:xx:xx:xx:xx:xx format ethernet address */
int
BCMROMFN(bcm_ether_atoe)(const char *p, struct ether_addr *ea)
{
	int i = 0;
	char *ep;

	for (;;) {
		ea->octet[i++] = (char) bcm_strtoul(p, &ep, 16);
		p = ep;
		if (!*p++ || i == 6)
			break;
	}

	return (i == 6);
}


#if defined(CONFIG_USBRNDIS_RETAIL) || defined(NDIS_MINIPORT_DRIVER)
/* registry routine buffer preparation utility functions:
 * parameter order is like strncpy, but returns count
 * of bytes copied. Minimum bytes copied is null char(1)/wchar(2)
 */
ulong
wchar2ascii(char *abuf, ushort *wbuf, ushort wbuflen, ulong abuflen)
{
	ulong copyct = 1;
	ushort i;

	if (abuflen == 0)
		return 0;

	/* wbuflen is in bytes */
	wbuflen /= sizeof(ushort);

	for (i = 0; i < wbuflen; ++i) {
		if (--abuflen == 0)
			break;
		*abuf++ = (char) *wbuf++;
		++copyct;
	}
	*abuf = '\0';

	return copyct;
}
#endif /* CONFIG_USBRNDIS_RETAIL || NDIS_MINIPORT_DRIVER */

char *
bcm_ether_ntoa(const struct ether_addr *ea, char *buf)
{
	static const char hex[] =
	{
		'0', '1', '2', '3', '4', '5', '6', '7',
		'8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
	};
	const uint8 *octet = ea->octet;
	char *p = buf;
	int i;

	for (i = 0; i < 6; i++, octet++) {
		*p++ = hex[(*octet >> 4) & 0xf];
		*p++ = hex[*octet & 0xf];
		*p++ = ':';
	}

	*(p-1) = '\0';

	return (buf);
}

char *
bcm_ip_ntoa(struct ipv4_addr *ia, char *buf)
{
	snprintf(buf, 16, "%d.%d.%d.%d",
	         ia->addr[0], ia->addr[1], ia->addr[2], ia->addr[3]);
	return (buf);
}

char *
bcm_ipv6_ntoa(void *ipv6, char *buf)
{
	/* Implementing RFC 5952 Sections 4 + 5 */
	/* Not thoroughly tested */
	uint16 *a = (uint16 *)ipv6;
	char *p = buf;
	int i, i_max = -1, cnt = 0, cnt_max = 1;
	uint8 *a4 = NULL;

	for (i = 0; i < IPV6_ADDR_LEN/2; i++) {
		if (a[i]) {
			if (cnt > cnt_max) {
				cnt_max = cnt;
				i_max = i - cnt;
			}
			cnt = 0;
		} else
			cnt++;
	}
	if (cnt > cnt_max) {
		cnt_max = cnt;
		i_max = i - cnt;
	}
	if (i_max == 0 &&
		/* IPv4-translated: ::ffff:0:a.b.c.d */
		((cnt_max == 4 && a[4] == 0xffff && a[5] == 0) ||
		/* IPv4-mapped: ::ffff:a.b.c.d */
		(cnt_max == 5 && a[5] == 0xffff)))
		a4 = (uint8*) (a + 6);

	for (i = 0; i < IPV6_ADDR_LEN/2; i++) {
		if ((uint8*) (a + i) == a4) {
			snprintf(p, 17, ":%u.%u.%u.%u", a4[0], a4[1], a4[2], a4[3]);
			break;
		} else if (i == i_max) {
			*p++ = ':';
			i += cnt_max - 1;
			p[0] = ':';
			p[1] = '\0';
		} else {
			if (i)
				*p++ = ':';
			p += snprintf(p, 8, "%x", ntoh16(a[i]));
		}
	}

	return buf;
}

#ifdef BCMDRIVER

void
bcm_mdelay(uint ms)
{
	uint i;

	for (i = 0; i < ms; i++) {
		OSL_DELAY(1000);
	}
}

/*
 * Search the name=value vars for a specific one and return its value.
 * Returns NULL if not found.
 */
char *
getvar(char *vars, const char *name)
{
#ifdef _MINOSL_
	return NULL;
#else
	char *s;
	int len;

	if (!name)
		return NULL;

	len = strlen(name);
	if (len == 0)
		return NULL;

	/* first look in vars[] */
	for (s = vars; s && *s;) {
		if ((bcmp(s, name, len) == 0) && (s[len] == '='))
			return (&s[len+1]);

		while (*s++)
			;
	}

	/* then query nvram */
	return (nvram_get(name));
#endif	/* defined(_MINOSL_) */
}

/*
 * Search the vars for a specific one and return its value as
 * an integer. Returns 0 if not found.
 */
int
getintvar(char *vars, const char *name)
{
#ifdef	_MINOSL_
	return 0;
#else
	char *val;

	if ((val = getvar(vars, name)) == NULL)
		return (0);

	return (bcm_strtoul(val, NULL, 0));
#endif	/* _MINOSL_ */
}

int
getintvararray(char *vars, const char *name, int index)
{
#ifdef	_MINOSL_
	return 0;
#else
	char *buf, *endp;
	int i = 0;
	int val = 0;

	if ((buf = getvar(vars, name)) == NULL) {
		return (0);
	}

	/* table values are always separated by "," or " " */
	while (*buf != '\0') {
		val = bcm_strtoul(buf, &endp, 0);
		if (i == index) {
			return val;
		}
		buf = endp;
		/* delimiter is ',' */
		if (*buf == ',')
			buf++;
		i++;
	}
	return 0;
#endif	/* _MINOSL_ */
}

int
getintvararraysize(char *vars, const char *name)
{
#ifdef	_MINOSL_
	return 0;
#else
	char *buf, *endp;
	int count = 0;
	int val = 0;

	if ((buf = getvar(vars, name)) == NULL) {
		return (0);
	}

	/* table values are always separated by "," or " " */
	while (*buf != '\0') {
		val = bcm_strtoul(buf, &endp, 0);
		buf = endp;
		/* delimiter is ',' */
		if (*buf == ',')
			buf++;
		count++;
	}
	BCM_REFERENCE(val);
	return count;
#endif	/* _MINOSL_ */
}

/* Search for token in comma separated token-string */
static int
findmatch(const char *string, const char *name)
{
	uint len;
	char *c;

	len = strlen(name);
	while ((c = strchr(string, ',')) != NULL) {
		if (len == (uint)(c - string) && !strncmp(string, name, len))
			return 1;
		string = c + 1;
	}

	return (!strcmp(string, name));
}

/* Return gpio pin number assigned to the named pin
 *
 * Variable should be in format:
 *
 *	gpio<N>=pin_name,pin_name
 *
 * This format allows multiple features to share the gpio with mutual
 * understanding.
 *
 * 'def_pin' is returned if a specific gpio is not defined for the requested functionality
 * and if def_pin is not used by others.
 */
uint
getgpiopin(char *vars, char *pin_name, uint def_pin)
{
	char name[] = "gpioXXXX";
	char *val;
	uint pin;

	/* Go thru all possibilities till a match in pin name */
	for (pin = 0; pin < GPIO_NUMPINS; pin ++) {
		snprintf(name, sizeof(name), "gpio%d", pin);
		val = getvar(vars, name);
		if (val && findmatch(val, pin_name))
			return pin;
	}

	if (def_pin != GPIO_PIN_NOTDEFINED) {
		/* make sure the default pin is not used by someone else */
		snprintf(name, sizeof(name), "gpio%d", def_pin);
		if (getvar(vars, name)) {
			def_pin =  GPIO_PIN_NOTDEFINED;
		}
	}
	return def_pin;
}

#if defined(BCMPERFSTATS) || defined(BCMTSTAMPEDLOGS)

#define	LOGSIZE	256			/* should be power of 2 to avoid div below */
static struct {
	uint	cycles;
	char	*fmt;
	uint	a1;
	uint	a2;
} logtab[LOGSIZE];

/* last entry logged  */
static uint logi = 0;
/* next entry to read */
static uint readi = 0;
#endif	/* defined(BCMPERFSTATS) || defined(BCMTSTAMPEDLOGS) */

#ifdef BCMPERFSTATS
void
bcm_perf_enable()
{
	BCMPERF_ENABLE_INSTRCOUNT();
	BCMPERF_ENABLE_ICACHE_MISS();
	BCMPERF_ENABLE_ICACHE_HIT();
}

/* WARNING:  This routine uses OSL_GETCYCLES(), which can give unexpected results on
 * modern speed stepping CPUs.  Use bcmtslog() instead in combination with TSF counter.
 */
void
bcmlog(char *fmt, uint a1, uint a2)
{
	static uint last = 0;
	uint cycles, i;
	OSL_GETCYCLES(cycles);

	i = logi;

	logtab[i].cycles = cycles - last;
	logtab[i].fmt = fmt;
	logtab[i].a1 = a1;
	logtab[i].a2 = a2;

	logi = (i + 1) % LOGSIZE;
	last = cycles;
}


void
bcmstats(char *fmt)
{
	static uint last = 0;
	static uint32 ic_miss = 0;
	static uint32 instr_count = 0;
	uint32 ic_miss_cur;
	uint32 instr_count_cur;
	uint cycles, i;

	OSL_GETCYCLES(cycles);
	BCMPERF_GETICACHE_MISS(ic_miss_cur);
	BCMPERF_GETINSTRCOUNT(instr_count_cur);

	i = logi;

	logtab[i].cycles = cycles - last;
	logtab[i].a1 = ic_miss_cur - ic_miss;
	logtab[i].a2 = instr_count_cur - instr_count;
	logtab[i].fmt = fmt;

	logi = (i + 1) % LOGSIZE;

	last = cycles;
	instr_count = instr_count_cur;
	ic_miss = ic_miss_cur;
}


void
bcmdumplog(char *buf, int size)
{
	char *limit;
	int j = 0;
	int num;

	limit = buf + size - 80;
	*buf = '\0';

	num = logi - readi;

	if (num < 0)
		num += LOGSIZE;

	/* print in chronological order */

	for (j = 0; j < num && (buf < limit); readi = (readi + 1) % LOGSIZE, j++) {
		if (logtab[readi].fmt == NULL)
		    continue;
		buf += snprintf(buf, (limit - buf), "%d\t", logtab[readi].cycles);
		buf += snprintf(buf, (limit - buf), logtab[readi].fmt, logtab[readi].a1,
		                logtab[readi].a2);
		buf += snprintf(buf, (limit - buf), "\n");
	}

}


/*
 * Dump one log entry at a time.
 * Return index of next entry or -1 when no more .
 */
int
bcmdumplogent(char *buf, uint i)
{
	bool hit;

	/*
	 * If buf is NULL, return the starting index,
	 * interpreting i as the indicator of last 'i' entries to dump.
	 */
	if (buf == NULL) {
		i = ((i > 0) && (i < (LOGSIZE - 1))) ? i : (LOGSIZE - 1);
		return ((logi - i) % LOGSIZE);
	}

	*buf = '\0';

	ASSERT(i < LOGSIZE);

	if (i == logi)
		return (-1);

	hit = FALSE;
	for (; (i != logi) && !hit; i = (i + 1) % LOGSIZE) {
		if (logtab[i].fmt == NULL)
			continue;
		buf += sprintf(buf, "%d: %d\t", i, logtab[i].cycles);
		buf += sprintf(buf, logtab[i].fmt, logtab[i].a1, logtab[i].a2);
		buf += sprintf(buf, "\n");
		hit = TRUE;
	}

	return (i);
}

#endif	/* BCMPERFSTATS */

#if defined(BCMTSTAMPEDLOGS)
/* Store a TSF timestamp and a log line in the log buffer */
void
bcmtslog(uint32 tstamp, char *fmt, uint a1, uint a2)
{
	uint i = logi;
	bool use_delta = FALSE;
	static uint32 last = 0;	/* used only when use_delta is true */

	logtab[i].cycles = tstamp;
	if (use_delta)
		logtab[i].cycles -= last;

	logtab[i].fmt = fmt;
	logtab[i].a1 = a1;
	logtab[i].a2 = a2;

	if (use_delta)
		last = tstamp;
	logi = (i + 1) % LOGSIZE;
}

/* Print out a microsecond timestamp as "sec.ms.us " */
void
bcmprinttstamp(uint32 ticks)
{
	uint us, ms, sec;

	us = (ticks % TSF_TICKS_PER_MS) * 1000 / TSF_TICKS_PER_MS;
	ms = ticks / TSF_TICKS_PER_MS;
	sec = ms / 1000;
	ms -= sec * 1000;
	printf("%04u.%03u.%03u ", sec, ms, us);
}

/* Print out the log buffer with timestamps */
void
bcmprinttslogs(void)
{
	int j = 0;
	int num;

	num = logi - readi;
	if (num < 0)
		num += LOGSIZE;

	/* Format and print the log entries directly in chronological order */
	for (j = 0; j < num; readi = (readi + 1) % LOGSIZE, j++) {
		if (logtab[readi].fmt == NULL)
		    continue;
		bcmprinttstamp(logtab[readi].cycles);
		printf(logtab[readi].fmt, logtab[readi].a1, logtab[readi].a2);
		printf("\n");
	}
}

void
bcmdumptslog(char *buf, int size)
{
	char *limit;
	int j = 0;
	int num;
	uint us, ms, sec;

	limit = buf + size - 80;
	*buf = '\0';

	num = logi - readi;

	if (num < 0)
		num += LOGSIZE;

	/* print in chronological order */
	for (j = 0; j < num && (buf < limit); readi = (readi + 1) % LOGSIZE, j++) {
		if (logtab[readi].fmt == NULL)
			continue;
		us = (logtab[readi].cycles % TSF_TICKS_PER_MS) * 1000 / TSF_TICKS_PER_MS;
		ms = logtab[readi].cycles / TSF_TICKS_PER_MS;
		sec = ms / 1000;
		ms -= sec * 1000;

		buf += snprintf(buf, (limit - buf), "%04u.%03u.%03u ", sec, ms, us);
		/*      buf += snprintf(buf, (limit - buf), "%d\t", logtab[readi].cycles); */
		buf += snprintf(buf, (limit - buf), logtab[readi].fmt, logtab[readi].a1,
		logtab[readi].a2);
		buf += snprintf(buf, (limit - buf), "\n");
	}
}

#endif	/* BCMTSTAMPEDLOGS */

#if defined(BCMDBG) || defined(DHD_DEBUG)
/* pretty hex print a pkt buffer chain */
void
prpkt(const char *msg, osl_t *osh, void *p0)
{
	void *p;

	if (msg && (msg[0] != '\0'))
		printf("%s:\n", msg);

	for (p = p0; p; p = PKTNEXT(osh, p))
		prhex(NULL, PKTDATA(osh, p), PKTLEN(osh, p));
}
#endif	/* BCMDBG || DHD_DEBUG */

/* Takes an Ethernet frame and sets out-of-bound PKTPRIO.
 * Also updates the inplace vlan tag if requested.
 * For debugging, it returns an indication of what it did.
 */
uint BCMFASTPATH
pktsetprio(void *pkt, bool update_vtag)
{
	struct ether_header *eh;
	struct ethervlan_header *evh;
	uint8 *pktdata;
	int priority = 0;
	int rc = 0;

	pktdata = (uint8 *)PKTDATA(NULL, pkt);
	ASSERT(ISALIGNED((uintptr)pktdata, sizeof(uint16)));

	eh = (struct ether_header *) pktdata;

	if (eh->ether_type == hton16(ETHER_TYPE_8021Q)) {
		uint16 vlan_tag;
		int vlan_prio, dscp_prio = 0;

		evh = (struct ethervlan_header *)eh;

		vlan_tag = ntoh16(evh->vlan_tag);
		vlan_prio = (int) (vlan_tag >> VLAN_PRI_SHIFT) & VLAN_PRI_MASK;

		if (evh->ether_type == hton16(ETHER_TYPE_IP)) {
			uint8 *ip_body = pktdata + sizeof(struct ethervlan_header);
			uint8 tos_tc = IP_TOS46(ip_body);
			dscp_prio = (int)(tos_tc >> IPV4_TOS_PREC_SHIFT);
		}

		/* DSCP priority gets precedence over 802.1P (vlan tag) */
		if (dscp_prio != 0) {
			priority = dscp_prio;
			rc |= PKTPRIO_VDSCP;
		} else {
			priority = vlan_prio;
			rc |= PKTPRIO_VLAN;
		}
		/*
		 * If the DSCP priority is not the same as the VLAN priority,
		 * then overwrite the priority field in the vlan tag, with the
		 * DSCP priority value. This is required for Linux APs because
		 * the VLAN driver on Linux, overwrites the skb->priority field
		 * with the priority value in the vlan tag
		 */
		if (update_vtag && (priority != vlan_prio)) {
			vlan_tag &= ~(VLAN_PRI_MASK << VLAN_PRI_SHIFT);
			vlan_tag |= (uint16)priority << VLAN_PRI_SHIFT;
			evh->vlan_tag = hton16(vlan_tag);
			rc |= PKTPRIO_UPD;
		}
	} else if (eh->ether_type == hton16(ETHER_TYPE_IP)) {
		uint8 *ip_body = pktdata + sizeof(struct ether_header);
		uint8 tos_tc = IP_TOS46(ip_body);
		priority = (int)(tos_tc >> IPV4_TOS_PREC_SHIFT);
		rc |= PKTPRIO_DSCP;
	}

	ASSERT(priority >= 0 && priority <= MAXPRIO);
	PKTSETPRIO(pkt, priority);
	return (rc | priority);
}

#ifndef BCM_BOOTLOADER

static char bcm_undeferrstr[32];
static const char *const bcmerrorstrtable[] = BCMERRSTRINGTABLE;

/* Convert the error codes into related error strings  */
const char *
bcmerrorstr(int bcmerror)
{
	/* check if someone added a bcmerror code but forgot to add errorstring */
	ASSERT(ABS(BCME_LAST) == (ARRAYSIZE(bcmerrorstrtable) - 1));

	if (bcmerror > 0 || bcmerror < BCME_LAST) {
		snprintf(bcm_undeferrstr, sizeof(bcm_undeferrstr), "Undefined error %d", bcmerror);
		return bcm_undeferrstr;
	}

	ASSERT(strlen(bcmerrorstrtable[-bcmerror]) < BCME_STRLEN);

	return bcmerrorstrtable[-bcmerror];
}

#endif /* !BCM_BOOTLOADER */

#ifdef WLC_LOW
static void
BCMINITFN(bcm_nvram_refresh)(char *flash)
{
	int i;
	int ret = 0;

	ASSERT(flash != NULL);

	/* default "empty" vars cache */
	bzero(flash, 2);

	if ((ret = nvram_getall(flash, MAX_NVRAM_SPACE)))
		return;

	/* determine nvram length */
	for (i = 0; i < MAX_NVRAM_SPACE; i++) {
		if (flash[i] == '\0' && flash[i+1] == '\0')
			break;
	}

	if (i > 1)
		vars_len = i + 2;
	else
		vars_len = 0;
}

char *
bcm_nvram_vars(uint *length)
{
#ifndef BCMNVRAMR
	/* cache may be stale if nvram is read/write */
	if (nvram_vars) {
		ASSERT(!bcmreclaimed);
		bcm_nvram_refresh(nvram_vars);
	}
#endif
	if (length)
		*length = vars_len;
	return nvram_vars;
}

/* copy nvram vars into locally-allocated multi-string array */
int
BCMINITFN(bcm_nvram_cache)(void *sih)
{
	int ret = 0;
	void *osh;
	char *flash = NULL;

	if (vars_len >= 0) {
#ifndef BCMNVRAMR
		bcm_nvram_refresh(nvram_vars);
#endif
		return 0;
	}

	osh = si_osh((si_t *)sih);

	/* allocate memory and read in flash */
	if (!(flash = MALLOC(osh, MAX_NVRAM_SPACE))) {
		ret = BCME_NOMEM;
		goto exit;
	}

	bcm_nvram_refresh(flash);

#ifdef BCMNVRAMR
	if (vars_len > 3) {
		/* copy into a properly-sized buffer */
		if (!(nvram_vars = MALLOC(osh, vars_len))) {
			ret = BCME_NOMEM;
		} else
			bcopy(flash, nvram_vars, vars_len);
	}
	MFREE(osh, flash, MAX_NVRAM_SPACE);
#else
	/* cache must be full size of nvram if read/write */
	nvram_vars = flash;
#endif	/* BCMNVRAMR */

exit:
	return ret;
}
#endif /* WLC_LOW */


/* iovar table lookup */
const bcm_iovar_t*
bcm_iovar_lookup(const bcm_iovar_t *table, const char *name)
{
	const bcm_iovar_t *vi;
	const char *lookup_name;

	/* skip any ':' delimited option prefixes */
	lookup_name = strrchr(name, ':');
	if (lookup_name != NULL)
		lookup_name++;
	else
		lookup_name = name;

	ASSERT(table != NULL);

	for (vi = table; vi->name; vi++) {
		if (!strcmp(vi->name, lookup_name))
			return vi;
	}
	/* ran to end of table */

	return NULL; /* var name not found */
}

int
bcm_iovar_lencheck(const bcm_iovar_t *vi, void *arg, int len, bool set)
{
	int bcmerror = 0;

	/* length check on io buf */
	switch (vi->type) {
	case IOVT_BOOL:
	case IOVT_INT8:
	case IOVT_INT16:
	case IOVT_INT32:
	case IOVT_UINT8:
	case IOVT_UINT16:
	case IOVT_UINT32:
		/* all integers are int32 sized args at the ioctl interface */
		if (len < (int)sizeof(int)) {
			bcmerror = BCME_BUFTOOSHORT;
		}
		break;

	case IOVT_BUFFER:
		/* buffer must meet minimum length requirement */
		if (len < vi->minlen) {
			bcmerror = BCME_BUFTOOSHORT;
		}
		break;

	case IOVT_VOID:
		if (!set) {
			/* Cannot return nil... */
			bcmerror = BCME_UNSUPPORTED;
		} else if (len) {
			/* Set is an action w/o parameters */
			bcmerror = BCME_BUFTOOLONG;
		}
		break;

	default:
		/* unknown type for length check in iovar info */
		ASSERT(0);
		bcmerror = BCME_UNSUPPORTED;
	}

	return bcmerror;
}

#endif	/* BCMDRIVER */


/*******************************************************************************
 * crc8
 *
 * Computes a crc8 over the input data using the polynomial:
 *
 *       x^8 + x^7 +x^6 + x^4 + x^2 + 1
 *
 * The caller provides the initial value (either CRC8_INIT_VALUE
 * or the previous returned value) to allow for processing of
 * discontiguous blocks of data.  When generating the CRC the
 * caller is responsible for complementing the final return value
 * and inserting it into the byte stream.  When checking, a final
 * return value of CRC8_GOOD_VALUE indicates a valid CRC.
 *
 * Reference: Dallas Semiconductor Application Note 27
 *   Williams, Ross N., "A Painless Guide to CRC Error Detection Algorithms",
 *     ver 3, Aug 1993, ross@guest.adelaide.edu.au, Rocksoft Pty Ltd.,
 *     ftp://ftp.rocksoft.com/clients/rocksoft/papers/crc_v3.txt
 *
 * ****************************************************************************
 */

static const uint8 crc8_table[256] = {
    0x00, 0xF7, 0xB9, 0x4E, 0x25, 0xD2, 0x9C, 0x6B,
    0x4A, 0xBD, 0xF3, 0x04, 0x6F, 0x98, 0xD6, 0x21,
    0x94, 0x63, 0x2D, 0xDA, 0xB1, 0x46, 0x08, 0xFF,
    0xDE, 0x29, 0x67, 0x90, 0xFB, 0x0C, 0x42, 0xB5,
    0x7F, 0x88, 0xC6, 0x31, 0x5A, 0xAD, 0xE3, 0x14,
    0x35, 0xC2, 0x8C, 0x7B, 0x10, 0xE7, 0xA9, 0x5E,
    0xEB, 0x1C, 0x52, 0xA5, 0xCE, 0x39, 0x77, 0x80,
    0xA1, 0x56, 0x18, 0xEF, 0x84, 0x73, 0x3D, 0xCA,
    0xFE, 0x09, 0x47, 0xB0, 0xDB, 0x2C, 0x62, 0x95,
    0xB4, 0x43, 0x0D, 0xFA, 0x91, 0x66, 0x28, 0xDF,
    0x6A, 0x9D, 0xD3, 0x24, 0x4F, 0xB8, 0xF6, 0x01,
    0x20, 0xD7, 0x99, 0x6E, 0x05, 0xF2, 0xBC, 0x4B,
    0x81, 0x76, 0x38, 0xCF, 0xA4, 0x53, 0x1D, 0xEA,
    0xCB, 0x3C, 0x72, 0x85, 0xEE, 0x19, 0x57, 0xA0,
    0x15, 0xE2, 0xAC, 0x5B, 0x30, 0xC7, 0x89, 0x7E,
    0x5F, 0xA8, 0xE6, 0x11, 0x7A, 0x8D, 0xC3, 0x34,
    0xAB, 0x5C, 0x12, 0xE5, 0x8E, 0x79, 0x37, 0xC0,
    0xE1, 0x16, 0x58, 0xAF, 0xC4, 0x33, 0x7D, 0x8A,
    0x3F, 0xC8, 0x86, 0x71, 0x1A, 0xED, 0xA3, 0x54,
    0x75, 0x82, 0xCC, 0x3B, 0x50, 0xA7, 0xE9, 0x1E,
    0xD4, 0x23, 0x6D, 0x9A, 0xF1, 0x06, 0x48, 0xBF,
    0x9E, 0x69, 0x27, 0xD0, 0xBB, 0x4C, 0x02, 0xF5,
    0x40, 0xB7, 0xF9, 0x0E, 0x65, 0x92, 0xDC, 0x2B,
    0x0A, 0xFD, 0xB3, 0x44, 0x2F, 0xD8, 0x96, 0x61,
    0x55, 0xA2, 0xEC, 0x1B, 0x70, 0x87, 0xC9, 0x3E,
    0x1F, 0xE8, 0xA6, 0x51, 0x3A, 0xCD, 0x83, 0x74,
    0xC1, 0x36, 0x78, 0x8F, 0xE4, 0x13, 0x5D, 0xAA,
    0x8B, 0x7C, 0x32, 0xC5, 0xAE, 0x59, 0x17, 0xE0,
    0x2A, 0xDD, 0x93, 0x64, 0x0F, 0xF8, 0xB6, 0x41,
    0x60, 0x97, 0xD9, 0x2E, 0x45, 0xB2, 0xFC, 0x0B,
    0xBE, 0x49, 0x07, 0xF0, 0x9B, 0x6C, 0x22, 0xD5,
    0xF4, 0x03, 0x4D, 0xBA, 0xD1, 0x26, 0x68, 0x9F
};

#define CRC_INNER_LOOP(n, c, x) \
	(c) = ((c) >> 8) ^ crc##n##_table[((c) ^ (x)) & 0xff]

uint8
BCMROMFN(hndcrc8)(
	uint8 *pdata,	/* pointer to array of data to process */
	uint  nbytes,	/* number of input data bytes to process */
	uint8 crc	/* either CRC8_INIT_VALUE or previous return value */
)
{
	/* hard code the crc loop instead of using CRC_INNER_LOOP macro
	 * to avoid the undefined and unnecessary (uint8 >> 8) operation.
	 */
	while (nbytes-- > 0)
		crc = crc8_table[(crc ^ *pdata++) & 0xff];

	return crc;
}

/*******************************************************************************
 * crc16
 *
 * Computes a crc16 over the input data using the polynomial:
 *
 *       x^16 + x^12 +x^5 + 1
 *
 * The caller provides the initial value (either CRC16_INIT_VALUE
 * or the previous returned value) to allow for processing of
 * discontiguous blocks of data.  When generating the CRC the
 * caller is responsible for complementing the final return value
 * and inserting it into the byte stream.  When checking, a final
 * return value of CRC16_GOOD_VALUE indicates a valid CRC.
 *
 * Reference: Dallas Semiconductor Application Note 27
 *   Williams, Ross N., "A Painless Guide to CRC Error Detection Algorithms",
 *     ver 3, Aug 1993, ross@guest.adelaide.edu.au, Rocksoft Pty Ltd.,
 *     ftp://ftp.rocksoft.com/clients/rocksoft/papers/crc_v3.txt
 *
 * ****************************************************************************
 */

static const uint16 crc16_table[256] = {
    0x0000, 0x1189, 0x2312, 0x329B, 0x4624, 0x57AD, 0x6536, 0x74BF,
    0x8C48, 0x9DC1, 0xAF5A, 0xBED3, 0xCA6C, 0xDBE5, 0xE97E, 0xF8F7,
    0x1081, 0x0108, 0x3393, 0x221A, 0x56A5, 0x472C, 0x75B7, 0x643E,
    0x9CC9, 0x8D40, 0xBFDB, 0xAE52, 0xDAED, 0xCB64, 0xF9FF, 0xE876,
    0x2102, 0x308B, 0x0210, 0x1399, 0x6726, 0x76AF, 0x4434, 0x55BD,
    0xAD4A, 0xBCC3, 0x8E58, 0x9FD1, 0xEB6E, 0xFAE7, 0xC87C, 0xD9F5,
    0x3183, 0x200A, 0x1291, 0x0318, 0x77A7, 0x662E, 0x54B5, 0x453C,
    0xBDCB, 0xAC42, 0x9ED9, 0x8F50, 0xFBEF, 0xEA66, 0xD8FD, 0xC974,
    0x4204, 0x538D, 0x6116, 0x709F, 0x0420, 0x15A9, 0x2732, 0x36BB,
    0xCE4C, 0xDFC5, 0xED5E, 0xFCD7, 0x8868, 0x99E1, 0xAB7A, 0xBAF3,
    0x5285, 0x430C, 0x7197, 0x601E, 0x14A1, 0x0528, 0x37B3, 0x263A,
    0xDECD, 0xCF44, 0xFDDF, 0xEC56, 0x98E9, 0x8960, 0xBBFB, 0xAA72,
    0x6306, 0x728F, 0x4014, 0x519D, 0x2522, 0x34AB, 0x0630, 0x17B9,
    0xEF4E, 0xFEC7, 0xCC5C, 0xDDD5, 0xA96A, 0xB8E3, 0x8A78, 0x9BF1,
    0x7387, 0x620E, 0x5095, 0x411C, 0x35A3, 0x242A, 0x16B1, 0x0738,
    0xFFCF, 0xEE46, 0xDCDD, 0xCD54, 0xB9EB, 0xA862, 0x9AF9, 0x8B70,
    0x8408, 0x9581, 0xA71A, 0xB693, 0xC22C, 0xD3A5, 0xE13E, 0xF0B7,
    0x0840, 0x19C9, 0x2B52, 0x3ADB, 0x4E64, 0x5FED, 0x6D76, 0x7CFF,
    0x9489, 0x8500, 0xB79B, 0xA612, 0xD2AD, 0xC324, 0xF1BF, 0xE036,
    0x18C1, 0x0948, 0x3BD3, 0x2A5A, 0x5EE5, 0x4F6C, 0x7DF7, 0x6C7E,
    0xA50A, 0xB483, 0x8618, 0x9791, 0xE32E, 0xF2A7, 0xC03C, 0xD1B5,
    0x2942, 0x38CB, 0x0A50, 0x1BD9, 0x6F66, 0x7EEF, 0x4C74, 0x5DFD,
    0xB58B, 0xA402, 0x9699, 0x8710, 0xF3AF, 0xE226, 0xD0BD, 0xC134,
    0x39C3, 0x284A, 0x1AD1, 0x0B58, 0x7FE7, 0x6E6E, 0x5CF5, 0x4D7C,
    0xC60C, 0xD785, 0xE51E, 0xF497, 0x8028, 0x91A1, 0xA33A, 0xB2B3,
    0x4A44, 0x5BCD, 0x6956, 0x78DF, 0x0C60, 0x1DE9, 0x2F72, 0x3EFB,
    0xD68D, 0xC704, 0xF59F, 0xE416, 0x90A9, 0x8120, 0xB3BB, 0xA232,
    0x5AC5, 0x4B4C, 0x79D7, 0x685E, 0x1CE1, 0x0D68, 0x3FF3, 0x2E7A,
    0xE70E, 0xF687, 0xC41C, 0xD595, 0xA12A, 0xB0A3, 0x8238, 0x93B1,
    0x6B46, 0x7ACF, 0x4854, 0x59DD, 0x2D62, 0x3CEB, 0x0E70, 0x1FF9,
    0xF78F, 0xE606, 0xD49D, 0xC514, 0xB1AB, 0xA022, 0x92B9, 0x8330,
    0x7BC7, 0x6A4E, 0x58D5, 0x495C, 0x3DE3, 0x2C6A, 0x1EF1, 0x0F78
};

uint16
BCMROMFN(hndcrc16)(
    uint8 *pdata,  /* pointer to array of data to process */
    uint nbytes, /* number of input data bytes to process */
    uint16 crc     /* either CRC16_INIT_VALUE or previous return value */
)
{
	while (nbytes-- > 0)
		CRC_INNER_LOOP(16, crc, *pdata++);
	return crc;
}

static const uint32 crc32_table[256] = {
    0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA,
    0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
    0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988,
    0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91,
    0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE,
    0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
    0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC,
    0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5,
    0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172,
    0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B,
    0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940,
    0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
    0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116,
    0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F,
    0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924,
    0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D,
    0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A,
    0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
    0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818,
    0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01,
    0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E,
    0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,
    0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C,
    0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
    0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2,
    0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB,
    0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0,
    0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9,
    0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086,
    0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
    0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4,
    0x59B33D17, 0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD,
    0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A,
    0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683,
    0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8,
    0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
    0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE,
    0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7,
    0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC,
    0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5,
    0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252,
    0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
    0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60,
    0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x4669BE79,
    0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236,
    0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F,
    0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04,
    0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
    0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A,
    0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713,
    0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38,
    0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21,
    0x86D3D2D4, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E,
    0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
    0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C,
    0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45,
    0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2,
    0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB,
    0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0,
    0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
    0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6,
    0xBAD03605, 0xCDD70693, 0x54DE5729, 0x23D967BF,
    0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94,
    0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D
};

/*
 * crc input is CRC32_INIT_VALUE for a fresh start, or previous return value if
 * accumulating over multiple pieces.
 */
uint32
BCMROMFN(hndcrc32)(uint8 *pdata, uint nbytes, uint32 crc)
{
	uint8 *pend;
#ifdef __mips__
	uint8 tmp[4];
	ulong *tptr = (ulong *)tmp;

	if (nbytes > 3) {
		/* in case the beginning of the buffer isn't aligned */
		pend = (uint8 *)((uint)(pdata + 3) & ~0x3);
		nbytes -= (pend - pdata);
		while (pdata < pend)
			CRC_INNER_LOOP(32, crc, *pdata++);
	}

	if (nbytes > 3) {
		/* handle bulk of data as 32-bit words */
		pend = pdata + (nbytes & ~0x3);
		while (pdata < pend) {
			*tptr = *(ulong *)pdata;
			pdata += sizeof(ulong *);
			CRC_INNER_LOOP(32, crc, tmp[0]);
			CRC_INNER_LOOP(32, crc, tmp[1]);
			CRC_INNER_LOOP(32, crc, tmp[2]);
			CRC_INNER_LOOP(32, crc, tmp[3]);
		}
	}

	/* 1-3 bytes at end of buffer */
	pend = pdata + (nbytes & 0x03);
	while (pdata < pend)
		CRC_INNER_LOOP(32, crc, *pdata++);
#else
	pend = pdata + nbytes;
	while (pdata < pend)
		CRC_INNER_LOOP(32, crc, *pdata++);
#endif /* __mips__ */

	return crc;
}

#ifdef notdef
#define CLEN 	1499 	/*  CRC Length */
#define CBUFSIZ 	(CLEN+4)
#define CNBUFS		5 /* # of bufs */

void
testcrc32(void)
{
	uint j, k, l;
	uint8 *buf;
	uint len[CNBUFS];
	uint32 crcr;
	uint32 crc32tv[CNBUFS] =
		{0xd2cb1faa, 0xd385c8fa, 0xf5b4f3f3, 0x55789e20, 0x00343110};

	ASSERT((buf = MALLOC(CBUFSIZ*CNBUFS)) != NULL);

	/* step through all possible alignments */
	for (l = 0; l <= 4; l++) {
		for (j = 0; j < CNBUFS; j++) {
			len[j] = CLEN;
			for (k = 0; k < len[j]; k++)
				*(buf + j*CBUFSIZ + (k+l)) = (j+k) & 0xff;
		}

		for (j = 0; j < CNBUFS; j++) {
			crcr = crc32(buf + j*CBUFSIZ + l, len[j], CRC32_INIT_VALUE);
			ASSERT(crcr == crc32tv[j]);
		}
	}

	MFREE(buf, CBUFSIZ*CNBUFS);
	return;
}
#endif /* notdef */

/*
 * Advance from the current 1-byte tag/1-byte length/variable-length value
 * triple, to the next, returning a pointer to the next.
 * If the current or next TLV is invalid (does not fit in given buffer length),
 * NULL is returned.
 * *buflen is not modified if the TLV elt parameter is invalid, or is decremented
 * by the TLV parameter's length if it is valid.
 */
bcm_tlv_t *
BCMROMFN(bcm_next_tlv)(bcm_tlv_t *elt, int *buflen)
{
	int len;

	/* validate current elt */
	if (!bcm_valid_tlv(elt, *buflen))
		return NULL;

	/* advance to next elt */
	len = elt->len;
	elt = (bcm_tlv_t*)(elt->data + len);
	*buflen -= (TLV_HDR_LEN + len);

	/* validate next elt */
	if (!bcm_valid_tlv(elt, *buflen))
		return NULL;

	return elt;
}

/*
 * Traverse a string of 1-byte tag/1-byte length/variable-length value
 * triples, returning a pointer to the substring whose first element
 * matches tag
 */
bcm_tlv_t *
BCMROMFN(bcm_parse_tlvs)(void *buf, int buflen, uint key)
{
	bcm_tlv_t *elt;
	int totlen;

	elt = (bcm_tlv_t*)buf;
	totlen = buflen;

	/* find tagged parameter */
	while (totlen >= TLV_HDR_LEN) {
		int len = elt->len;

		/* validate remaining totlen */
		if ((elt->id == key) &&
		    (totlen >= (len + TLV_HDR_LEN)))
			return (elt);

		elt = (bcm_tlv_t*)((uint8*)elt + (len + TLV_HDR_LEN));
		totlen -= (len + TLV_HDR_LEN);
	}

	return NULL;
}

/*
 * Traverse a string of 1-byte tag/1-byte length/variable-length value
 * triples, returning a pointer to the substring whose first element
 * matches tag.  Stop parsing when we see an element whose ID is greater
 * than the target key.
 */
bcm_tlv_t *
BCMROMFN(bcm_parse_ordered_tlvs)(void *buf, int buflen, uint key)
{
	bcm_tlv_t *elt;
	int totlen;

	elt = (bcm_tlv_t*)buf;
	totlen = buflen;

	/* find tagged parameter */
	while (totlen >= TLV_HDR_LEN) {
		uint id = elt->id;
		int len = elt->len;

		/* Punt if we start seeing IDs > than target key */
		if (id > key)
			return (NULL);

		/* validate remaining totlen */
		if ((id == key) &&
		    (totlen >= (len + TLV_HDR_LEN)))
			return (elt);

		elt = (bcm_tlv_t*)((uint8*)elt + (len + TLV_HDR_LEN));
		totlen -= (len + TLV_HDR_LEN);
	}
	return NULL;
}

#if defined(BCMDBG) || defined(BCMDBG_ERR) || defined(WLMSG_PRHDRS) || \
	defined(WLMSG_PRPKT) || defined(WLMSG_ASSOC) || defined(DHD_DEBUG)
int
bcm_format_field(const bcm_bit_desc_ex_t *bd, uint32 flags, char* buf, int len)
{
	int i, slen = 0;
	uint32 bit, mask;
	const char *name;
	mask = bd->mask;
	if (len < 2 || !buf)
		return 0;

	buf[0] = '\0';

	for (i = 0;  (name = bd->bitfield[i].name) != NULL; i++) {
		bit = bd->bitfield[i].bit;
		if ((flags & mask) == bit) {
			if (len > (int)strlen(name)) {
				slen = strlen(name);
				strncpy(buf, name, slen+1);
			}
			break;
		}
	}
	return slen;
}

int
bcm_format_flags(const bcm_bit_desc_t *bd, uint32 flags, char* buf, int len)
{
	int i;
	char* p = buf;
	char hexstr[16];
	int slen = 0, nlen = 0;
	uint32 bit;
	const char* name;

	if (len < 2 || !buf)
		return 0;

	buf[0] = '\0';

	for (i = 0; flags != 0; i++) {
		bit = bd[i].bit;
		name = bd[i].name;
		if (bit == 0 && flags != 0) {
			/* print any unnamed bits */
			snprintf(hexstr, 16, "0x%X", flags);
			name = hexstr;
			flags = 0;	/* exit loop */
		} else if ((flags & bit) == 0)
			continue;
		flags &= ~bit;
		nlen = strlen(name);
		slen += nlen;
		/* count btwn flag space */
		if (flags != 0)
			slen += 1;
		/* need NULL char as well */
		if (len <= slen)
			break;
		/* copy NULL char but don't count it */
		strncpy(p, name, nlen + 1);
		p += nlen;
		/* copy btwn flag space and NULL char */
		if (flags != 0)
			p += snprintf(p, 2, " ");
	}

	/* indicate the str was too short */
	if (flags != 0) {
		if (len < 2)
			p -= 2 - len;	/* overwrite last char */
		p += snprintf(p, 2, ">");
	}

	return (int)(p - buf);
}

/* print bytes formatted as hex to a string. return the resulting string length */
int
bcm_format_hex(char *str, const void *bytes, int len)
{
	int i;
	char *p = str;
	const uint8 *src = (const uint8*)bytes;

	for (i = 0; i < len; i++) {
		p += snprintf(p, 3, "%02X", *src);
		src++;
	}
	return (int)(p - str);
}
#endif 

/* pretty hex print a contiguous buffer */
void
prhex(const char *msg, uchar *buf, uint nbytes)
{
	char line[128], *p;
	int len = sizeof(line);
	int nchar;
	uint i;

	if (msg && (msg[0] != '\0'))
		printf("%s:\n", msg);

	p = line;
	for (i = 0; i < nbytes; i++) {
		if (i % 16 == 0) {
			nchar = snprintf(p, len, "  %04d: ", i);	/* line prefix */
			p += nchar;
			len -= nchar;
		}
		if (len > 0) {
			nchar = snprintf(p, len, "%02x ", buf[i]);
			p += nchar;
			len -= nchar;
		}

		if (i % 16 == 15) {
			printf("%s\n", line);		/* flush line */
			p = line;
			len = sizeof(line);
		}
	}

	/* flush last partial line */
	if (p != line)
		printf("%s\n", line);
}

static const char *crypto_algo_names[] = {
	"NONE",
	"WEP1",
	"TKIP",
	"WEP128",
	"AES_CCM",
	"AES_OCB_MSDU",
	"AES_OCB_MPDU",
	"NALG"
	"UNDEF",
	"UNDEF",
	"UNDEF",
	"UNDEF"
};

const char *
bcm_crypto_algo_name(uint algo)
{
	return (algo < ARRAYSIZE(crypto_algo_names)) ? crypto_algo_names[algo] : "ERR";
}

#ifdef BCMDBG
void
deadbeef(void *p, uint len)
{
	static uint8 meat[] = { 0xde, 0xad, 0xbe, 0xef };

	while (len-- > 0) {
		*(uint8*)p = meat[((uintptr)p) & 3];
		p = (uint8*)p + 1;
	}
}
#endif /* BCMDBG */

char *
bcm_chipname(uint chipid, char *buf, uint len)
{
	const char *fmt;

	fmt = ((chipid > 0xa000) || (chipid < 0x4000)) ? "%d" : "%x";
	snprintf(buf, len, fmt, chipid);
	return buf;
}

/* Produce a human-readable string for boardrev */
char *
bcm_brev_str(uint32 brev, char *buf)
{
	if (brev < 0x100)
		snprintf(buf, 8, "%d.%d", (brev & 0xf0) >> 4, brev & 0xf);
	else
		snprintf(buf, 8, "%c%03x", ((brev & 0xf000) == 0x1000) ? 'P' : 'A', brev & 0xfff);

	return (buf);
}

#define BUFSIZE_TODUMP_ATONCE 512 /* Buffer size */

/* dump large strings to console */
void
printbig(char *buf)
{
	uint len, max_len;
	char c;

	len = strlen(buf);

	max_len = BUFSIZE_TODUMP_ATONCE;

	while (len > max_len) {
		c = buf[max_len];
		buf[max_len] = '\0';
		printf("%s", buf);
		buf[max_len] = c;

		buf += max_len;
		len -= max_len;
	}
	/* print the remaining string */
	printf("%s\n", buf);
	return;
}

/* routine to dump fields in a fileddesc structure */
uint
bcmdumpfields(bcmutl_rdreg_rtn read_rtn, void *arg0, uint arg1, struct fielddesc *fielddesc_array,
	char *buf, uint32 bufsize)
{
	uint  filled_len;
	int len;
	struct fielddesc *cur_ptr;

	filled_len = 0;
	cur_ptr = fielddesc_array;

	while (bufsize > 1) {
		if (cur_ptr->nameandfmt == NULL)
			break;
		len = snprintf(buf, bufsize, cur_ptr->nameandfmt,
		               read_rtn(arg0, arg1, cur_ptr->offset));
		/* check for snprintf overflow or error */
		if (len < 0 || (uint32)len >= bufsize)
			len = bufsize - 1;
		buf += len;
		bufsize -= len;
		filled_len += len;
		cur_ptr++;
	}
	return filled_len;
}

uint
bcm_mkiovar(char *name, char *data, uint datalen, char *buf, uint buflen)
{
	uint len;

	len = strlen(name) + 1;

	if ((len + datalen) > buflen)
		return 0;

	strncpy(buf, name, buflen);

	/* append data onto the end of the name string */
	memcpy(&buf[len], data, datalen);
	len += datalen;

	return len;
}

/* Quarter dBm units to mW
 * Table starts at QDBM_OFFSET, so the first entry is mW for qdBm=153
 * Table is offset so the last entry is largest mW value that fits in
 * a uint16.
 */

#define QDBM_OFFSET 153		/* Offset for first entry */
#define QDBM_TABLE_LEN 40	/* Table size */

/* Smallest mW value that will round up to the first table entry, QDBM_OFFSET.
 * Value is ( mW(QDBM_OFFSET - 1) + mW(QDBM_OFFSET) ) / 2
 */
#define QDBM_TABLE_LOW_BOUND 6493 /* Low bound */

/* Largest mW value that will round down to the last table entry,
 * QDBM_OFFSET + QDBM_TABLE_LEN-1.
 * Value is ( mW(QDBM_OFFSET + QDBM_TABLE_LEN - 1) + mW(QDBM_OFFSET + QDBM_TABLE_LEN) ) / 2.
 */
#define QDBM_TABLE_HIGH_BOUND 64938 /* High bound */

static const uint16 nqdBm_to_mW_map[QDBM_TABLE_LEN] = {
/* qdBm: 	+0 	+1 	+2 	+3 	+4 	+5 	+6 	+7 */
/* 153: */      6683,	7079,	7499,	7943,	8414,	8913,	9441,	10000,
/* 161: */      10593,	11220,	11885,	12589,	13335,	14125,	14962,	15849,
/* 169: */      16788,	17783,	18836,	19953,	21135,	22387,	23714,	25119,
/* 177: */      26607,	28184,	29854,	31623,	33497,	35481,	37584,	39811,
/* 185: */      42170,	44668,	47315,	50119,	53088,	56234,	59566,	63096
};

uint16
BCMROMFN(bcm_qdbm_to_mw)(uint8 qdbm)
{
	uint factor = 1;
	int idx = qdbm - QDBM_OFFSET;

	if (idx >= QDBM_TABLE_LEN) {
		/* clamp to max uint16 mW value */
		return 0xFFFF;
	}

	/* scale the qdBm index up to the range of the table 0-40
	 * where an offset of 40 qdBm equals a factor of 10 mW.
	 */
	while (idx < 0) {
		idx += 40;
		factor *= 10;
	}

	/* return the mW value scaled down to the correct factor of 10,
	 * adding in factor/2 to get proper rounding.
	 */
	return ((nqdBm_to_mW_map[idx] + factor/2) / factor);
}

uint8
BCMROMFN(bcm_mw_to_qdbm)(uint16 mw)
{
	uint8 qdbm;
	int offset;
	uint mw_uint = mw;
	uint boundary;

	/* handle boundary case */
	if (mw_uint <= 1)
		return 0;

	offset = QDBM_OFFSET;

	/* move mw into the range of the table */
	while (mw_uint < QDBM_TABLE_LOW_BOUND) {
		mw_uint *= 10;
		offset -= 40;
	}

	for (qdbm = 0; qdbm < QDBM_TABLE_LEN-1; qdbm++) {
		boundary = nqdBm_to_mW_map[qdbm] + (nqdBm_to_mW_map[qdbm+1] -
		                                    nqdBm_to_mW_map[qdbm])/2;
		if (mw_uint < boundary) break;
	}

	qdbm += (uint8)offset;

	return (qdbm);
}


uint
BCMROMFN(bcm_bitcount)(uint8 *bitmap, uint length)
{
	uint bitcount = 0, i;
	uint8 tmp;
	for (i = 0; i < length; i++) {
		tmp = bitmap[i];
		while (tmp) {
			bitcount++;
			tmp &= (tmp - 1);
		}
	}
	return bitcount;
}

#ifdef BCMDRIVER

/* Initialization of bcmstrbuf structure */
void
bcm_binit(struct bcmstrbuf *b, char *buf, uint size)
{
	b->origsize = b->size = size;
	b->origbuf = b->buf = buf;
}

/* Buffer sprintf wrapper to guard against buffer overflow */
int
bcm_bprintf(struct bcmstrbuf *b, const char *fmt, ...)
{
	va_list ap;
	int r;

	va_start(ap, fmt);

	r = vsnprintf(b->buf, b->size, fmt, ap);

	/* Non Ansi C99 compliant returns -1,
	 * Ansi compliant return r >= b->size,
	 * bcmstdlib returns 0, handle all
	 */
	/* r == 0 is also the case when strlen(fmt) is zero.
	 * typically the case when "" is passed as argument.
	 */
	if ((r == -1) || (r >= (int)b->size)) {
		b->size = 0;
	} else {
		b->size -= r;
		b->buf += r;
	}

	va_end(ap);

	return r;
}

void
bcm_bprhex(struct bcmstrbuf *b, const char *msg, bool newline, uint8 *buf, int len)
{
	int i;

	if (msg != NULL && msg[0] != '\0')
		bcm_bprintf(b, "%s", msg);
	for (i = 0; i < len; i ++)
		bcm_bprintf(b, "%02X", buf[i]);
	if (newline)
		bcm_bprintf(b, "\n");
}

void
bcm_inc_bytes(uchar *num, int num_bytes, uint8 amount)
{
	int i;

	for (i = 0; i < num_bytes; i++) {
		num[i] += amount;
		if (num[i] >= amount)
			break;
		amount = 1;
	}
}

int
bcm_cmp_bytes(const uchar *arg1, const uchar *arg2, uint8 nbytes)
{
	int i;

	for (i = nbytes - 1; i >= 0; i--) {
		if (arg1[i] != arg2[i])
			return (arg1[i] - arg2[i]);
	}
	return 0;
}

void
bcm_print_bytes(const char *name, const uchar *data, int len)
{
	int i;
	int per_line = 0;

	printf("%s: %d \n", name ? name : "", len);
	for (i = 0; i < len; i++) {
		printf("%02x ", *data++);
		per_line++;
		if (per_line == 16) {
			per_line = 0;
			printf("\n");
		}
	}
	printf("\n");
}
#if defined(WLTINYDUMP) || defined(BCMDBG) || defined(WLMSG_INFORM) || \
	defined(WLMSG_ASSOC) || defined(WLMSG_PRPKT) || defined(WLMSG_WSEC)
#define SSID_FMT_BUF_LEN	((4 * DOT11_MAX_SSID_LEN) + 1)

int
bcm_format_ssid(char* buf, const uchar ssid[], uint ssid_len)
{
	uint i, c;
	char *p = buf;
	char *endp = buf + SSID_FMT_BUF_LEN;

	if (ssid_len > DOT11_MAX_SSID_LEN) ssid_len = DOT11_MAX_SSID_LEN;

	for (i = 0; i < ssid_len; i++) {
		c = (uint)ssid[i];
		if (c == '\\') {
			*p++ = '\\';
			*p++ = '\\';
		} else if (bcm_isprint((uchar)c)) {
			*p++ = (char)c;
		} else {
			p += snprintf(p, (endp - p), "\\x%02X", c);
		}
	}
	*p = '\0';
	ASSERT(p < endp);

	return (int)(p - buf);
}
#endif /* WLTINYDUMP || BCMDBG || WLMSG_INFORM || WLMSG_ASSOC || WLMSG_PRPKT */

#endif /* BCMDRIVER */

/*
 * ProcessVars:Takes a buffer of "<var>=<value>\n" lines read from a file and ending in a NUL.
 * also accepts nvram files which are already in the format of <var1>=<value>\0\<var2>=<value2>\0
 * Removes carriage returns, empty lines, comment lines, and converts newlines to NULs.
 * Shortens buffer as needed and pads with NULs.  End of buffer is marked by two NULs.
*/

unsigned int
process_nvram_vars(char *varbuf, unsigned int len)
{
	char *dp;
	bool findNewline;
	int column;
	unsigned int buf_len, n;
	unsigned int pad = 0;

	dp = varbuf;

	findNewline = FALSE;
	column = 0;

	for (n = 0; n < len; n++) {
		if (varbuf[n] == '\r')
			continue;
		if (findNewline && varbuf[n] != '\n')
			continue;
		findNewline = FALSE;
		if (varbuf[n] == '#') {
			findNewline = TRUE;
			continue;
		}
		if (varbuf[n] == '\n') {
			if (column == 0)
				continue;
			*dp++ = 0;
			column = 0;
			continue;
		}
		*dp++ = varbuf[n];
		column++;
	}
	buf_len = (unsigned int)(dp - varbuf);
	if (buf_len % 4) {
		pad = 4 - buf_len % 4;
		if (pad && (buf_len + pad <= len)) {
			buf_len += pad;
		}
	}

	while (dp < varbuf + n)
		*dp++ = 0;

	return buf_len;
}

/* calculate a * b + c */
void
bcm_uint64_multiple_add(uint32* r_high, uint32* r_low, uint32 a, uint32 b, uint32 c)
{
#define FORMALIZE(var) {cc += (var & 0x80000000) ? 1 : 0; var &= 0x7fffffff;}
	uint32 r1, r0;
	uint32 a1, a0, b1, b0, t, cc = 0;

	a1 = a >> 16;
	a0 = a & 0xffff;
	b1 = b >> 16;
	b0 = b & 0xffff;

	r0 = a0 * b0;
	FORMALIZE(r0);

	t = (a1 * b0) << 16;
	FORMALIZE(t);

	r0 += t;
	FORMALIZE(r0);

	t = (a0 * b1) << 16;
	FORMALIZE(t);

	r0 += t;
	FORMALIZE(r0);

	FORMALIZE(c);

	r0 += c;
	FORMALIZE(r0);

	r0 |= (cc % 2) ? 0x80000000 : 0;
	r1 = a1 * b1 + ((a1 * b0) >> 16) + ((b1 * a0) >> 16) + (cc / 2);

	*r_high = r1;
	*r_low = r0;
}

/* calculate a / b */
void
bcm_uint64_divide(uint32* r, uint32 a_high, uint32 a_low, uint32 b)
{
	uint32 a1 = a_high, a0 = a_low, r0 = 0;

	if (b < 2)
		return;

	while (a1 != 0) {
		r0 += (0xffffffff / b) * a1;
		bcm_uint64_multiple_add(&a1, &a0, ((0xffffffff % b) + 1) % b, a1, a0);
	}

	r0 += a0 / b;
	*r = r0;
}

/* calculate a >> b; and returns only lower 32 bits */
void
bcm_uint64_right_shift(uint32* r, uint32 a_high, uint32 a_low, uint32 b)
{
	uint32 a1 = a_high, a0 = a_low, r0 = 0;

	if (b == 0) {
		r0 = a_low;
		*r = r0;
		return;
	}

	if (b < 32) {
		a0 = a0 >> b;
		a1 = a1 & ((1 << b) - 1);
		a1 = a1 << (32 - b);
		r0 = a0 | a1;
		*r = r0;
		return;
	} else {
		r0 = a1 >> (b - 32);
		*r = r0;
		return;
	}

}
