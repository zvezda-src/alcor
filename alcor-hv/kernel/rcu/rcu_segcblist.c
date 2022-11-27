
#include <linux/cpu.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/types.h>

#include "rcu_segcblist.h"

void rcu_cblist_init(struct rcu_cblist *rclp)
{
	rclp->head = NULL;
	rclp->tail = &rclp->head;
	rclp->len = 0;
}

void rcu_cblist_enqueue(struct rcu_cblist *rclp, struct rcu_head *rhp)
{
	rclp->tail = &rhp->next;
	WRITE_ONCE(rclp->len, rclp->len + 1);
}

void rcu_cblist_flush_enqueue(struct rcu_cblist *drclp,
			      struct rcu_cblist *srclp,
			      struct rcu_head *rhp)
{
	drclp->head = srclp->head;
	if (drclp->head)
		drclp->tail = srclp->tail;
	else
		drclp->tail = &drclp->head;
	drclp->len = srclp->len;
	if (!rhp) {
		rcu_cblist_init(srclp);
	} else {
		rhp->next = NULL;
		srclp->head = rhp;
		srclp->tail = &rhp->next;
		WRITE_ONCE(srclp->len, 1);
	}
}

struct rcu_head *rcu_cblist_dequeue(struct rcu_cblist *rclp)
{
	struct rcu_head *rhp;

	rhp = rclp->head;
	if (!rhp)
		return NULL;
	rclp->len--;
	rclp->head = rhp->next;
	if (!rclp->head)
		rclp->tail = &rclp->head;
	return rhp;
}

static void rcu_segcblist_set_len(struct rcu_segcblist *rsclp, long v)
{
#ifdef CONFIG_RCU_NOCB_CPU
	atomic_long_set(&rsclp->len, v);
#else
	WRITE_ONCE(rsclp->len, v);
#endif
}

static long rcu_segcblist_get_seglen(struct rcu_segcblist *rsclp, int seg)
{
	return READ_ONCE(rsclp->seglen[seg]);
}

long rcu_segcblist_n_segment_cbs(struct rcu_segcblist *rsclp)
{
	long len = 0;
	int i;

	for (i = RCU_DONE_TAIL; i < RCU_CBLIST_NSEGS; i++)
		len += rcu_segcblist_get_seglen(rsclp, i);

	return len;
}

static void rcu_segcblist_set_seglen(struct rcu_segcblist *rsclp, int seg, long v)
{
	WRITE_ONCE(rsclp->seglen[seg], v);
}

static void rcu_segcblist_add_seglen(struct rcu_segcblist *rsclp, int seg, long v)
{
	WRITE_ONCE(rsclp->seglen[seg], rsclp->seglen[seg] + v);
}

static void rcu_segcblist_move_seglen(struct rcu_segcblist *rsclp, int from, int to)
{
	long len;

	if (from == to)
		return;

	len = rcu_segcblist_get_seglen(rsclp, from);
	if (!len)
		return;

	rcu_segcblist_add_seglen(rsclp, to, len);
	rcu_segcblist_set_seglen(rsclp, from, 0);
}

static void rcu_segcblist_inc_seglen(struct rcu_segcblist *rsclp, int seg)
{
	rcu_segcblist_add_seglen(rsclp, seg, 1);
}

void rcu_segcblist_add_len(struct rcu_segcblist *rsclp, long v)
{
#ifdef CONFIG_RCU_NOCB_CPU
	smp_mb__before_atomic(); // Read header comment above.
	atomic_long_add(v, &rsclp->len);
	smp_mb__after_atomic();  // Read header comment above.
#else
	smp_mb(); // Read header comment above.
	WRITE_ONCE(rsclp->len, rsclp->len + v);
	smp_mb(); // Read header comment above.
#endif
}

void rcu_segcblist_inc_len(struct rcu_segcblist *rsclp)
{
	rcu_segcblist_add_len(rsclp, 1);
}

void rcu_segcblist_init(struct rcu_segcblist *rsclp)
{
	int i;

	BUILD_BUG_ON(RCU_NEXT_TAIL + 1 != ARRAY_SIZE(rsclp->gp_seq));
	BUILD_BUG_ON(ARRAY_SIZE(rsclp->tails) != ARRAY_SIZE(rsclp->gp_seq));
	rsclp->head = NULL;
	for (i = 0; i < RCU_CBLIST_NSEGS; i++) {
		rsclp->tails[i] = &rsclp->head;
		rcu_segcblist_set_seglen(rsclp, i, 0);
	}
	rcu_segcblist_set_len(rsclp, 0);
	rcu_segcblist_set_flags(rsclp, SEGCBLIST_ENABLED);
}

void rcu_segcblist_disable(struct rcu_segcblist *rsclp)
{
	WARN_ON_ONCE(!rcu_segcblist_empty(rsclp));
	WARN_ON_ONCE(rcu_segcblist_n_cbs(rsclp));
	rcu_segcblist_clear_flags(rsclp, SEGCBLIST_ENABLED);
}

void rcu_segcblist_offload(struct rcu_segcblist *rsclp, bool offload)
{
	if (offload)
		rcu_segcblist_set_flags(rsclp, SEGCBLIST_LOCKING | SEGCBLIST_OFFLOADED);
	else
		rcu_segcblist_clear_flags(rsclp, SEGCBLIST_OFFLOADED);
}

bool rcu_segcblist_ready_cbs(struct rcu_segcblist *rsclp)
{
	return rcu_segcblist_is_enabled(rsclp) &&
	       &rsclp->head != READ_ONCE(rsclp->tails[RCU_DONE_TAIL]);
}

bool rcu_segcblist_pend_cbs(struct rcu_segcblist *rsclp)
{
	return rcu_segcblist_is_enabled(rsclp) &&
	       !rcu_segcblist_restempty(rsclp, RCU_DONE_TAIL);
}

struct rcu_head *rcu_segcblist_first_cb(struct rcu_segcblist *rsclp)
{
	if (rcu_segcblist_is_enabled(rsclp))
		return rsclp->head;
	return NULL;
}

struct rcu_head *rcu_segcblist_first_pend_cb(struct rcu_segcblist *rsclp)
{
	if (rcu_segcblist_is_enabled(rsclp))
		return *rsclp->tails[RCU_DONE_TAIL];
	return NULL;
}

bool rcu_segcblist_nextgp(struct rcu_segcblist *rsclp, unsigned long *lp)
{
	if (!rcu_segcblist_pend_cbs(rsclp))
		return false;
	return true;
}

void rcu_segcblist_enqueue(struct rcu_segcblist *rsclp,
			   struct rcu_head *rhp)
{
	rcu_segcblist_inc_len(rsclp);
	rcu_segcblist_inc_seglen(rsclp, RCU_NEXT_TAIL);
	rhp->next = NULL;
	WRITE_ONCE(*rsclp->tails[RCU_NEXT_TAIL], rhp);
	WRITE_ONCE(rsclp->tails[RCU_NEXT_TAIL], &rhp->next);
}

bool rcu_segcblist_entrain(struct rcu_segcblist *rsclp,
			   struct rcu_head *rhp)
{
	int i;

	if (rcu_segcblist_n_cbs(rsclp) == 0)
		return false;
	rcu_segcblist_inc_len(rsclp);
	smp_mb(); /* Ensure counts are updated before callback is entrained. */
	rhp->next = NULL;
	for (i = RCU_NEXT_TAIL; i > RCU_DONE_TAIL; i--)
		if (rsclp->tails[i] != rsclp->tails[i - 1])
			break;
	rcu_segcblist_inc_seglen(rsclp, i);
	WRITE_ONCE(*rsclp->tails[i], rhp);
	for (; i <= RCU_NEXT_TAIL; i++)
		WRITE_ONCE(rsclp->tails[i], &rhp->next);
	return true;
}

void rcu_segcblist_extract_done_cbs(struct rcu_segcblist *rsclp,
				    struct rcu_cblist *rclp)
{
	int i;

	if (!rcu_segcblist_ready_cbs(rsclp))
		return; /* Nothing to do. */
	rclp->len = rcu_segcblist_get_seglen(rsclp, RCU_DONE_TAIL);
	WRITE_ONCE(rsclp->head, *rsclp->tails[RCU_DONE_TAIL]);
	WRITE_ONCE(*rsclp->tails[RCU_DONE_TAIL], NULL);
	rclp->tail = rsclp->tails[RCU_DONE_TAIL];
	for (i = RCU_CBLIST_NSEGS - 1; i >= RCU_DONE_TAIL; i--)
		if (rsclp->tails[i] == rsclp->tails[RCU_DONE_TAIL])
			WRITE_ONCE(rsclp->tails[i], &rsclp->head);
	rcu_segcblist_set_seglen(rsclp, RCU_DONE_TAIL, 0);
}

void rcu_segcblist_extract_pend_cbs(struct rcu_segcblist *rsclp,
				    struct rcu_cblist *rclp)
{
	int i;

	if (!rcu_segcblist_pend_cbs(rsclp))
		return; /* Nothing to do. */
	rclp->len = 0;
	rclp->tail = rsclp->tails[RCU_NEXT_TAIL];
	WRITE_ONCE(*rsclp->tails[RCU_DONE_TAIL], NULL);
	for (i = RCU_DONE_TAIL + 1; i < RCU_CBLIST_NSEGS; i++) {
		rclp->len += rcu_segcblist_get_seglen(rsclp, i);
		WRITE_ONCE(rsclp->tails[i], rsclp->tails[RCU_DONE_TAIL]);
		rcu_segcblist_set_seglen(rsclp, i, 0);
	}
}

void rcu_segcblist_insert_count(struct rcu_segcblist *rsclp,
				struct rcu_cblist *rclp)
{
	rcu_segcblist_add_len(rsclp, rclp->len);
}

void rcu_segcblist_insert_done_cbs(struct rcu_segcblist *rsclp,
				   struct rcu_cblist *rclp)
{
	int i;

	if (!rclp->head)
		return; /* No callbacks to move. */
	rcu_segcblist_add_seglen(rsclp, RCU_DONE_TAIL, rclp->len);
	WRITE_ONCE(rsclp->head, rclp->head);
	for (i = RCU_DONE_TAIL; i < RCU_CBLIST_NSEGS; i++)
		if (&rsclp->head == rsclp->tails[i])
			WRITE_ONCE(rsclp->tails[i], rclp->tail);
		else
			break;
	rclp->head = NULL;
	rclp->tail = &rclp->head;
}

void rcu_segcblist_insert_pend_cbs(struct rcu_segcblist *rsclp,
				   struct rcu_cblist *rclp)
{
	if (!rclp->head)
		return; /* Nothing to do. */

	rcu_segcblist_add_seglen(rsclp, RCU_NEXT_TAIL, rclp->len);
	WRITE_ONCE(*rsclp->tails[RCU_NEXT_TAIL], rclp->head);
	WRITE_ONCE(rsclp->tails[RCU_NEXT_TAIL], rclp->tail);
}

void rcu_segcblist_advance(struct rcu_segcblist *rsclp, unsigned long seq)
{
	int i, j;

	WARN_ON_ONCE(!rcu_segcblist_is_enabled(rsclp));
	if (rcu_segcblist_restempty(rsclp, RCU_DONE_TAIL))
		return;

	/*
	for (i = RCU_WAIT_TAIL; i < RCU_NEXT_TAIL; i++) {
		if (ULONG_CMP_LT(seq, rsclp->gp_seq[i]))
			break;
		WRITE_ONCE(rsclp->tails[RCU_DONE_TAIL], rsclp->tails[i]);
		rcu_segcblist_move_seglen(rsclp, i, RCU_DONE_TAIL);
	}

	/* If no callbacks moved, nothing more need be done. */
	if (i == RCU_WAIT_TAIL)
		return;

	/* Clean up tail pointers that might have been misordered above. */
	for (j = RCU_WAIT_TAIL; j < i; j++)
		WRITE_ONCE(rsclp->tails[j], rsclp->tails[RCU_DONE_TAIL]);

	/*
	for (j = RCU_WAIT_TAIL; i < RCU_NEXT_TAIL; i++, j++) {
		if (rsclp->tails[j] == rsclp->tails[RCU_NEXT_TAIL])
			break;  /* No more callbacks. */
		WRITE_ONCE(rsclp->tails[j], rsclp->tails[i]);
		rcu_segcblist_move_seglen(rsclp, i, j);
		rsclp->gp_seq[j] = rsclp->gp_seq[i];
	}
}

bool rcu_segcblist_accelerate(struct rcu_segcblist *rsclp, unsigned long seq)
{
	int i, j;

	WARN_ON_ONCE(!rcu_segcblist_is_enabled(rsclp));
	if (rcu_segcblist_restempty(rsclp, RCU_DONE_TAIL))
		return false;

	/*
	for (i = RCU_NEXT_READY_TAIL; i > RCU_DONE_TAIL; i--)
		if (rsclp->tails[i] != rsclp->tails[i - 1] &&
		    ULONG_CMP_LT(rsclp->gp_seq[i], seq))
			break;

	/*
	if (rcu_segcblist_restempty(rsclp, i) || ++i >= RCU_NEXT_TAIL)
		return false;

	/* Accounting: everything below i is about to get merged into i. */
	for (j = i + 1; j <= RCU_NEXT_TAIL; j++)
		rcu_segcblist_move_seglen(rsclp, j, i);

	/*
	for (; i < RCU_NEXT_TAIL; i++) {
		WRITE_ONCE(rsclp->tails[i], rsclp->tails[RCU_NEXT_TAIL]);
		rsclp->gp_seq[i] = seq;
	}
	return true;
}

void rcu_segcblist_merge(struct rcu_segcblist *dst_rsclp,
			 struct rcu_segcblist *src_rsclp)
{
	struct rcu_cblist donecbs;
	struct rcu_cblist pendcbs;

	lockdep_assert_cpus_held();

	rcu_cblist_init(&donecbs);
	rcu_cblist_init(&pendcbs);

	rcu_segcblist_extract_done_cbs(src_rsclp, &donecbs);
	rcu_segcblist_extract_pend_cbs(src_rsclp, &pendcbs);

	/*
	rcu_segcblist_set_len(src_rsclp, 0);

	rcu_segcblist_insert_count(dst_rsclp, &donecbs);
	rcu_segcblist_insert_count(dst_rsclp, &pendcbs);
	rcu_segcblist_insert_done_cbs(dst_rsclp, &donecbs);
	rcu_segcblist_insert_pend_cbs(dst_rsclp, &pendcbs);

	rcu_segcblist_init(src_rsclp);
}
