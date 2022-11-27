
#include <linux/kernel.h>
#include <linux/irqflags.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/bug.h>
#include "printk_ringbuffer.h"


#define DATA_SIZE(data_ring)		_DATA_SIZE((data_ring)->size_bits)
#define DATA_SIZE_MASK(data_ring)	(DATA_SIZE(data_ring) - 1)

#define DESCS_COUNT(desc_ring)		_DESCS_COUNT((desc_ring)->count_bits)
#define DESCS_COUNT_MASK(desc_ring)	(DESCS_COUNT(desc_ring) - 1)

#define DATA_INDEX(data_ring, lpos)	((lpos) & DATA_SIZE_MASK(data_ring))

#define DESC_INDEX(desc_ring, n)	((n) & DESCS_COUNT_MASK(desc_ring))

#define DATA_WRAPS(data_ring, lpos)	((lpos) >> (data_ring)->size_bits)

#define LPOS_DATALESS(lpos)		((lpos) & 1UL)
#define BLK_DATALESS(blk)		(LPOS_DATALESS((blk)->begin) && \
					 LPOS_DATALESS((blk)->next))

#define DATA_THIS_WRAP_START_LPOS(data_ring, lpos) \
((lpos) & ~DATA_SIZE_MASK(data_ring))

#define DESC_ID_PREV_WRAP(desc_ring, id) \
DESC_ID((id) - DESCS_COUNT(desc_ring))

struct prb_data_block {
	unsigned long	id;
	char		data[];
};

static struct prb_desc *to_desc(struct prb_desc_ring *desc_ring, u64 n)
{
	return &desc_ring->descs[DESC_INDEX(desc_ring, n)];
}

static struct printk_info *to_info(struct prb_desc_ring *desc_ring, u64 n)
{
	return &desc_ring->infos[DESC_INDEX(desc_ring, n)];
}

static struct prb_data_block *to_block(struct prb_data_ring *data_ring,
				       unsigned long begin_lpos)
{
	return (void *)&data_ring->data[DATA_INDEX(data_ring, begin_lpos)];
}

static unsigned int to_blk_size(unsigned int size)
{
	struct prb_data_block *db = NULL;

	size += sizeof(*db);
	size = ALIGN(size, sizeof(db->id));
	return size;
}

static bool data_check_size(struct prb_data_ring *data_ring, unsigned int size)
{
	struct prb_data_block *db = NULL;

	if (size == 0)
		return true;

	/*
	size = to_blk_size(size);
	if (size > DATA_SIZE(data_ring) - sizeof(db->id))
		return false;

	return true;
}

static enum desc_state get_desc_state(unsigned long id,
				      unsigned long state_val)
{
	if (id != DESC_ID(state_val))
		return desc_miss;

	return DESC_STATE(state_val);
}

static enum desc_state desc_read(struct prb_desc_ring *desc_ring,
				 unsigned long id, struct prb_desc *desc_out,
				 u64 *seq_out, u32 *caller_id_out)
{
	struct printk_info *info = to_info(desc_ring, id);
	struct prb_desc *desc = to_desc(desc_ring, id);
	atomic_long_t *state_var = &desc->state_var;
	enum desc_state d_state;
	unsigned long state_val;

	/* Check the descriptor state. */
	state_val = atomic_long_read(state_var); /* LMM(desc_read:A) */
	d_state = get_desc_state(id, state_val);
	if (d_state == desc_miss || d_state == desc_reserved) {
		/*
		goto out;
	}

	/*
	smp_rmb(); /* LMM(desc_read:B) */

	/*
	if (desc_out) {
		memcpy(&desc_out->text_blk_lpos, &desc->text_blk_lpos,
		       sizeof(desc_out->text_blk_lpos)); /* LMM(desc_read:C) */
	}
	if (seq_out)
		*seq_out = info->seq; /* also part of desc_read:C */
	if (caller_id_out)
		*caller_id_out = info->caller_id; /* also part of desc_read:C */

	/*
	smp_rmb(); /* LMM(desc_read:D) */

	/*
	state_val = atomic_long_read(state_var); /* LMM(desc_read:E) */
	d_state = get_desc_state(id, state_val);
out:
	if (desc_out)
		atomic_long_set(&desc_out->state_var, state_val);
	return d_state;
}

static void desc_make_reusable(struct prb_desc_ring *desc_ring,
			       unsigned long id)
{
	unsigned long val_finalized = DESC_SV(id, desc_finalized);
	unsigned long val_reusable = DESC_SV(id, desc_reusable);
	struct prb_desc *desc = to_desc(desc_ring, id);
	atomic_long_t *state_var = &desc->state_var;

	atomic_long_cmpxchg_relaxed(state_var, val_finalized,
				    val_reusable); /* LMM(desc_make_reusable:A) */
}

static bool data_make_reusable(struct printk_ringbuffer *rb,
			       unsigned long lpos_begin,
			       unsigned long lpos_end,
			       unsigned long *lpos_out)
{

	struct prb_data_ring *data_ring = &rb->text_data_ring;
	struct prb_desc_ring *desc_ring = &rb->desc_ring;
	struct prb_data_block *blk;
	enum desc_state d_state;
	struct prb_desc desc;
	struct prb_data_blk_lpos *blk_lpos = &desc.text_blk_lpos;
	unsigned long id;

	/* Loop until @lpos_begin has advanced to or beyond @lpos_end. */
	while ((lpos_end - lpos_begin) - 1 < DATA_SIZE(data_ring)) {
		blk = to_block(data_ring, lpos_begin);

		/*
		id = blk->id; /* LMM(data_make_reusable:A) */

		d_state = desc_read(desc_ring, id, &desc,
				    NULL, NULL); /* LMM(data_make_reusable:B) */

		switch (d_state) {
		case desc_miss:
		case desc_reserved:
		case desc_committed:
			return false;
		case desc_finalized:
			/*
			if (blk_lpos->begin != lpos_begin)
				return false;
			desc_make_reusable(desc_ring, id);
			break;
		case desc_reusable:
			/*
			if (blk_lpos->begin != lpos_begin)
				return false;
			break;
		}

		/* Advance @lpos_begin to the next data block. */
		lpos_begin = blk_lpos->next;
	}

	return true;
}

static bool data_push_tail(struct printk_ringbuffer *rb, unsigned long lpos)
{
	struct prb_data_ring *data_ring = &rb->text_data_ring;
	unsigned long tail_lpos_new;
	unsigned long tail_lpos;
	unsigned long next_lpos;

	/* If @lpos is from a data-less block, there is nothing to do. */
	if (LPOS_DATALESS(lpos))
		return true;

	/*
	tail_lpos = atomic_long_read(&data_ring->tail_lpos); /* LMM(data_push_tail:A) */

	/*
	while ((lpos - tail_lpos) - 1 < DATA_SIZE(data_ring)) {
		/*
		if (!data_make_reusable(rb, tail_lpos, lpos, &next_lpos)) {
			/*
			smp_rmb(); /* LMM(data_push_tail:B) */

			tail_lpos_new = atomic_long_read(&data_ring->tail_lpos
							); /* LMM(data_push_tail:C) */
			if (tail_lpos_new == tail_lpos)
				return false;

			/* Another CPU pushed the tail. Try again. */
			tail_lpos = tail_lpos_new;
			continue;
		}

		/*
		if (atomic_long_try_cmpxchg(&data_ring->tail_lpos, &tail_lpos,
					    next_lpos)) { /* LMM(data_push_tail:D) */
			break;
		}
	}

	return true;
}

static bool desc_push_tail(struct printk_ringbuffer *rb,
			   unsigned long tail_id)
{
	struct prb_desc_ring *desc_ring = &rb->desc_ring;
	enum desc_state d_state;
	struct prb_desc desc;

	d_state = desc_read(desc_ring, tail_id, &desc, NULL, NULL);

	switch (d_state) {
	case desc_miss:
		/*
		if (DESC_ID(atomic_long_read(&desc.state_var)) ==
		    DESC_ID_PREV_WRAP(desc_ring, tail_id)) {
			return false;
		}

		/*
		return true;
	case desc_reserved:
	case desc_committed:
		return false;
	case desc_finalized:
		desc_make_reusable(desc_ring, tail_id);
		break;
	case desc_reusable:
		break;
	}

	/*

	if (!data_push_tail(rb, desc.text_blk_lpos.next))
		return false;

	/*
	d_state = desc_read(desc_ring, DESC_ID(tail_id + 1), &desc,
			    NULL, NULL); /* LMM(desc_push_tail:A) */

	if (d_state == desc_finalized || d_state == desc_reusable) {
		/*
		atomic_long_cmpxchg(&desc_ring->tail_id, tail_id,
				    DESC_ID(tail_id + 1)); /* LMM(desc_push_tail:B) */
	} else {
		/*
		smp_rmb(); /* LMM(desc_push_tail:C) */

		/*
		if (atomic_long_read(&desc_ring->tail_id) == tail_id) /* LMM(desc_push_tail:D) */
			return false;
	}

	return true;
}

static bool desc_reserve(struct printk_ringbuffer *rb, unsigned long *id_out)
{
	struct prb_desc_ring *desc_ring = &rb->desc_ring;
	unsigned long prev_state_val;
	unsigned long id_prev_wrap;
	struct prb_desc *desc;
	unsigned long head_id;
	unsigned long id;

	head_id = atomic_long_read(&desc_ring->head_id); /* LMM(desc_reserve:A) */

	do {
		id = DESC_ID(head_id + 1);
		id_prev_wrap = DESC_ID_PREV_WRAP(desc_ring, id);

		/*
		smp_rmb(); /* LMM(desc_reserve:B) */

		if (id_prev_wrap == atomic_long_read(&desc_ring->tail_id
						    )) { /* LMM(desc_reserve:C) */
			/*
			if (!desc_push_tail(rb, id_prev_wrap))
				return false;
		}

		/*
	} while (!atomic_long_try_cmpxchg(&desc_ring->head_id, &head_id,
					  id)); /* LMM(desc_reserve:D) */

	desc = to_desc(desc_ring, id);

	/*
	prev_state_val = atomic_long_read(&desc->state_var); /* LMM(desc_reserve:E) */
	if (prev_state_val &&
	    get_desc_state(id_prev_wrap, prev_state_val) != desc_reusable) {
		WARN_ON_ONCE(1);
		return false;
	}

	/*
	if (!atomic_long_try_cmpxchg(&desc->state_var, &prev_state_val,
			DESC_SV(id, desc_reserved))) { /* LMM(desc_reserve:F) */
		WARN_ON_ONCE(1);
		return false;
	}

	/* Now data in @desc can be modified: LMM(desc_reserve:G) */

	return true;
}

static unsigned long get_next_lpos(struct prb_data_ring *data_ring,
				   unsigned long lpos, unsigned int size)
{
	unsigned long begin_lpos;
	unsigned long next_lpos;

	begin_lpos = lpos;
	next_lpos = lpos + size;

	/* First check if the data block does not wrap. */
	if (DATA_WRAPS(data_ring, begin_lpos) == DATA_WRAPS(data_ring, next_lpos))
		return next_lpos;

	/* Wrapping data blocks store their data at the beginning. */
	return (DATA_THIS_WRAP_START_LPOS(data_ring, next_lpos) + size);
}

static char *data_alloc(struct printk_ringbuffer *rb, unsigned int size,
			struct prb_data_blk_lpos *blk_lpos, unsigned long id)
{
	struct prb_data_ring *data_ring = &rb->text_data_ring;
	struct prb_data_block *blk;
	unsigned long begin_lpos;
	unsigned long next_lpos;

	if (size == 0) {
		/* Specify a data-less block. */
		blk_lpos->begin = NO_LPOS;
		blk_lpos->next = NO_LPOS;
		return NULL;
	}

	size = to_blk_size(size);

	begin_lpos = atomic_long_read(&data_ring->head_lpos);

	do {
		next_lpos = get_next_lpos(data_ring, begin_lpos, size);

		if (!data_push_tail(rb, next_lpos - DATA_SIZE(data_ring))) {
			/* Failed to allocate, specify a data-less block. */
			blk_lpos->begin = FAILED_LPOS;
			blk_lpos->next = FAILED_LPOS;
			return NULL;
		}

		/*
	} while (!atomic_long_try_cmpxchg(&data_ring->head_lpos, &begin_lpos,
					  next_lpos)); /* LMM(data_alloc:A) */

	blk = to_block(data_ring, begin_lpos);
	blk->id = id; /* LMM(data_alloc:B) */

	if (DATA_WRAPS(data_ring, begin_lpos) != DATA_WRAPS(data_ring, next_lpos)) {
		/* Wrapping data blocks store their data at the beginning. */
		blk = to_block(data_ring, 0);

		/*
		blk->id = id;
	}

	blk_lpos->begin = begin_lpos;
	blk_lpos->next = next_lpos;

	return &blk->data[0];
}

static char *data_realloc(struct printk_ringbuffer *rb, unsigned int size,
			  struct prb_data_blk_lpos *blk_lpos, unsigned long id)
{
	struct prb_data_ring *data_ring = &rb->text_data_ring;
	struct prb_data_block *blk;
	unsigned long head_lpos;
	unsigned long next_lpos;
	bool wrapped;

	/* Reallocation only works if @blk_lpos is the newest data block. */
	head_lpos = atomic_long_read(&data_ring->head_lpos);
	if (head_lpos != blk_lpos->next)
		return NULL;

	/* Keep track if @blk_lpos was a wrapping data block. */
	wrapped = (DATA_WRAPS(data_ring, blk_lpos->begin) != DATA_WRAPS(data_ring, blk_lpos->next));

	size = to_blk_size(size);

	next_lpos = get_next_lpos(data_ring, blk_lpos->begin, size);

	/* If the data block does not increase, there is nothing to do. */
	if (head_lpos - next_lpos < DATA_SIZE(data_ring)) {
		if (wrapped)
			blk = to_block(data_ring, 0);
		else
			blk = to_block(data_ring, blk_lpos->begin);
		return &blk->data[0];
	}

	if (!data_push_tail(rb, next_lpos - DATA_SIZE(data_ring)))
		return NULL;

	/* The memory barrier involvement is the same as data_alloc:A. */
	if (!atomic_long_try_cmpxchg(&data_ring->head_lpos, &head_lpos,
				     next_lpos)) { /* LMM(data_realloc:A) */
		return NULL;
	}

	blk = to_block(data_ring, blk_lpos->begin);

	if (DATA_WRAPS(data_ring, blk_lpos->begin) != DATA_WRAPS(data_ring, next_lpos)) {
		struct prb_data_block *old_blk = blk;

		/* Wrapping data blocks store their data at the beginning. */
		blk = to_block(data_ring, 0);

		/*
		blk->id = id;

		if (!wrapped) {
			/*
			memcpy(&blk->data[0], &old_blk->data[0],
			       (blk_lpos->next - blk_lpos->begin) - sizeof(blk->id));
		}
	}

	blk_lpos->next = next_lpos;

	return &blk->data[0];
}

static unsigned int space_used(struct prb_data_ring *data_ring,
			       struct prb_data_blk_lpos *blk_lpos)
{
	/* Data-less blocks take no space. */
	if (BLK_DATALESS(blk_lpos))
		return 0;

	if (DATA_WRAPS(data_ring, blk_lpos->begin) == DATA_WRAPS(data_ring, blk_lpos->next)) {
		/* Data block does not wrap. */
		return (DATA_INDEX(data_ring, blk_lpos->next) -
			DATA_INDEX(data_ring, blk_lpos->begin));
	}

	/*
	return (DATA_INDEX(data_ring, blk_lpos->next) +
		DATA_SIZE(data_ring) - DATA_INDEX(data_ring, blk_lpos->begin));
}

static const char *get_data(struct prb_data_ring *data_ring,
			    struct prb_data_blk_lpos *blk_lpos,
			    unsigned int *data_size)
{
	struct prb_data_block *db;

	/* Data-less data block description. */
	if (BLK_DATALESS(blk_lpos)) {
		if (blk_lpos->begin == NO_LPOS && blk_lpos->next == NO_LPOS) {
			*data_size = 0;
			return "";
		}
		return NULL;
	}

	/* Regular data block: @begin less than @next and in same wrap. */
	if (DATA_WRAPS(data_ring, blk_lpos->begin) == DATA_WRAPS(data_ring, blk_lpos->next) &&
	    blk_lpos->begin < blk_lpos->next) {
		db = to_block(data_ring, blk_lpos->begin);
		*data_size = blk_lpos->next - blk_lpos->begin;

	/* Wrapping data block: @begin is one wrap behind @next. */
	} else if (DATA_WRAPS(data_ring, blk_lpos->begin + DATA_SIZE(data_ring)) ==
		   DATA_WRAPS(data_ring, blk_lpos->next)) {
		db = to_block(data_ring, 0);
		*data_size = DATA_INDEX(data_ring, blk_lpos->next);

	/* Illegal block description. */
	} else {
		WARN_ON_ONCE(1);
		return NULL;
	}

	/* A valid data block will always be aligned to the ID size. */
	if (WARN_ON_ONCE(blk_lpos->begin != ALIGN(blk_lpos->begin, sizeof(db->id))) ||
	    WARN_ON_ONCE(blk_lpos->next != ALIGN(blk_lpos->next, sizeof(db->id)))) {
		return NULL;
	}

	/* A valid data block will always have at least an ID. */
	if (WARN_ON_ONCE(*data_size < sizeof(db->id)))
		return NULL;

	/* Subtract block ID space from size to reflect data size. */

	return &db->data[0];
}

static struct prb_desc *desc_reopen_last(struct prb_desc_ring *desc_ring,
					 u32 caller_id, unsigned long *id_out)
{
	unsigned long prev_state_val;
	enum desc_state d_state;
	struct prb_desc desc;
	struct prb_desc *d;
	unsigned long id;
	u32 cid;

	id = atomic_long_read(&desc_ring->head_id);

	/*
	d_state = desc_read(desc_ring, id, &desc, NULL, &cid);
	if (d_state != desc_committed || cid != caller_id)
		return NULL;

	d = to_desc(desc_ring, id);

	prev_state_val = DESC_SV(id, desc_committed);

	/*
	if (!atomic_long_try_cmpxchg(&d->state_var, &prev_state_val,
			DESC_SV(id, desc_reserved))) { /* LMM(desc_reopen_last:A) */
		return NULL;
	}

	return d;
}

bool prb_reserve_in_last(struct prb_reserved_entry *e, struct printk_ringbuffer *rb,
			 struct printk_record *r, u32 caller_id, unsigned int max_size)
{
	struct prb_desc_ring *desc_ring = &rb->desc_ring;
	struct printk_info *info;
	unsigned int data_size;
	struct prb_desc *d;
	unsigned long id;

	local_irq_save(e->irqflags);

	/* Transition the newest descriptor back to the reserved state. */
	d = desc_reopen_last(desc_ring, caller_id, &id);
	if (!d) {
		local_irq_restore(e->irqflags);
		goto fail_reopen;
	}

	/* Now the writer has exclusive access: LMM(prb_reserve_in_last:A) */

	info = to_info(desc_ring, id);

	/*
	e->rb = rb;
	e->id = id;

	/*
	if (caller_id != info->caller_id)
		goto fail;

	if (BLK_DATALESS(&d->text_blk_lpos)) {
		if (WARN_ON_ONCE(info->text_len != 0)) {
			pr_warn_once("wrong text_len value (%hu, expecting 0)\n",
				     info->text_len);
			info->text_len = 0;
		}

		if (!data_check_size(&rb->text_data_ring, r->text_buf_size))
			goto fail;

		if (r->text_buf_size > max_size)
			goto fail;

		r->text_buf = data_alloc(rb, r->text_buf_size,
					 &d->text_blk_lpos, id);
	} else {
		if (!get_data(&rb->text_data_ring, &d->text_blk_lpos, &data_size))
			goto fail;

		/*
		if (WARN_ON_ONCE(info->text_len > data_size)) {
			pr_warn_once("wrong text_len value (%hu, expecting <=%u)\n",
				     info->text_len, data_size);
			info->text_len = data_size;
		}
		r->text_buf_size += info->text_len;

		if (!data_check_size(&rb->text_data_ring, r->text_buf_size))
			goto fail;

		if (r->text_buf_size > max_size)
			goto fail;

		r->text_buf = data_realloc(rb, r->text_buf_size,
					   &d->text_blk_lpos, id);
	}
	if (r->text_buf_size && !r->text_buf)
		goto fail;

	r->info = info;

	e->text_space = space_used(&rb->text_data_ring, &d->text_blk_lpos);

	return true;
fail:
	prb_commit(e);
	/* prb_commit() re-enabled interrupts. */
fail_reopen:
	/* Make it clear to the caller that the re-reserve failed. */
	memset(r, 0, sizeof(*r));
	return false;
}

static void desc_make_final(struct prb_desc_ring *desc_ring, unsigned long id)
{
	unsigned long prev_state_val = DESC_SV(id, desc_committed);
	struct prb_desc *d = to_desc(desc_ring, id);

	atomic_long_cmpxchg_relaxed(&d->state_var, prev_state_val,
			DESC_SV(id, desc_finalized)); /* LMM(desc_make_final:A) */

	/* Best effort to remember the last finalized @id. */
	atomic_long_set(&desc_ring->last_finalized_id, id);
}

bool prb_reserve(struct prb_reserved_entry *e, struct printk_ringbuffer *rb,
		 struct printk_record *r)
{
	struct prb_desc_ring *desc_ring = &rb->desc_ring;
	struct printk_info *info;
	struct prb_desc *d;
	unsigned long id;
	u64 seq;

	if (!data_check_size(&rb->text_data_ring, r->text_buf_size))
		goto fail;

	/*
	local_irq_save(e->irqflags);

	if (!desc_reserve(rb, &id)) {
		/* Descriptor reservation failures are tracked. */
		atomic_long_inc(&rb->fail);
		local_irq_restore(e->irqflags);
		goto fail;
	}

	d = to_desc(desc_ring, id);
	info = to_info(desc_ring, id);

	/*
	seq = info->seq;
	memset(info, 0, sizeof(*info));

	/*
	e->rb = rb;
	e->id = id;

	/*
	if (seq == 0 && DESC_INDEX(desc_ring, id) != 0)
		info->seq = DESC_INDEX(desc_ring, id);
	else
		info->seq = seq + DESCS_COUNT(desc_ring);

	/*
	if (info->seq > 0)
		desc_make_final(desc_ring, DESC_ID(id - 1));

	r->text_buf = data_alloc(rb, r->text_buf_size, &d->text_blk_lpos, id);
	/* If text data allocation fails, a data-less record is committed. */
	if (r->text_buf_size && !r->text_buf) {
		prb_commit(e);
		/* prb_commit() re-enabled interrupts. */
		goto fail;
	}

	r->info = info;

	/* Record full text space used by record. */
	e->text_space = space_used(&rb->text_data_ring, &d->text_blk_lpos);

	return true;
fail:
	/* Make it clear to the caller that the reserve failed. */
	memset(r, 0, sizeof(*r));
	return false;
}

static void _prb_commit(struct prb_reserved_entry *e, unsigned long state_val)
{
	struct prb_desc_ring *desc_ring = &e->rb->desc_ring;
	struct prb_desc *d = to_desc(desc_ring, e->id);
	unsigned long prev_state_val = DESC_SV(e->id, desc_reserved);

	/* Now the writer has finished all writing: LMM(_prb_commit:A) */

	/*
	if (!atomic_long_try_cmpxchg(&d->state_var, &prev_state_val,
			DESC_SV(e->id, state_val))) { /* LMM(_prb_commit:B) */
		WARN_ON_ONCE(1);
	}

	/* Restore interrupts, the reserve/commit window is finished. */
	local_irq_restore(e->irqflags);
}

void prb_commit(struct prb_reserved_entry *e)
{
	struct prb_desc_ring *desc_ring = &e->rb->desc_ring;
	unsigned long head_id;

	_prb_commit(e, desc_committed);

	/*
	head_id = atomic_long_read(&desc_ring->head_id); /* LMM(prb_commit:A) */
	if (head_id != e->id)
		desc_make_final(desc_ring, e->id);
}

void prb_final_commit(struct prb_reserved_entry *e)
{
	struct prb_desc_ring *desc_ring = &e->rb->desc_ring;

	_prb_commit(e, desc_finalized);

	/* Best effort to remember the last finalized @id. */
	atomic_long_set(&desc_ring->last_finalized_id, e->id);
}

static unsigned int count_lines(const char *text, unsigned int text_size)
{
	unsigned int next_size = text_size;
	unsigned int line_count = 1;
	const char *next = text;

	while (next_size) {
		next = memchr(next, '\n', next_size);
		if (!next)
			break;
		line_count++;
		next++;
		next_size = text_size - (next - text);
	}

	return line_count;
}

static bool copy_data(struct prb_data_ring *data_ring,
		      struct prb_data_blk_lpos *blk_lpos, u16 len, char *buf,
		      unsigned int buf_size, unsigned int *line_count)
{
	unsigned int data_size;
	const char *data;

	/* Caller might not want any data. */
	if ((!buf || !buf_size) && !line_count)
		return true;

	data = get_data(data_ring, blk_lpos, &data_size);
	if (!data)
		return false;

	/*
	if (data_size < (unsigned int)len)
		return false;

	/* Caller interested in the line count? */
	if (line_count)
		*line_count = count_lines(data, len);

	/* Caller interested in the data content? */
	if (!buf || !buf_size)
		return true;

	data_size = min_t(u16, buf_size, len);

	memcpy(&buf[0], data, data_size); /* LMM(copy_data:A) */
	return true;
}

static int desc_read_finalized_seq(struct prb_desc_ring *desc_ring,
				   unsigned long id, u64 seq,
				   struct prb_desc *desc_out)
{
	struct prb_data_blk_lpos *blk_lpos = &desc_out->text_blk_lpos;
	enum desc_state d_state;
	u64 s;

	d_state = desc_read(desc_ring, id, desc_out, &s, NULL);

	/*
	if (d_state == desc_miss ||
	    d_state == desc_reserved ||
	    d_state == desc_committed ||
	    s != seq) {
		return -EINVAL;
	}

	/*
	if (d_state == desc_reusable ||
	    (blk_lpos->begin == FAILED_LPOS && blk_lpos->next == FAILED_LPOS)) {
		return -ENOENT;
	}

	return 0;
}

static int prb_read(struct printk_ringbuffer *rb, u64 seq,
		    struct printk_record *r, unsigned int *line_count)
{
	struct prb_desc_ring *desc_ring = &rb->desc_ring;
	struct printk_info *info = to_info(desc_ring, seq);
	struct prb_desc *rdesc = to_desc(desc_ring, seq);
	atomic_long_t *state_var = &rdesc->state_var;
	struct prb_desc desc;
	unsigned long id;
	int err;

	/* Extract the ID, used to specify the descriptor to read. */
	id = DESC_ID(atomic_long_read(state_var));

	/* Get a local copy of the correct descriptor (if available). */
	err = desc_read_finalized_seq(desc_ring, id, seq, &desc);

	/*
	if (err || !r)
		return err;

	/* If requested, copy meta data. */
	if (r->info)
		memcpy(r->info, info, sizeof(*(r->info)));

	/* Copy text data. If it fails, this is a data-less record. */
	if (!copy_data(&rb->text_data_ring, &desc.text_blk_lpos, info->text_len,
		       r->text_buf, r->text_buf_size, line_count)) {
		return -ENOENT;
	}

	/* Ensure the record is still finalized and has the same @seq. */
	return desc_read_finalized_seq(desc_ring, id, seq, &desc);
}

static u64 prb_first_seq(struct printk_ringbuffer *rb)
{
	struct prb_desc_ring *desc_ring = &rb->desc_ring;
	enum desc_state d_state;
	struct prb_desc desc;
	unsigned long id;
	u64 seq;

	for (;;) {
		id = atomic_long_read(&rb->desc_ring.tail_id); /* LMM(prb_first_seq:A) */

		d_state = desc_read(desc_ring, id, &desc, &seq, NULL); /* LMM(prb_first_seq:B) */

		/*
		if (d_state == desc_finalized || d_state == desc_reusable)
			break;

		/*
		smp_rmb(); /* LMM(prb_first_seq:C) */
	}

	return seq;
}

static bool _prb_read_valid(struct printk_ringbuffer *rb, u64 *seq,
			    struct printk_record *r, unsigned int *line_count)
{
	u64 tail_seq;
	int err;

	while ((err = prb_read(rb, *seq, r, line_count))) {
		tail_seq = prb_first_seq(rb);

		if (*seq < tail_seq) {
			/*
			*seq = tail_seq;

		} else if (err == -ENOENT) {
			/* Record exists, but no data available. Skip. */
			(*seq)++;

		} else {
			/* Non-existent/non-finalized record. Must stop. */
			return false;
		}
	}

	return true;
}

bool prb_read_valid(struct printk_ringbuffer *rb, u64 seq,
		    struct printk_record *r)
{
	return _prb_read_valid(rb, &seq, r, NULL);
}

bool prb_read_valid_info(struct printk_ringbuffer *rb, u64 seq,
			 struct printk_info *info, unsigned int *line_count)
{
	struct printk_record r;

	prb_rec_init_rd(&r, info, NULL, 0);

	return _prb_read_valid(rb, &seq, &r, line_count);
}

u64 prb_first_valid_seq(struct printk_ringbuffer *rb)
{
	u64 seq = 0;

	if (!_prb_read_valid(rb, &seq, NULL, NULL))
		return 0;

	return seq;
}

u64 prb_next_seq(struct printk_ringbuffer *rb)
{
	struct prb_desc_ring *desc_ring = &rb->desc_ring;
	enum desc_state d_state;
	unsigned long id;
	u64 seq;

	/* Check if the cached @id still points to a valid @seq. */
	id = atomic_long_read(&desc_ring->last_finalized_id);
	d_state = desc_read(desc_ring, id, NULL, &seq, NULL);

	if (d_state == desc_finalized || d_state == desc_reusable) {
		/*
		if (seq != 0)
			seq++;
	} else {
		/*
		seq = 0;
	}

	/*
	while (_prb_read_valid(rb, &seq, NULL, NULL))
		seq++;

	return seq;
}

void prb_init(struct printk_ringbuffer *rb,
	      char *text_buf, unsigned int textbits,
	      struct prb_desc *descs, unsigned int descbits,
	      struct printk_info *infos)
{
	memset(descs, 0, _DESCS_COUNT(descbits) * sizeof(descs[0]));
	memset(infos, 0, _DESCS_COUNT(descbits) * sizeof(infos[0]));

	rb->desc_ring.count_bits = descbits;
	rb->desc_ring.descs = descs;
	rb->desc_ring.infos = infos;
	atomic_long_set(&rb->desc_ring.head_id, DESC0_ID(descbits));
	atomic_long_set(&rb->desc_ring.tail_id, DESC0_ID(descbits));
	atomic_long_set(&rb->desc_ring.last_finalized_id, DESC0_ID(descbits));

	rb->text_data_ring.size_bits = textbits;
	rb->text_data_ring.data = text_buf;
	atomic_long_set(&rb->text_data_ring.head_lpos, BLK0_LPOS(textbits));
	atomic_long_set(&rb->text_data_ring.tail_lpos, BLK0_LPOS(textbits));

	atomic_long_set(&rb->fail, 0);

	atomic_long_set(&(descs[_DESCS_COUNT(descbits) - 1].state_var), DESC0_SV(descbits));
	descs[_DESCS_COUNT(descbits) - 1].text_blk_lpos.begin = FAILED_LPOS;
	descs[_DESCS_COUNT(descbits) - 1].text_blk_lpos.next = FAILED_LPOS;

	infos[0].seq = -(u64)_DESCS_COUNT(descbits);
	infos[_DESCS_COUNT(descbits) - 1].seq = 0;
}

unsigned int prb_record_text_space(struct prb_reserved_entry *e)
{
	return e->text_space;
}
