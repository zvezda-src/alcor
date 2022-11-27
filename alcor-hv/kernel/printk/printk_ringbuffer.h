
#ifndef _KERNEL_PRINTK_RINGBUFFER_H
#define _KERNEL_PRINTK_RINGBUFFER_H

#include <linux/atomic.h>
#include <linux/dev_printk.h>

struct printk_info {
	u64	seq;		/* sequence number */
	u64	ts_nsec;	/* timestamp in nanoseconds */
	u16	text_len;	/* length of text message */
	u8	facility;	/* syslog facility */
	u8	flags:5;	/* internal record flags */
	u8	level:3;	/* syslog level */
	u32	caller_id;	/* thread id or processor id */

	struct dev_printk_info	dev_info;
};

struct printk_record {
	struct printk_info	*info;
	char			*text_buf;
	unsigned int		text_buf_size;
};

struct prb_data_blk_lpos {
	unsigned long	begin;
	unsigned long	next;
};

struct prb_desc {
	atomic_long_t			state_var;
	struct prb_data_blk_lpos	text_blk_lpos;
};

struct prb_data_ring {
	unsigned int	size_bits;
	char		*data;
	atomic_long_t	head_lpos;
	atomic_long_t	tail_lpos;
};

struct prb_desc_ring {
	unsigned int		count_bits;
	struct prb_desc		*descs;
	struct printk_info	*infos;
	atomic_long_t		head_id;
	atomic_long_t		tail_id;
	atomic_long_t		last_finalized_id;
};

struct printk_ringbuffer {
	struct prb_desc_ring	desc_ring;
	struct prb_data_ring	text_data_ring;
	atomic_long_t		fail;
};

struct prb_reserved_entry {
	struct printk_ringbuffer	*rb;
	unsigned long			irqflags;
	unsigned long			id;
	unsigned int			text_space;
};

enum desc_state {
	desc_miss	=  -1,	/* ID mismatch (pseudo state) */
	desc_reserved	= 0x0,	/* reserved, in use by writer */
	desc_committed	= 0x1,	/* committed by writer, could get reopened */
	desc_finalized	= 0x2,	/* committed, no further modification allowed */
	desc_reusable	= 0x3,	/* free, not yet used by any writer */
};

#define _DATA_SIZE(sz_bits)	(1UL << (sz_bits))
#define _DESCS_COUNT(ct_bits)	(1U << (ct_bits))
#define DESC_SV_BITS		(sizeof(unsigned long) * 8)
#define DESC_FLAGS_SHIFT	(DESC_SV_BITS - 2)
#define DESC_FLAGS_MASK		(3UL << DESC_FLAGS_SHIFT)
#define DESC_STATE(sv)		(3UL & (sv >> DESC_FLAGS_SHIFT))
#define DESC_SV(id, state)	(((unsigned long)state << DESC_FLAGS_SHIFT) | id)
#define DESC_ID_MASK		(~DESC_FLAGS_MASK)
#define DESC_ID(sv)		((sv) & DESC_ID_MASK)
#define FAILED_LPOS		0x1
#define NO_LPOS			0x3

#define FAILED_BLK_LPOS	\
{				\
	.begin	= FAILED_LPOS,	\
	.next	= FAILED_LPOS,	\
}


#define BLK0_LPOS(sz_bits)	(-(_DATA_SIZE(sz_bits)))
#define DESC0_ID(ct_bits)	DESC_ID(-(_DESCS_COUNT(ct_bits) + 1))
#define DESC0_SV(ct_bits)	DESC_SV(DESC0_ID(ct_bits), desc_reusable)

#define _DEFINE_PRINTKRB(name, descbits, avgtextbits, text_buf)			\
static struct prb_desc _##name##_descs[_DESCS_COUNT(descbits)] = {				\
	/* the initial head and tail */								\
	[_DESCS_COUNT(descbits) - 1] = {							\
		/* reusable */									\
		.state_var	= ATOMIC_INIT(DESC0_SV(descbits)),				\
		/* no associated data block */							\
		.text_blk_lpos	= FAILED_BLK_LPOS,						\
	},											\
};												\
static struct printk_info _##name##_infos[_DESCS_COUNT(descbits)] = {				\
	/* this will be the first record reserved by a writer */				\
	[0] = {											\
		/* will be incremented to 0 on the first reservation */				\
		.seq = -(u64)_DESCS_COUNT(descbits),						\
	},											\
	/* the initial head and tail */								\
	[_DESCS_COUNT(descbits) - 1] = {							\
		/* reports the first seq value during the bootstrap phase */			\
		.seq = 0,									\
	},											\
};												\
static struct printk_ringbuffer name = {							\
	.desc_ring = {										\
		.count_bits	= descbits,							\
		.descs		= &_##name##_descs[0],						\
		.infos		= &_##name##_infos[0],						\
		.head_id	= ATOMIC_INIT(DESC0_ID(descbits)),				\
		.tail_id	= ATOMIC_INIT(DESC0_ID(descbits)),				\
		.last_finalized_id = ATOMIC_INIT(DESC0_ID(descbits)),				\
	},											\
	.text_data_ring = {									\
		.size_bits	= (avgtextbits) + (descbits),					\
		.data		= text_buf,							\
		.head_lpos	= ATOMIC_LONG_INIT(BLK0_LPOS((avgtextbits) + (descbits))),	\
		.tail_lpos	= ATOMIC_LONG_INIT(BLK0_LPOS((avgtextbits) + (descbits))),	\
	},											\
	.fail			= ATOMIC_LONG_INIT(0),						\
}

#define DEFINE_PRINTKRB(name, descbits, avgtextbits)				\
static char _##name##_text[1U << ((avgtextbits) + (descbits))]			\
			__aligned(__alignof__(unsigned long));			\
_DEFINE_PRINTKRB(name, descbits, avgtextbits, &_##name##_text[0])


static inline void prb_rec_init_wr(struct printk_record *r,
				   unsigned int text_buf_size)
{
	r->info = NULL;
	r->text_buf = NULL;
	r->text_buf_size = text_buf_size;
}

bool prb_reserve(struct prb_reserved_entry *e, struct printk_ringbuffer *rb,
		 struct printk_record *r);
bool prb_reserve_in_last(struct prb_reserved_entry *e, struct printk_ringbuffer *rb,
			 struct printk_record *r, u32 caller_id, unsigned int max_size);
void prb_commit(struct prb_reserved_entry *e);
void prb_final_commit(struct prb_reserved_entry *e);

void prb_init(struct printk_ringbuffer *rb,
	      char *text_buf, unsigned int text_buf_size,
	      struct prb_desc *descs, unsigned int descs_count_bits,
	      struct printk_info *infos);
unsigned int prb_record_text_space(struct prb_reserved_entry *e);


static inline void prb_rec_init_rd(struct printk_record *r,
				   struct printk_info *info,
				   char *text_buf, unsigned int text_buf_size)
{
	r->info = info;
	r->text_buf = text_buf;
	r->text_buf_size = text_buf_size;
}

#define prb_for_each_record(from, rb, s, r) \
for ((s) = from; prb_read_valid(rb, s, r); (s) = (r)->info->seq + 1)

#define prb_for_each_info(from, rb, s, i, lc) \
for ((s) = from; prb_read_valid_info(rb, s, i, lc); (s) = (i)->seq + 1)

bool prb_read_valid(struct printk_ringbuffer *rb, u64 seq,
		    struct printk_record *r);
bool prb_read_valid_info(struct printk_ringbuffer *rb, u64 seq,
			 struct printk_info *info, unsigned int *line_count);

u64 prb_first_valid_seq(struct printk_ringbuffer *rb);
u64 prb_next_seq(struct printk_ringbuffer *rb);

#endif /* _KERNEL_PRINTK_RINGBUFFER_H */
