

#ifndef _TRACE_INTERNAL_PID_LIST_H
#define _TRACE_INTERNAL_PID_LIST_H


#define UPPER_BITS	8
#define UPPER_MAX	(1 << UPPER_BITS)
#define UPPER1_SIZE	(1 << UPPER_BITS)
#define UPPER2_SIZE	(1 << UPPER_BITS)

#define LOWER_BITS	14
#define LOWER_MAX	(1 << LOWER_BITS)
#define LOWER_SIZE	(LOWER_MAX / BITS_PER_LONG)

#define UPPER1_SHIFT	(LOWER_BITS + UPPER_BITS)
#define UPPER2_SHIFT	LOWER_BITS
#define LOWER_MASK	(LOWER_MAX - 1)

#define UPPER_MASK	(UPPER_MAX - 1)

#define MAX_PID		(1 << 30)

#define CHUNK_ALLOC 6

#define CHUNK_REALLOC 2

union lower_chunk {
	union lower_chunk		*next;
	unsigned long			data[LOWER_SIZE]; // 2K in size
};

union upper_chunk {
	union upper_chunk		*next;
	union lower_chunk		*data[UPPER2_SIZE]; // 1 or 2K in size
};

struct trace_pid_list {
	raw_spinlock_t			lock;
	struct irq_work			refill_irqwork;
	union upper_chunk		*upper[UPPER1_SIZE]; // 1 or 2K in size
	union upper_chunk		*upper_list;
	union lower_chunk		*lower_list;
	int				free_upper_chunks;
	int				free_lower_chunks;
};

#endif /* _TRACE_INTERNAL_PID_LIST_H */
