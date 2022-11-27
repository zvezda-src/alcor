
#include <linux/perf_event.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/circ_buf.h>
#include <linux/poll.h>
#include <linux/nospec.h>

#include "internal.h"

static void perf_output_wakeup(struct perf_output_handle *handle)
{
	atomic_set(&handle->rb->poll, EPOLLIN);

	handle->event->pending_wakeup = 1;
	irq_work_queue(&handle->event->pending);
}

static void perf_output_get_handle(struct perf_output_handle *handle)
{
	struct perf_buffer *rb = handle->rb;

	preempt_disable();

	/*
	(*(volatile unsigned int *)&rb->nest)++;
	handle->wakeup = local_read(&rb->wakeup);
}

static void perf_output_put_handle(struct perf_output_handle *handle)
{
	struct perf_buffer *rb = handle->rb;
	unsigned long head;
	unsigned int nest;

	/*
	nest = READ_ONCE(rb->nest);
	if (nest > 1) {
		WRITE_ONCE(rb->nest, nest - 1);
		goto out;
	}

again:
	/*
	barrier();
	head = local_read(&rb->head);

	/*

	/*
	smp_wmb(); /* B, matches C */
	WRITE_ONCE(rb->user_page->data_head, head);

	/*
	barrier();
	WRITE_ONCE(rb->nest, 0);

	/*
	barrier();
	if (unlikely(head != local_read(&rb->head))) {
		WRITE_ONCE(rb->nest, 1);
		goto again;
	}

	if (handle->wakeup != local_read(&rb->wakeup))
		perf_output_wakeup(handle);

out:
	preempt_enable();
}

static __always_inline bool
ring_buffer_has_space(unsigned long head, unsigned long tail,
		      unsigned long data_size, unsigned int size,
		      bool backward)
{
	if (!backward)
		return CIRC_SPACE(head, tail, data_size) >= size;
	else
		return CIRC_SPACE(tail, head, data_size) >= size;
}

static __always_inline int
__perf_output_begin(struct perf_output_handle *handle,
		    struct perf_sample_data *data,
		    struct perf_event *event, unsigned int size,
		    bool backward)
{
	struct perf_buffer *rb;
	unsigned long tail, offset, head;
	int have_lost, page_shift;
	struct {
		struct perf_event_header header;
		u64			 id;
		u64			 lost;
	} lost_event;

	rcu_read_lock();
	/*
	if (event->parent)
		event = event->parent;

	rb = rcu_dereference(event->rb);
	if (unlikely(!rb))
		goto out;

	if (unlikely(rb->paused)) {
		if (rb->nr_pages) {
			local_inc(&rb->lost);
			atomic64_inc(&event->lost_samples);
		}
		goto out;
	}

	handle->rb    = rb;
	handle->event = event;

	have_lost = local_read(&rb->lost);
	if (unlikely(have_lost)) {
		size += sizeof(lost_event);
		if (event->attr.sample_id_all)
			size += event->id_header_size;
	}

	perf_output_get_handle(handle);

	do {
		tail = READ_ONCE(rb->user_page->data_tail);
		offset = head = local_read(&rb->head);
		if (!rb->overwrite) {
			if (unlikely(!ring_buffer_has_space(head, tail,
							    perf_data_size(rb),
							    size, backward)))
				goto fail;
		}

		/*

		if (!backward)
			head += size;
		else
			head -= size;
	} while (local_cmpxchg(&rb->head, offset, head) != offset);

	if (backward) {
		offset = head;
		head = (u64)(-head);
	}

	/*

	if (unlikely(head - local_read(&rb->wakeup) > rb->watermark))
		local_add(rb->watermark, &rb->wakeup);

	page_shift = PAGE_SHIFT + page_order(rb);

	handle->page = (offset >> page_shift) & (rb->nr_pages - 1);
	offset &= (1UL << page_shift) - 1;
	handle->addr = rb->data_pages[handle->page] + offset;
	handle->size = (1UL << page_shift) - offset;

	if (unlikely(have_lost)) {
		lost_event.header.size = sizeof(lost_event);
		lost_event.header.type = PERF_RECORD_LOST;
		lost_event.header.misc = 0;
		lost_event.id          = event->id;
		lost_event.lost        = local_xchg(&rb->lost, 0);

		/* XXX mostly redundant; @data is already fully initializes */
		perf_event_header__init_id(&lost_event.header, data, event);
		perf_output_put(handle, lost_event);
		perf_event__output_id_sample(event, handle, data);
	}

	return 0;

fail:
	local_inc(&rb->lost);
	atomic64_inc(&event->lost_samples);
	perf_output_put_handle(handle);
out:
	rcu_read_unlock();

	return -ENOSPC;
}

int perf_output_begin_forward(struct perf_output_handle *handle,
			      struct perf_sample_data *data,
			      struct perf_event *event, unsigned int size)
{
	return __perf_output_begin(handle, data, event, size, false);
}

int perf_output_begin_backward(struct perf_output_handle *handle,
			       struct perf_sample_data *data,
			       struct perf_event *event, unsigned int size)
{
	return __perf_output_begin(handle, data, event, size, true);
}

int perf_output_begin(struct perf_output_handle *handle,
		      struct perf_sample_data *data,
		      struct perf_event *event, unsigned int size)
{

	return __perf_output_begin(handle, data, event, size,
				   unlikely(is_write_backward(event)));
}

unsigned int perf_output_copy(struct perf_output_handle *handle,
		      const void *buf, unsigned int len)
{
	return __output_copy(handle, buf, len);
}

unsigned int perf_output_skip(struct perf_output_handle *handle,
			      unsigned int len)
{
	return __output_skip(handle, NULL, len);
}

void perf_output_end(struct perf_output_handle *handle)
{
	perf_output_put_handle(handle);
	rcu_read_unlock();
}

static void
ring_buffer_init(struct perf_buffer *rb, long watermark, int flags)
{
	long max_size = perf_data_size(rb);

	if (watermark)
		rb->watermark = min(max_size, watermark);

	if (!rb->watermark)
		rb->watermark = max_size / 2;

	if (flags & RING_BUFFER_WRITABLE)
		rb->overwrite = 0;
	else
		rb->overwrite = 1;

	refcount_set(&rb->refcount, 1);

	INIT_LIST_HEAD(&rb->event_list);
	spin_lock_init(&rb->event_lock);

	/*
	if (!rb->nr_pages)
		rb->paused = 1;
}

void perf_aux_output_flag(struct perf_output_handle *handle, u64 flags)
{
	/*
	if (WARN_ON_ONCE(flags & PERF_AUX_FLAG_OVERWRITE))
		return;

	handle->aux_flags |= flags;
}
EXPORT_SYMBOL_GPL(perf_aux_output_flag);

void *perf_aux_output_begin(struct perf_output_handle *handle,
			    struct perf_event *event)
{
	struct perf_event *output_event = event;
	unsigned long aux_head, aux_tail;
	struct perf_buffer *rb;
	unsigned int nest;

	if (output_event->parent)
		output_event = output_event->parent;

	/*
	rb = ring_buffer_get(output_event);
	if (!rb)
		return NULL;

	if (!rb_has_aux(rb))
		goto err;

	/*
	if (!atomic_read(&rb->aux_mmap_count))
		goto err;

	if (!refcount_inc_not_zero(&rb->aux_refcount))
		goto err;

	nest = READ_ONCE(rb->aux_nest);
	/*
	if (WARN_ON_ONCE(nest))
		goto err_put;

	WRITE_ONCE(rb->aux_nest, nest + 1);

	aux_head = rb->aux_head;

	handle->rb = rb;
	handle->event = event;
	handle->head = aux_head;
	handle->size = 0;
	handle->aux_flags = 0;

	/*
	if (!rb->aux_overwrite) {
		aux_tail = READ_ONCE(rb->user_page->aux_tail);
		handle->wakeup = rb->aux_wakeup + rb->aux_watermark;
		if (aux_head - aux_tail < perf_aux_size(rb))
			handle->size = CIRC_SPACE(aux_head, aux_tail, perf_aux_size(rb));

		/*
		if (!handle->size) { /* A, matches D */
			event->pending_disable = smp_processor_id();
			perf_output_wakeup(handle);
			WRITE_ONCE(rb->aux_nest, 0);
			goto err_put;
		}
	}

	return handle->rb->aux_priv;

err_put:
	/* can't be last */
	rb_free_aux(rb);

err:
	ring_buffer_put(rb);
	handle->event = NULL;

	return NULL;
}
EXPORT_SYMBOL_GPL(perf_aux_output_begin);

static __always_inline bool rb_need_aux_wakeup(struct perf_buffer *rb)
{
	if (rb->aux_overwrite)
		return false;

	if (rb->aux_head - rb->aux_wakeup >= rb->aux_watermark) {
		rb->aux_wakeup = rounddown(rb->aux_head, rb->aux_watermark);
		return true;
	}

	return false;
}

void perf_aux_output_end(struct perf_output_handle *handle, unsigned long size)
{
	bool wakeup = !!(handle->aux_flags & PERF_AUX_FLAG_TRUNCATED);
	struct perf_buffer *rb = handle->rb;
	unsigned long aux_head;

	/* in overwrite mode, driver provides aux_head via handle */
	if (rb->aux_overwrite) {
		handle->aux_flags |= PERF_AUX_FLAG_OVERWRITE;

		aux_head = handle->head;
		rb->aux_head = aux_head;
	} else {
		handle->aux_flags &= ~PERF_AUX_FLAG_OVERWRITE;

		aux_head = rb->aux_head;
		rb->aux_head += size;
	}

	/*
	if (size || (handle->aux_flags & ~(u64)PERF_AUX_FLAG_OVERWRITE))
		perf_event_aux_event(handle->event, aux_head, size,
				     handle->aux_flags);

	WRITE_ONCE(rb->user_page->aux_head, rb->aux_head);
	if (rb_need_aux_wakeup(rb))
		wakeup = true;

	if (wakeup) {
		if (handle->aux_flags & PERF_AUX_FLAG_TRUNCATED)
			handle->event->pending_disable = smp_processor_id();
		perf_output_wakeup(handle);
	}

	handle->event = NULL;

	WRITE_ONCE(rb->aux_nest, 0);
	/* can't be last */
	rb_free_aux(rb);
	ring_buffer_put(rb);
}
EXPORT_SYMBOL_GPL(perf_aux_output_end);

int perf_aux_output_skip(struct perf_output_handle *handle, unsigned long size)
{
	struct perf_buffer *rb = handle->rb;

	if (size > handle->size)
		return -ENOSPC;

	rb->aux_head += size;

	WRITE_ONCE(rb->user_page->aux_head, rb->aux_head);
	if (rb_need_aux_wakeup(rb)) {
		perf_output_wakeup(handle);
		handle->wakeup = rb->aux_wakeup + rb->aux_watermark;
	}

	handle->head = rb->aux_head;
	handle->size -= size;

	return 0;
}
EXPORT_SYMBOL_GPL(perf_aux_output_skip);

void *perf_get_aux(struct perf_output_handle *handle)
{
	/* this is only valid between perf_aux_output_begin and *_end */
	if (!handle->event)
		return NULL;

	return handle->rb->aux_priv;
}
EXPORT_SYMBOL_GPL(perf_get_aux);

long perf_output_copy_aux(struct perf_output_handle *aux_handle,
			  struct perf_output_handle *handle,
			  unsigned long from, unsigned long to)
{
	struct perf_buffer *rb = aux_handle->rb;
	unsigned long tocopy, remainder, len = 0;
	void *addr;

	from &= (rb->aux_nr_pages << PAGE_SHIFT) - 1;
	to &= (rb->aux_nr_pages << PAGE_SHIFT) - 1;

	do {
		tocopy = PAGE_SIZE - offset_in_page(from);
		if (to > from)
			tocopy = min(tocopy, to - from);
		if (!tocopy)
			break;

		addr = rb->aux_pages[from >> PAGE_SHIFT];
		addr += offset_in_page(from);

		remainder = perf_output_copy(handle, addr, tocopy);
		if (remainder)
			return -EFAULT;

		len += tocopy;
		from += tocopy;
		from &= (rb->aux_nr_pages << PAGE_SHIFT) - 1;
	} while (to != from);

	return len;
}

#define PERF_AUX_GFP	(GFP_KERNEL | __GFP_ZERO | __GFP_NOWARN | __GFP_NORETRY)

static struct page *rb_alloc_aux_page(int node, int order)
{
	struct page *page;

	if (order > MAX_ORDER)
		order = MAX_ORDER;

	do {
		page = alloc_pages_node(node, PERF_AUX_GFP, order);
	} while (!page && order--);

	if (page && order) {
		/*
		split_page(page, order);
		SetPagePrivate(page);
		set_page_private(page, order);
	}

	return page;
}

static void rb_free_aux_page(struct perf_buffer *rb, int idx)
{
	struct page *page = virt_to_page(rb->aux_pages[idx]);

	ClearPagePrivate(page);
	page->mapping = NULL;
	__free_page(page);
}

static void __rb_free_aux(struct perf_buffer *rb)
{
	int pg;

	/*
	WARN_ON_ONCE(in_atomic());

	if (rb->aux_priv) {
		rb->free_aux(rb->aux_priv);
		rb->free_aux = NULL;
		rb->aux_priv = NULL;
	}

	if (rb->aux_nr_pages) {
		for (pg = 0; pg < rb->aux_nr_pages; pg++)
			rb_free_aux_page(rb, pg);

		kfree(rb->aux_pages);
		rb->aux_nr_pages = 0;
	}
}

int rb_alloc_aux(struct perf_buffer *rb, struct perf_event *event,
		 pgoff_t pgoff, int nr_pages, long watermark, int flags)
{
	bool overwrite = !(flags & RING_BUFFER_WRITABLE);
	int node = (event->cpu == -1) ? -1 : cpu_to_node(event->cpu);
	int ret = -ENOMEM, max_order;

	if (!has_aux(event))
		return -EOPNOTSUPP;

	if (!overwrite) {
		/*
		if (!watermark)
			watermark = nr_pages << (PAGE_SHIFT - 1);

		/*
		max_order = get_order(watermark);
	} else {
		/*
		max_order = ilog2(nr_pages);
		watermark = 0;
	}

	rb->aux_pages = kcalloc_node(nr_pages, sizeof(void *), GFP_KERNEL,
				     node);
	if (!rb->aux_pages)
		return -ENOMEM;

	rb->free_aux = event->pmu->free_aux;
	for (rb->aux_nr_pages = 0; rb->aux_nr_pages < nr_pages;) {
		struct page *page;
		int last, order;

		order = min(max_order, ilog2(nr_pages - rb->aux_nr_pages));
		page = rb_alloc_aux_page(node, order);
		if (!page)
			goto out;

		for (last = rb->aux_nr_pages + (1 << page_private(page));
		     last > rb->aux_nr_pages; rb->aux_nr_pages++)
			rb->aux_pages[rb->aux_nr_pages] = page_address(page++);
	}

	/*
	if ((event->pmu->capabilities & PERF_PMU_CAP_AUX_NO_SG) &&
	    overwrite) {
		struct page *page = virt_to_page(rb->aux_pages[0]);

		if (page_private(page) != max_order)
			goto out;
	}

	rb->aux_priv = event->pmu->setup_aux(event, rb->aux_pages, nr_pages,
					     overwrite);
	if (!rb->aux_priv)
		goto out;

	ret = 0;

	/*
	refcount_set(&rb->aux_refcount, 1);

	rb->aux_overwrite = overwrite;
	rb->aux_watermark = watermark;

out:
	if (!ret)
		rb->aux_pgoff = pgoff;
	else
		__rb_free_aux(rb);

	return ret;
}

void rb_free_aux(struct perf_buffer *rb)
{
	if (refcount_dec_and_test(&rb->aux_refcount))
		__rb_free_aux(rb);
}

#ifndef CONFIG_PERF_USE_VMALLOC


static struct page *
__perf_mmap_to_page(struct perf_buffer *rb, unsigned long pgoff)
{
	if (pgoff > rb->nr_pages)
		return NULL;

	if (pgoff == 0)
		return virt_to_page(rb->user_page);

	return virt_to_page(rb->data_pages[pgoff - 1]);
}

static void *perf_mmap_alloc_page(int cpu)
{
	struct page *page;
	int node;

	node = (cpu == -1) ? cpu : cpu_to_node(cpu);
	page = alloc_pages_node(node, GFP_KERNEL | __GFP_ZERO, 0);
	if (!page)
		return NULL;

	return page_address(page);
}

static void perf_mmap_free_page(void *addr)
{
	struct page *page = virt_to_page(addr);

	page->mapping = NULL;
	__free_page(page);
}

struct perf_buffer *rb_alloc(int nr_pages, long watermark, int cpu, int flags)
{
	struct perf_buffer *rb;
	unsigned long size;
	int i, node;

	size = sizeof(struct perf_buffer);
	size += nr_pages * sizeof(void *);

	if (order_base_2(size) >= PAGE_SHIFT+MAX_ORDER)
		goto fail;

	node = (cpu == -1) ? cpu : cpu_to_node(cpu);
	rb = kzalloc_node(size, GFP_KERNEL, node);
	if (!rb)
		goto fail;

	rb->user_page = perf_mmap_alloc_page(cpu);
	if (!rb->user_page)
		goto fail_user_page;

	for (i = 0; i < nr_pages; i++) {
		rb->data_pages[i] = perf_mmap_alloc_page(cpu);
		if (!rb->data_pages[i])
			goto fail_data_pages;
	}

	rb->nr_pages = nr_pages;

	ring_buffer_init(rb, watermark, flags);

	return rb;

fail_data_pages:
	for (i--; i >= 0; i--)
		perf_mmap_free_page(rb->data_pages[i]);

	perf_mmap_free_page(rb->user_page);

fail_user_page:
	kfree(rb);

fail:
	return NULL;
}

void rb_free(struct perf_buffer *rb)
{
	int i;

	perf_mmap_free_page(rb->user_page);
	for (i = 0; i < rb->nr_pages; i++)
		perf_mmap_free_page(rb->data_pages[i]);
	kfree(rb);
}

#else
static struct page *
__perf_mmap_to_page(struct perf_buffer *rb, unsigned long pgoff)
{
	/* The '>' counts in the user page. */
	if (pgoff > data_page_nr(rb))
		return NULL;

	return vmalloc_to_page((void *)rb->user_page + pgoff * PAGE_SIZE);
}

static void perf_mmap_unmark_page(void *addr)
{
	struct page *page = vmalloc_to_page(addr);

	page->mapping = NULL;
}

static void rb_free_work(struct work_struct *work)
{
	struct perf_buffer *rb;
	void *base;
	int i, nr;

	rb = container_of(work, struct perf_buffer, work);
	nr = data_page_nr(rb);

	base = rb->user_page;
	/* The '<=' counts in the user page. */
	for (i = 0; i <= nr; i++)
		perf_mmap_unmark_page(base + (i * PAGE_SIZE));

	vfree(base);
	kfree(rb);
}

void rb_free(struct perf_buffer *rb)
{
	schedule_work(&rb->work);
}

struct perf_buffer *rb_alloc(int nr_pages, long watermark, int cpu, int flags)
{
	struct perf_buffer *rb;
	unsigned long size;
	void *all_buf;
	int node;

	size = sizeof(struct perf_buffer);
	size += sizeof(void *);

	node = (cpu == -1) ? cpu : cpu_to_node(cpu);
	rb = kzalloc_node(size, GFP_KERNEL, node);
	if (!rb)
		goto fail;

	INIT_WORK(&rb->work, rb_free_work);

	all_buf = vmalloc_user((nr_pages + 1) * PAGE_SIZE);
	if (!all_buf)
		goto fail_all_buf;

	rb->user_page = all_buf;
	rb->data_pages[0] = all_buf + PAGE_SIZE;
	if (nr_pages) {
		rb->nr_pages = 1;
		rb->page_order = ilog2(nr_pages);
	}

	ring_buffer_init(rb, watermark, flags);

	return rb;

fail_all_buf:
	kfree(rb);

fail:
	return NULL;
}

#endif

struct page *
perf_mmap_to_page(struct perf_buffer *rb, unsigned long pgoff)
{
	if (rb->aux_nr_pages) {
		/* above AUX space */
		if (pgoff > rb->aux_pgoff + rb->aux_nr_pages)
			return NULL;

		/* AUX space */
		if (pgoff >= rb->aux_pgoff) {
			int aux_pgoff = array_index_nospec(pgoff - rb->aux_pgoff, rb->aux_nr_pages);
			return virt_to_page(rb->aux_pages[aux_pgoff]);
		}
	}

	return __perf_mmap_to_page(rb, pgoff);
}
