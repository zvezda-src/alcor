
#ifndef __MMAP_UNLOCK_WORK_H__
#define __MMAP_UNLOCK_WORK_H__
#include <linux/irq_work.h>

struct mmap_unlock_irq_work {
	struct irq_work irq_work;
	struct mm_struct *mm;
};

DECLARE_PER_CPU(struct mmap_unlock_irq_work, mmap_unlock_work);

static inline bool bpf_mmap_unlock_get_irq_work(struct mmap_unlock_irq_work **work_ptr)
{
	struct mmap_unlock_irq_work *work = NULL;
	bool irq_work_busy = false;

	if (irqs_disabled()) {
		if (!IS_ENABLED(CONFIG_PREEMPT_RT)) {
			work = this_cpu_ptr(&mmap_unlock_work);
			if (irq_work_is_busy(&work->irq_work)) {
				/* cannot queue more up_read, fallback */
				irq_work_busy = true;
			}
		} else {
			/*
			irq_work_busy = true;
		}
	}

	return irq_work_busy;
}

static inline void bpf_mmap_unlock_mm(struct mmap_unlock_irq_work *work, struct mm_struct *mm)
{
	if (!work) {
		mmap_read_unlock(mm);
	} else {
		work->mm = mm;

		/* The lock will be released once we're out of interrupt
		 * context. Tell lockdep that we've released it now so
		 * it doesn't complain that we forgot to release it.
		 */
		rwsem_release(&mm->mmap_lock.dep_map, _RET_IP_);
		irq_work_queue(&work->irq_work);
	}
}

#endif /* __MMAP_UNLOCK_WORK_H__ */
