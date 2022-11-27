#include <linux/capability.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <linux/bitmap.h>
#include <linux/ioport.h>
#include <linux/sched.h>
#include <linux/slab.h>

#include <asm/io_bitmap.h>
#include <asm/desc.h>
#include <asm/syscalls.h>

#ifdef CONFIG_X86_IOPL_IOPERM

static atomic64_t io_bitmap_sequence;

void io_bitmap_share(struct task_struct *tsk)
{
	/* Can be NULL when current->thread.iopl_emul == 3 */
	if (current->thread.io_bitmap) {
		/*
		refcount_inc(&current->thread.io_bitmap->refcnt);
		tsk->thread.io_bitmap = current->thread.io_bitmap;
	}
	set_tsk_thread_flag(tsk, TIF_IO_BITMAP);
}

static void task_update_io_bitmap(struct task_struct *tsk)
{
	struct thread_struct *t = &tsk->thread;

	if (t->iopl_emul == 3 || t->io_bitmap) {
		/* TSS update is handled on exit to user space */
		set_tsk_thread_flag(tsk, TIF_IO_BITMAP);
	} else {
		clear_tsk_thread_flag(tsk, TIF_IO_BITMAP);
		/* Invalidate TSS */
		preempt_disable();
		tss_update_io_bitmap();
		preempt_enable();
	}
}

void io_bitmap_exit(struct task_struct *tsk)
{
	struct io_bitmap *iobm = tsk->thread.io_bitmap;

	tsk->thread.io_bitmap = NULL;
	task_update_io_bitmap(tsk);
	if (iobm && refcount_dec_and_test(&iobm->refcnt))
		kfree(iobm);
}

long ksys_ioperm(unsigned long from, unsigned long num, int turn_on)
{
	struct thread_struct *t = &current->thread;
	unsigned int i, max_long;
	struct io_bitmap *iobm;

	if ((from + num <= from) || (from + num > IO_BITMAP_BITS))
		return -EINVAL;
	if (turn_on && (!capable(CAP_SYS_RAWIO) ||
			security_locked_down(LOCKDOWN_IOPORT)))
		return -EPERM;

	/*
	iobm = t->io_bitmap;
	if (!iobm) {
		/* No point to allocate a bitmap just to clear permissions */
		if (!turn_on)
			return 0;
		iobm = kmalloc(sizeof(*iobm), GFP_KERNEL);
		if (!iobm)
			return -ENOMEM;

		memset(iobm->bitmap, 0xff, sizeof(iobm->bitmap));
		refcount_set(&iobm->refcnt, 1);
	}

	/*
	if (refcount_read(&iobm->refcnt) > 1) {
		iobm = kmemdup(iobm, sizeof(*iobm), GFP_KERNEL);
		if (!iobm)
			return -ENOMEM;
		refcount_set(&iobm->refcnt, 1);
		io_bitmap_exit(current);
	}

	/*
	t->io_bitmap = iobm;
	/* Mark it active for context switching and exit to user mode */
	set_thread_flag(TIF_IO_BITMAP);

	/*
	if (turn_on)
		bitmap_clear(iobm->bitmap, from, num);
	else
		bitmap_set(iobm->bitmap, from, num);

	/*
	max_long = UINT_MAX;
	for (i = 0; i < IO_BITMAP_LONGS; i++) {
		if (iobm->bitmap[i] != ~0UL)
			max_long = i;
	}
	/* All permissions dropped? */
	if (max_long == UINT_MAX) {
		io_bitmap_exit(current);
		return 0;
	}

	iobm->max = (max_long + 1) * sizeof(unsigned long);

	/*
	iobm->sequence = atomic64_add_return(1, &io_bitmap_sequence);

	return 0;
}

SYSCALL_DEFINE3(ioperm, unsigned long, from, unsigned long, num, int, turn_on)
{
	return ksys_ioperm(from, num, turn_on);
}

SYSCALL_DEFINE1(iopl, unsigned int, level)
{
	struct thread_struct *t = &current->thread;
	unsigned int old;

	if (level > 3)
		return -EINVAL;

	old = t->iopl_emul;

	/* No point in going further if nothing changes */
	if (level == old)
		return 0;

	/* Trying to gain more privileges? */
	if (level > old) {
		if (!capable(CAP_SYS_RAWIO) ||
		    security_locked_down(LOCKDOWN_IOPORT))
			return -EPERM;
	}

	t->iopl_emul = level;
	task_update_io_bitmap(current);

	return 0;
}

#else /* CONFIG_X86_IOPL_IOPERM */

long ksys_ioperm(unsigned long from, unsigned long num, int turn_on)
{
	return -ENOSYS;
}
SYSCALL_DEFINE3(ioperm, unsigned long, from, unsigned long, num, int, turn_on)
{
	return -ENOSYS;
}

SYSCALL_DEFINE1(iopl, unsigned int, level)
{
	return -ENOSYS;
}
#endif
