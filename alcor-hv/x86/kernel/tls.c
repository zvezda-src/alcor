#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/user.h>
#include <linux/regset.h>
#include <linux/syscalls.h>
#include <linux/nospec.h>

#include <linux/uaccess.h>
#include <asm/desc.h>
#include <asm/ldt.h>
#include <asm/processor.h>
#include <asm/proto.h>

#include "tls.h"

static int get_free_idx(void)
{
	struct thread_struct *t = &current->thread;
	int idx;

	for (idx = 0; idx < GDT_ENTRY_TLS_ENTRIES; idx++)
		if (desc_empty(&t->tls_array[idx]))
			return idx + GDT_ENTRY_TLS_MIN;
	return -ESRCH;
}

static bool tls_desc_okay(const struct user_desc *info)
{
	/*
	if (LDT_empty(info) || LDT_zero(info))
		return true;

	/*
	if (!info->seg_32bit)
		return false;

	/* Only allow data segments in the TLS array. */
	if (info->contents > 1)
		return false;

	/*
	if (info->seg_not_present)
		return false;

	return true;
}

static void set_tls_desc(struct task_struct *p, int idx,
			 const struct user_desc *info, int n)
{
	struct thread_struct *t = &p->thread;
	struct desc_struct *desc = &t->tls_array[idx - GDT_ENTRY_TLS_MIN];
	int cpu;

	/*
	cpu = get_cpu();

	while (n-- > 0) {
		if (LDT_empty(info) || LDT_zero(info))
			memset(desc, 0, sizeof(*desc));
		else
			fill_ldt(desc, info);
		++info;
		++desc;
	}

	if (t == &current->thread)
		load_TLS(t, cpu);

	put_cpu();
}

int do_set_thread_area(struct task_struct *p, int idx,
		       struct user_desc __user *u_info,
		       int can_allocate)
{
	struct user_desc info;
	unsigned short __maybe_unused sel, modified_sel;

	if (copy_from_user(&info, u_info, sizeof(info)))
		return -EFAULT;

	if (!tls_desc_okay(&info))
		return -EINVAL;

	if (idx == -1)
		idx = info.entry_number;

	/*
	if (idx == -1 && can_allocate) {
		idx = get_free_idx();
		if (idx < 0)
			return idx;
		if (put_user(idx, &u_info->entry_number))
			return -EFAULT;
	}

	if (idx < GDT_ENTRY_TLS_MIN || idx > GDT_ENTRY_TLS_MAX)
		return -EINVAL;

	set_tls_desc(p, idx, &info, 1);

	/*
	modified_sel = (idx << 3) | 3;

	if (p == current) {
#ifdef CONFIG_X86_64
		savesegment(ds, sel);
		if (sel == modified_sel)
			loadsegment(ds, sel);

		savesegment(es, sel);
		if (sel == modified_sel)
			loadsegment(es, sel);

		savesegment(fs, sel);
		if (sel == modified_sel)
			loadsegment(fs, sel);
#endif

		savesegment(gs, sel);
		if (sel == modified_sel)
			load_gs_index(sel);
	} else {
#ifdef CONFIG_X86_64
		if (p->thread.fsindex == modified_sel)
			p->thread.fsbase = info.base_addr;

		if (p->thread.gsindex == modified_sel)
			p->thread.gsbase = info.base_addr;
#endif
	}

	return 0;
}

SYSCALL_DEFINE1(set_thread_area, struct user_desc __user *, u_info)
{
	return do_set_thread_area(current, -1, u_info, 1);
}



static void fill_user_desc(struct user_desc *info, int idx,
			   const struct desc_struct *desc)

{
	memset(info, 0, sizeof(*info));
	info->entry_number = idx;
	info->base_addr = get_desc_base(desc);
	info->limit = get_desc_limit(desc);
	info->seg_32bit = desc->d;
	info->contents = desc->type >> 2;
	info->read_exec_only = !(desc->type & 2);
	info->limit_in_pages = desc->g;
	info->seg_not_present = !desc->p;
	info->useable = desc->avl;
#ifdef CONFIG_X86_64
	info->lm = desc->l;
#endif
}

int do_get_thread_area(struct task_struct *p, int idx,
		       struct user_desc __user *u_info)
{
	struct user_desc info;
	int index;

	if (idx == -1 && get_user(idx, &u_info->entry_number))
		return -EFAULT;

	if (idx < GDT_ENTRY_TLS_MIN || idx > GDT_ENTRY_TLS_MAX)
		return -EINVAL;

	index = idx - GDT_ENTRY_TLS_MIN;
	index = array_index_nospec(index,
			GDT_ENTRY_TLS_MAX - GDT_ENTRY_TLS_MIN + 1);

	fill_user_desc(&info, idx, &p->thread.tls_array[index]);

	if (copy_to_user(u_info, &info, sizeof(info)))
		return -EFAULT;
	return 0;
}

SYSCALL_DEFINE1(get_thread_area, struct user_desc __user *, u_info)
{
	return do_get_thread_area(current, -1, u_info);
}

int regset_tls_active(struct task_struct *target,
		      const struct user_regset *regset)
{
	struct thread_struct *t = &target->thread;
	int n = GDT_ENTRY_TLS_ENTRIES;
	while (n > 0 && desc_empty(&t->tls_array[n - 1]))
		--n;
	return n;
}

int regset_tls_get(struct task_struct *target, const struct user_regset *regset,
		   struct membuf to)
{
	const struct desc_struct *tls;
	struct user_desc v;
	int pos;

	for (pos = 0, tls = target->thread.tls_array; to.left; pos++, tls++) {
		fill_user_desc(&v, GDT_ENTRY_TLS_MIN + pos, tls);
		membuf_write(&to, &v, sizeof(v));
	}
	return 0;
}

int regset_tls_set(struct task_struct *target, const struct user_regset *regset,
		   unsigned int pos, unsigned int count,
		   const void *kbuf, const void __user *ubuf)
{
	struct user_desc infobuf[GDT_ENTRY_TLS_ENTRIES];
	const struct user_desc *info;
	int i;

	if (pos >= GDT_ENTRY_TLS_ENTRIES * sizeof(struct user_desc) ||
	    (pos % sizeof(struct user_desc)) != 0 ||
	    (count % sizeof(struct user_desc)) != 0)
		return -EINVAL;

	if (kbuf)
		info = kbuf;
	else if (__copy_from_user(infobuf, ubuf, count))
		return -EFAULT;
	else
		info = infobuf;

	for (i = 0; i < count / sizeof(struct user_desc); i++)
		if (!tls_desc_okay(info + i))
			return -EINVAL;

	set_tls_desc(target,
		     GDT_ENTRY_TLS_MIN + (pos / sizeof(struct user_desc)),
		     info, count / sizeof(struct user_desc));

	return 0;
}
