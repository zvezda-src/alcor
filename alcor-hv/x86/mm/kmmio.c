
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/spinlock.h>
#include <linux/hash.h>
#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/ptrace.h>
#include <linux/preempt.h>
#include <linux/percpu.h>
#include <linux/kdebug.h>
#include <linux/mutex.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <asm/cacheflush.h>
#include <asm/tlbflush.h>
#include <linux/errno.h>
#include <asm/debugreg.h>
#include <linux/mmiotrace.h>

#define KMMIO_PAGE_HASH_BITS 4
#define KMMIO_PAGE_TABLE_SIZE (1 << KMMIO_PAGE_HASH_BITS)

struct kmmio_fault_page {
	struct list_head list;
	struct kmmio_fault_page *release_next;
	unsigned long addr; /* the requested address */
	pteval_t old_presence; /* page presence prior to arming */
	bool armed;

	/*
	int count;

	bool scheduled_for_release;
};

struct kmmio_delayed_release {
	struct rcu_head rcu;
	struct kmmio_fault_page *release_list;
};

struct kmmio_context {
	struct kmmio_fault_page *fpage;
	struct kmmio_probe *probe;
	unsigned long saved_flags;
	unsigned long addr;
	int active;
};

static DEFINE_SPINLOCK(kmmio_lock);

unsigned int kmmio_count;

static struct list_head kmmio_page_table[KMMIO_PAGE_TABLE_SIZE];
static LIST_HEAD(kmmio_probes);

static struct list_head *kmmio_page_list(unsigned long addr)
{
	unsigned int l;
	pte_t *pte = lookup_address(addr, &l);

	if (!pte)
		return NULL;
	addr &= page_level_mask(l);

	return &kmmio_page_table[hash_long(addr, KMMIO_PAGE_HASH_BITS)];
}

static DEFINE_PER_CPU(struct kmmio_context, kmmio_ctx);

static struct kmmio_probe *get_kmmio_probe(unsigned long addr)
{
	struct kmmio_probe *p;
	list_for_each_entry_rcu(p, &kmmio_probes, list) {
		if (addr >= p->addr && addr < (p->addr + p->len))
			return p;
	}
	return NULL;
}

static struct kmmio_fault_page *get_kmmio_fault_page(unsigned long addr)
{
	struct list_head *head;
	struct kmmio_fault_page *f;
	unsigned int l;
	pte_t *pte = lookup_address(addr, &l);

	if (!pte)
		return NULL;
	addr &= page_level_mask(l);
	head = kmmio_page_list(addr);
	list_for_each_entry_rcu(f, head, list) {
		if (f->addr == addr)
			return f;
	}
	return NULL;
}

static void clear_pmd_presence(pmd_t *pmd, bool clear, pmdval_t *old)
{
	pmd_t new_pmd;
	pmdval_t v = pmd_val(*pmd);
	if (clear) {
		*old = v;
		new_pmd = pmd_mkinvalid(*pmd);
	} else {
		/* Presume this has been called with clear==true previously */
		new_pmd = __pmd(*old);
	}
	set_pmd(pmd, new_pmd);
}

static void clear_pte_presence(pte_t *pte, bool clear, pteval_t *old)
{
	pteval_t v = pte_val(*pte);
	if (clear) {
		*old = v;
		/* Nothing should care about address */
		pte_clear(&init_mm, 0, pte);
	} else {
		/* Presume this has been called with clear==true previously */
		set_pte_atomic(pte, __pte(*old));
	}
}

static int clear_page_presence(struct kmmio_fault_page *f, bool clear)
{
	unsigned int level;
	pte_t *pte = lookup_address(f->addr, &level);

	if (!pte) {
		pr_err("no pte for addr 0x%08lx\n", f->addr);
		return -1;
	}

	switch (level) {
	case PG_LEVEL_2M:
		clear_pmd_presence((pmd_t *)pte, clear, &f->old_presence);
		break;
	case PG_LEVEL_4K:
		clear_pte_presence(pte, clear, &f->old_presence);
		break;
	default:
		pr_err("unexpected page level 0x%x.\n", level);
		return -1;
	}

	flush_tlb_one_kernel(f->addr);
	return 0;
}

static int arm_kmmio_fault_page(struct kmmio_fault_page *f)
{
	int ret;
	WARN_ONCE(f->armed, KERN_ERR pr_fmt("kmmio page already armed.\n"));
	if (f->armed) {
		pr_warn("double-arm: addr 0x%08lx, ref %d, old %d\n",
			f->addr, f->count, !!f->old_presence);
	}
	ret = clear_page_presence(f, true);
	WARN_ONCE(ret < 0, KERN_ERR pr_fmt("arming at 0x%08lx failed.\n"),
		  f->addr);
	f->armed = true;
	return ret;
}

static void disarm_kmmio_fault_page(struct kmmio_fault_page *f)
{
	int ret = clear_page_presence(f, false);
	WARN_ONCE(ret < 0,
			KERN_ERR "kmmio disarming at 0x%08lx failed.\n", f->addr);
	f->armed = false;
}

int kmmio_handler(struct pt_regs *regs, unsigned long addr)
{
	struct kmmio_context *ctx;
	struct kmmio_fault_page *faultpage;
	int ret = 0; /* default to fault not handled */
	unsigned long page_base = addr;
	unsigned int l;
	pte_t *pte = lookup_address(addr, &l);
	if (!pte)
		return -EINVAL;
	page_base &= page_level_mask(l);

	/*
	preempt_disable();
	rcu_read_lock();

	faultpage = get_kmmio_fault_page(page_base);
	if (!faultpage) {
		/*
		goto no_kmmio;
	}

	ctx = this_cpu_ptr(&kmmio_ctx);
	if (ctx->active) {
		if (page_base == ctx->addr) {
			/*
			pr_debug("secondary hit for 0x%08lx CPU %d.\n",
				 addr, smp_processor_id());

			if (!faultpage->old_presence)
				pr_info("unexpected secondary hit for address 0x%08lx on CPU %d.\n",
					addr, smp_processor_id());
		} else {
			/*
			pr_emerg("recursive probe hit on CPU %d, for address 0x%08lx. Ignoring.\n",
				 smp_processor_id(), addr);
			pr_emerg("previous hit was at 0x%08lx.\n", ctx->addr);
			disarm_kmmio_fault_page(faultpage);
		}
		goto no_kmmio;
	}
	ctx->active++;

	ctx->fpage = faultpage;
	ctx->probe = get_kmmio_probe(page_base);
	ctx->saved_flags = (regs->flags & (X86_EFLAGS_TF | X86_EFLAGS_IF));
	ctx->addr = page_base;

	if (ctx->probe && ctx->probe->pre_handler)
		ctx->probe->pre_handler(ctx->probe, regs, addr);

	/*
	regs->flags |= X86_EFLAGS_TF;
	regs->flags &= ~X86_EFLAGS_IF;

	/* Now we set present bit in PTE and single step. */
	disarm_kmmio_fault_page(ctx->fpage);

	/*

	return 1; /* fault handled */

no_kmmio:
	rcu_read_unlock();
	preempt_enable_no_resched();
	return ret;
}

static int post_kmmio_handler(unsigned long condition, struct pt_regs *regs)
{
	int ret = 0;
	struct kmmio_context *ctx = this_cpu_ptr(&kmmio_ctx);

	if (!ctx->active) {
		/*
		pr_warn("unexpected debug trap on CPU %d.\n", smp_processor_id());
		goto out;
	}

	if (ctx->probe && ctx->probe->post_handler)
		ctx->probe->post_handler(ctx->probe, condition, regs);

	/* Prevent racing against release_kmmio_fault_page(). */
	spin_lock(&kmmio_lock);
	if (ctx->fpage->count)
		arm_kmmio_fault_page(ctx->fpage);
	spin_unlock(&kmmio_lock);

	regs->flags &= ~X86_EFLAGS_TF;
	regs->flags |= ctx->saved_flags;

	/* These were acquired in kmmio_handler(). */
	ctx->active--;
	BUG_ON(ctx->active);
	rcu_read_unlock();
	preempt_enable_no_resched();

	/*
	if (!(regs->flags & X86_EFLAGS_TF))
		ret = 1;
out:
	return ret;
}

static int add_kmmio_fault_page(unsigned long addr)
{
	struct kmmio_fault_page *f;

	f = get_kmmio_fault_page(addr);
	if (f) {
		if (!f->count)
			arm_kmmio_fault_page(f);
		f->count++;
		return 0;
	}

	f = kzalloc(sizeof(*f), GFP_ATOMIC);
	if (!f)
		return -1;

	f->count = 1;
	f->addr = addr;

	if (arm_kmmio_fault_page(f)) {
		kfree(f);
		return -1;
	}

	list_add_rcu(&f->list, kmmio_page_list(f->addr));

	return 0;
}

static void release_kmmio_fault_page(unsigned long addr,
				struct kmmio_fault_page **release_list)
{
	struct kmmio_fault_page *f;

	f = get_kmmio_fault_page(addr);
	if (!f)
		return;

	f->count--;
	BUG_ON(f->count < 0);
	if (!f->count) {
		disarm_kmmio_fault_page(f);
		if (!f->scheduled_for_release) {
			f->release_next = *release_list;
			*release_list = f;
			f->scheduled_for_release = true;
		}
	}
}

int register_kmmio_probe(struct kmmio_probe *p)
{
	unsigned long flags;
	int ret = 0;
	unsigned long size = 0;
	unsigned long addr = p->addr & PAGE_MASK;
	const unsigned long size_lim = p->len + (p->addr & ~PAGE_MASK);
	unsigned int l;
	pte_t *pte;

	spin_lock_irqsave(&kmmio_lock, flags);
	if (get_kmmio_probe(addr)) {
		ret = -EEXIST;
		goto out;
	}

	pte = lookup_address(addr, &l);
	if (!pte) {
		ret = -EINVAL;
		goto out;
	}

	kmmio_count++;
	list_add_rcu(&p->list, &kmmio_probes);
	while (size < size_lim) {
		if (add_kmmio_fault_page(addr + size))
			pr_err("Unable to set page fault.\n");
		size += page_level_size(l);
	}
out:
	spin_unlock_irqrestore(&kmmio_lock, flags);
	/*
	return ret;
}
EXPORT_SYMBOL(register_kmmio_probe);

static void rcu_free_kmmio_fault_pages(struct rcu_head *head)
{
	struct kmmio_delayed_release *dr = container_of(
						head,
						struct kmmio_delayed_release,
						rcu);
	struct kmmio_fault_page *f = dr->release_list;
	while (f) {
		struct kmmio_fault_page *next = f->release_next;
		BUG_ON(f->count);
		kfree(f);
		f = next;
	}
	kfree(dr);
}

static void remove_kmmio_fault_pages(struct rcu_head *head)
{
	struct kmmio_delayed_release *dr =
		container_of(head, struct kmmio_delayed_release, rcu);
	struct kmmio_fault_page *f = dr->release_list;
	struct kmmio_fault_page **prevp = &dr->release_list;
	unsigned long flags;

	spin_lock_irqsave(&kmmio_lock, flags);
	while (f) {
		if (!f->count) {
			list_del_rcu(&f->list);
			prevp = &f->release_next;
		} else {
			*prevp = f->release_next;
			f->release_next = NULL;
			f->scheduled_for_release = false;
		}
		f = *prevp;
	}
	spin_unlock_irqrestore(&kmmio_lock, flags);

	/* This is the real RCU destroy call. */
	call_rcu(&dr->rcu, rcu_free_kmmio_fault_pages);
}

void unregister_kmmio_probe(struct kmmio_probe *p)
{
	unsigned long flags;
	unsigned long size = 0;
	unsigned long addr = p->addr & PAGE_MASK;
	const unsigned long size_lim = p->len + (p->addr & ~PAGE_MASK);
	struct kmmio_fault_page *release_list = NULL;
	struct kmmio_delayed_release *drelease;
	unsigned int l;
	pte_t *pte;

	pte = lookup_address(addr, &l);
	if (!pte)
		return;

	spin_lock_irqsave(&kmmio_lock, flags);
	while (size < size_lim) {
		release_kmmio_fault_page(addr + size, &release_list);
		size += page_level_size(l);
	}
	list_del_rcu(&p->list);
	kmmio_count--;
	spin_unlock_irqrestore(&kmmio_lock, flags);

	if (!release_list)
		return;

	drelease = kmalloc(sizeof(*drelease), GFP_ATOMIC);
	if (!drelease) {
		pr_crit("leaking kmmio_fault_page objects.\n");
		return;
	}
	drelease->release_list = release_list;

	/*
	call_rcu(&drelease->rcu, remove_kmmio_fault_pages);
}
EXPORT_SYMBOL(unregister_kmmio_probe);

static int
kmmio_die_notifier(struct notifier_block *nb, unsigned long val, void *args)
{
	struct die_args *arg = args;
	unsigned long* dr6_p = (unsigned long *)ERR_PTR(arg->err);

	if (val == DIE_DEBUG && (*dr6_p & DR_STEP))
		if (post_kmmio_handler(*dr6_p, arg->regs) == 1) {
			/*
			*dr6_p &= ~DR_STEP;
			return NOTIFY_STOP;
		}

	return NOTIFY_DONE;
}

static struct notifier_block nb_die = {
	.notifier_call = kmmio_die_notifier
};

int kmmio_init(void)
{
	int i;

	for (i = 0; i < KMMIO_PAGE_TABLE_SIZE; i++)
		INIT_LIST_HEAD(&kmmio_page_table[i]);

	return register_die_notifier(&nb_die);
}

void kmmio_cleanup(void)
{
	int i;

	unregister_die_notifier(&nb_die);
	for (i = 0; i < KMMIO_PAGE_TABLE_SIZE; i++) {
		WARN_ONCE(!list_empty(&kmmio_page_table[i]),
			KERN_ERR "kmmio_page_table not empty at cleanup, any further tracing will leak memory.\n");
	}
}
