
#include <linux/cpuhotplug.h>
#include <linux/kasan.h>
#include <linux/mm.h>
#include <linux/scs.h>
#include <linux/vmalloc.h>
#include <linux/vmstat.h>

static void __scs_account(void *s, int account)
{
	struct page *scs_page = vmalloc_to_page(s);

	mod_node_page_state(page_pgdat(scs_page), NR_KERNEL_SCS_KB,
			    account * (SCS_SIZE / SZ_1K));
}

#define NR_CACHED_SCS 2
static DEFINE_PER_CPU(void *, scs_cache[NR_CACHED_SCS]);

static void *__scs_alloc(int node)
{
	int i;
	void *s;

	for (i = 0; i < NR_CACHED_SCS; i++) {
		s = this_cpu_xchg(scs_cache[i], NULL);
		if (s) {
			s = kasan_unpoison_vmalloc(s, SCS_SIZE,
						   KASAN_VMALLOC_PROT_NORMAL);
			memset(s, 0, SCS_SIZE);
			goto out;
		}
	}

	s = __vmalloc_node_range(SCS_SIZE, 1, VMALLOC_START, VMALLOC_END,
				    GFP_SCS, PAGE_KERNEL, 0, node,
				    __builtin_return_address(0));

out:
	return kasan_reset_tag(s);
}

void *scs_alloc(int node)
{
	void *s;

	s = __scs_alloc(node);
	if (!s)
		return NULL;


	/*
	kasan_poison_vmalloc(s, SCS_SIZE);
	__scs_account(s, 1);
	return s;
}

void scs_free(void *s)
{
	int i;

	__scs_account(s, -1);

	/*

	for (i = 0; i < NR_CACHED_SCS; i++)
		if (this_cpu_cmpxchg(scs_cache[i], 0, s) == NULL)
			return;

	kasan_unpoison_vmalloc(s, SCS_SIZE, KASAN_VMALLOC_PROT_NORMAL);
	vfree_atomic(s);
}

static int scs_cleanup(unsigned int cpu)
{
	int i;
	void **cache = per_cpu_ptr(scs_cache, cpu);

	for (i = 0; i < NR_CACHED_SCS; i++) {
		vfree(cache[i]);
		cache[i] = NULL;
	}

	return 0;
}

void __init scs_init(void)
{
	cpuhp_setup_state(CPUHP_BP_PREPARE_DYN, "scs:scs_cache", NULL,
			  scs_cleanup);
}

int scs_prepare(struct task_struct *tsk, int node)
{
	void *s = scs_alloc(node);

	if (!s)
		return -ENOMEM;

	task_scs(tsk) = task_scs_sp(tsk) = s;
	return 0;
}

static void scs_check_usage(struct task_struct *tsk)
{
	static unsigned long highest;

	unsigned long *p, prev, curr = highest, used = 0;

	if (!IS_ENABLED(CONFIG_DEBUG_STACK_USAGE))
		return;

	for (p = task_scs(tsk); p < __scs_magic(tsk); ++p) {
		if (!READ_ONCE_NOCHECK(*p))
			break;
		used += sizeof(*p);
	}

	while (used > curr) {
		prev = cmpxchg_relaxed(&highest, curr, used);

		if (prev == curr) {
			pr_info("%s (%d): highest shadow stack usage: %lu bytes\n",
				tsk->comm, task_pid_nr(tsk), used);
			break;
		}

		curr = prev;
	}
}

void scs_release(struct task_struct *tsk)
{
	void *s = task_scs(tsk);

	if (!s)
		return;

	WARN(task_scs_end_corrupted(tsk),
	     "corrupted shadow stack detected when freeing task\n");
	scs_check_usage(tsk);
	scs_free(s);
}
