
#include <linux/personality.h>
#include <linux/mm.h>
#include <linux/random.h>
#include <linux/limits.h>
#include <linux/sched/signal.h>
#include <linux/sched/mm.h>
#include <linux/compat.h>
#include <linux/elf-randomize.h>
#include <asm/elf.h>
#include <asm/io.h>

#include "physaddr.h"

struct va_alignment __read_mostly va_align = {
	.flags = -1,
};

unsigned long task_size_32bit(void)
{
	return IA32_PAGE_OFFSET;
}

unsigned long task_size_64bit(int full_addr_space)
{
	return full_addr_space ? TASK_SIZE_MAX : DEFAULT_MAP_WINDOW;
}

static unsigned long stack_maxrandom_size(unsigned long task_size)
{
	unsigned long max = 0;
	if (current->flags & PF_RANDOMIZE) {
		max = (-1UL) & __STACK_RND_MASK(task_size == task_size_32bit());
		max <<= PAGE_SHIFT;
	}

	return max;
}

#ifdef CONFIG_COMPAT
# define mmap32_rnd_bits  mmap_rnd_compat_bits
# define mmap64_rnd_bits  mmap_rnd_bits
#else
# define mmap32_rnd_bits  mmap_rnd_bits
# define mmap64_rnd_bits  mmap_rnd_bits
#endif

#define SIZE_128M    (128 * 1024 * 1024UL)

static int mmap_is_legacy(void)
{
	if (current->personality & ADDR_COMPAT_LAYOUT)
		return 1;

	return sysctl_legacy_va_layout;
}

static unsigned long arch_rnd(unsigned int rndbits)
{
	if (!(current->flags & PF_RANDOMIZE))
		return 0;
	return (get_random_long() & ((1UL << rndbits) - 1)) << PAGE_SHIFT;
}

unsigned long arch_mmap_rnd(void)
{
	return arch_rnd(mmap_is_ia32() ? mmap32_rnd_bits : mmap64_rnd_bits);
}

static unsigned long mmap_base(unsigned long rnd, unsigned long task_size,
			       struct rlimit *rlim_stack)
{
	unsigned long gap = rlim_stack->rlim_cur;
	unsigned long pad = stack_maxrandom_size(task_size) + stack_guard_gap;
	unsigned long gap_min, gap_max;

	/* Values close to RLIM_INFINITY can overflow. */
	if (gap + pad > gap)
		gap += pad;

	/*
	gap_min = SIZE_128M;
	gap_max = (task_size / 6) * 5;

	if (gap < gap_min)
		gap = gap_min;
	else if (gap > gap_max)
		gap = gap_max;

	return PAGE_ALIGN(task_size - gap - rnd);
}

static unsigned long mmap_legacy_base(unsigned long rnd,
				      unsigned long task_size)
{
	return __TASK_UNMAPPED_BASE(task_size) + rnd;
}

static void arch_pick_mmap_base(unsigned long *base, unsigned long *legacy_base,
		unsigned long random_factor, unsigned long task_size,
		struct rlimit *rlim_stack)
{
	if (mmap_is_legacy())
		*base = *legacy_base;
	else
		*base = mmap_base(random_factor, task_size, rlim_stack);
}

void arch_pick_mmap_layout(struct mm_struct *mm, struct rlimit *rlim_stack)
{
	if (mmap_is_legacy())
		mm->get_unmapped_area = arch_get_unmapped_area;
	else
		mm->get_unmapped_area = arch_get_unmapped_area_topdown;

	arch_pick_mmap_base(&mm->mmap_base, &mm->mmap_legacy_base,
			arch_rnd(mmap64_rnd_bits), task_size_64bit(0),
			rlim_stack);

#ifdef CONFIG_HAVE_ARCH_COMPAT_MMAP_BASES
	/*
	arch_pick_mmap_base(&mm->mmap_compat_base, &mm->mmap_compat_legacy_base,
			arch_rnd(mmap32_rnd_bits), task_size_32bit(),
			rlim_stack);
#endif
}

unsigned long get_mmap_base(int is_legacy)
{
	struct mm_struct *mm = current->mm;

#ifdef CONFIG_HAVE_ARCH_COMPAT_MMAP_BASES
	if (in_32bit_syscall()) {
		return is_legacy ? mm->mmap_compat_legacy_base
				 : mm->mmap_compat_base;
	}
#endif
	return is_legacy ? mm->mmap_legacy_base : mm->mmap_base;
}

const char *arch_vma_name(struct vm_area_struct *vma)
{
	return NULL;
}

bool mmap_address_hint_valid(unsigned long addr, unsigned long len)
{
	if (TASK_SIZE - len < addr)
		return false;

	return (addr > DEFAULT_MAP_WINDOW) == (addr + len > DEFAULT_MAP_WINDOW);
}

int valid_phys_addr_range(phys_addr_t addr, size_t count)
{
	return addr + count - 1 <= __pa(high_memory - 1);
}

int valid_mmap_phys_addr_range(unsigned long pfn, size_t count)
{
	phys_addr_t addr = (phys_addr_t)pfn << PAGE_SHIFT;

	return phys_addr_valid(addr + count - 1);
}

bool pfn_modify_allowed(unsigned long pfn, pgprot_t prot)
{
	if (!boot_cpu_has_bug(X86_BUG_L1TF))
		return true;
	if (!__pte_needs_invert(pgprot_val(prot)))
		return true;
	/* If it's real memory always allow */
	if (pfn_valid(pfn))
		return true;
	if (pfn >= l1tf_pfn_limit() && !capable(CAP_SYS_ADMIN))
		return false;
	return true;
}
