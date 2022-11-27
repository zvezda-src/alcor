#ifndef _ASM_X86_PKEYS_H
#define _ASM_X86_PKEYS_H

#define arch_max_pkey() (cpu_feature_enabled(X86_FEATURE_OSPKE) ? 16 : 1)

extern int arch_set_user_pkey_access(struct task_struct *tsk, int pkey,
		unsigned long init_val);

static inline bool arch_pkeys_enabled(void)
{
	return cpu_feature_enabled(X86_FEATURE_OSPKE);
}

extern int __execute_only_pkey(struct mm_struct *mm);
static inline int execute_only_pkey(struct mm_struct *mm)
{
	if (!cpu_feature_enabled(X86_FEATURE_OSPKE))
		return ARCH_DEFAULT_PKEY;

	return __execute_only_pkey(mm);
}

extern int __arch_override_mprotect_pkey(struct vm_area_struct *vma,
		int prot, int pkey);
static inline int arch_override_mprotect_pkey(struct vm_area_struct *vma,
		int prot, int pkey)
{
	if (!cpu_feature_enabled(X86_FEATURE_OSPKE))
		return 0;

	return __arch_override_mprotect_pkey(vma, prot, pkey);
}

#define ARCH_VM_PKEY_FLAGS (VM_PKEY_BIT0 | VM_PKEY_BIT1 | VM_PKEY_BIT2 | VM_PKEY_BIT3)

#define mm_pkey_allocation_map(mm)	(mm->context.pkey_allocation_map)
#define mm_set_pkey_allocated(mm, pkey) do {		\
	mm_pkey_allocation_map(mm) |= (1U << pkey);	\
} while (0)
#define mm_set_pkey_free(mm, pkey) do {			\
	mm_pkey_allocation_map(mm) &= ~(1U << pkey);	\
} while (0)

static inline
bool mm_pkey_is_allocated(struct mm_struct *mm, int pkey)
{
	/*
	if (pkey < 0)
		return false;
	if (pkey >= arch_max_pkey())
		return false;
	/*
	if (pkey == mm->context.execute_only_pkey)
		return false;

	return mm_pkey_allocation_map(mm) & (1U << pkey);
}

static inline
int mm_pkey_alloc(struct mm_struct *mm)
{
	/*
	u16 all_pkeys_mask = ((1U << arch_max_pkey()) - 1);
	int ret;

	/*
	if (mm_pkey_allocation_map(mm) == all_pkeys_mask)
		return -1;

	ret = ffz(mm_pkey_allocation_map(mm));

	mm_set_pkey_allocated(mm, ret);

	return ret;
}

static inline
int mm_pkey_free(struct mm_struct *mm, int pkey)
{
	if (!mm_pkey_is_allocated(mm, pkey))
		return -EINVAL;

	mm_set_pkey_free(mm, pkey);

	return 0;
}

static inline int vma_pkey(struct vm_area_struct *vma)
{
	unsigned long vma_pkey_mask = VM_PKEY_BIT0 | VM_PKEY_BIT1 |
				      VM_PKEY_BIT2 | VM_PKEY_BIT3;

	return (vma->vm_flags & vma_pkey_mask) >> VM_PKEY_SHIFT;
}

#endif /*_ASM_X86_PKEYS_H */
