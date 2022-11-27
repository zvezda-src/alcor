#ifndef _ASM_PGTABLE_INVERT_H
#define _ASM_PGTABLE_INVERT_H 1

#ifndef __ASSEMBLY__

static inline bool __pte_needs_invert(u64 val)
{
	return val && !(val & _PAGE_PRESENT);
}

static inline u64 protnone_mask(u64 val)
{
	return __pte_needs_invert(val) ?  ~0ull : 0;
}

static inline u64 flip_protnone_guard(u64 oldval, u64 val, u64 mask)
{
	/*
	if (__pte_needs_invert(oldval) != __pte_needs_invert(val))
		val = (val & ~mask) | (~val & mask);
	return val;
}

#endif /* __ASSEMBLY__ */

#endif
