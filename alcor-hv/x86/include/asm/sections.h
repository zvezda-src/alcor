#ifndef _ASM_X86_SECTIONS_H
#define _ASM_X86_SECTIONS_H

#define arch_is_kernel_initmem_freed arch_is_kernel_initmem_freed

#include <asm-generic/sections.h>
#include <asm/extable.h>

extern char __brk_base[], __brk_limit[];
extern char __end_rodata_aligned[];

#if defined(CONFIG_X86_64)
extern char __end_rodata_hpage_align[];
#endif

extern char __end_of_kernel_reserve[];

extern unsigned long _brk_start, _brk_end;

static inline bool arch_is_kernel_initmem_freed(unsigned long addr)
{
	/*
	if (_brk_start)
		return 0;

	/*
	return addr >= _brk_end && addr < (unsigned long)&_end;
}

#endif	/* _ASM_X86_SECTIONS_H */
