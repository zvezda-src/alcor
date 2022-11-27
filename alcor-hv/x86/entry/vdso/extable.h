#ifndef __VDSO_EXTABLE_H
#define __VDSO_EXTABLE_H

#ifdef __ASSEMBLY__
#define _ASM_VDSO_EXTABLE_HANDLE(from, to)	\
	ASM_VDSO_EXTABLE_HANDLE from to

.macro ASM_VDSO_EXTABLE_HANDLE from:req to:req
	.pushsection __ex_table, "a"
	.long (\from) - __ex_table
	.long (\to) - __ex_table
	.popsection
.endm
#else
#define _ASM_VDSO_EXTABLE_HANDLE(from, to)	\
	".pushsection __ex_table, \"a\"\n"      \
	".long (" #from ") - __ex_table\n"      \
	".long (" #to ") - __ex_table\n"        \
	".popsection\n"
#endif

#endif /* __VDSO_EXTABLE_H */
