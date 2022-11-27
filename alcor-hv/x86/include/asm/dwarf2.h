#ifndef _ASM_X86_DWARF2_H
#define _ASM_X86_DWARF2_H

#ifndef __ASSEMBLY__
#warning "asm/dwarf2.h should be only included in pure assembly files"
#endif

#define CFI_STARTPROC		.cfi_startproc
#define CFI_ENDPROC		.cfi_endproc
#define CFI_DEF_CFA		.cfi_def_cfa
#define CFI_DEF_CFA_REGISTER	.cfi_def_cfa_register
#define CFI_DEF_CFA_OFFSET	.cfi_def_cfa_offset
#define CFI_ADJUST_CFA_OFFSET	.cfi_adjust_cfa_offset
#define CFI_OFFSET		.cfi_offset
#define CFI_REL_OFFSET		.cfi_rel_offset
#define CFI_REGISTER		.cfi_register
#define CFI_RESTORE		.cfi_restore
#define CFI_REMEMBER_STATE	.cfi_remember_state
#define CFI_RESTORE_STATE	.cfi_restore_state
#define CFI_UNDEFINED		.cfi_undefined
#define CFI_ESCAPE		.cfi_escape

#ifndef BUILD_VDSO
	/*
	.cfi_sections .debug_frame
#else
	 /*
	.cfi_sections .eh_frame, .debug_frame
#endif

#endif /* _ASM_X86_DWARF2_H */
