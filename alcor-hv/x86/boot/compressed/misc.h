#ifndef BOOT_COMPRESSED_MISC_H
#define BOOT_COMPRESSED_MISC_H

#undef CONFIG_PARAVIRT
#undef CONFIG_PARAVIRT_XXL
#undef CONFIG_PARAVIRT_SPINLOCKS
#undef CONFIG_KASAN
#undef CONFIG_KASAN_GENERIC

#define __NO_FORTIFY

#define USE_EARLY_PGTABLE_L5

#include <linux/linkage.h>
#include <linux/screen_info.h>
#include <linux/elf.h>
#include <asm/page.h>
#include <asm/boot.h>
#include <asm/bootparam.h>
#include <asm/desc_defs.h>

#include "tdx.h"

#define BOOT_CTYPE_H
#include <linux/acpi.h>

#define BOOT_BOOT_H
#include "../ctype.h"
#include "../io.h"

#include "efi.h"

#ifdef CONFIG_X86_64
#define memptr long
#else
#define memptr unsigned
#endif

extern char _head[], _end[];

extern memptr free_mem_ptr;
extern memptr free_mem_end_ptr;
void *malloc(int size);
void free(void *where);
extern struct boot_params *boot_params;
void __putstr(const char *s);
void __puthex(unsigned long value);
#define error_putstr(__x)  __putstr(__x)
#define error_puthex(__x)  __puthex(__x)

#ifdef CONFIG_X86_VERBOSE_BOOTUP

#define debug_putstr(__x)  __putstr(__x)
#define debug_puthex(__x)  __puthex(__x)
#define debug_putaddr(__x) { \
		debug_putstr(#__x ": 0x"); \
		debug_puthex((unsigned long)(__x)); \
		debug_putstr("\n"); \
	}

#else

static inline void debug_putstr(const char *s)
{ }
static inline void debug_puthex(unsigned long value)
{ }
#define debug_putaddr(x) /* */

#endif

int cmdline_find_option(const char *option, char *buffer, int bufsize);
int cmdline_find_option_bool(const char *option);

struct mem_vector {
	u64 start;
	u64 size;
};

#ifdef CONFIG_RANDOMIZE_BASE
void choose_random_location(unsigned long input,
			    unsigned long input_size,
			    unsigned long *output,
			    unsigned long output_size,
			    unsigned long *virt_addr);
#else
static inline void choose_random_location(unsigned long input,
					  unsigned long input_size,
					  unsigned long *output,
					  unsigned long output_size,
					  unsigned long *virt_addr)
{
}
#endif

bool has_cpuflag(int flag);

#ifdef CONFIG_X86_64
extern int set_page_decrypted(unsigned long address);
extern int set_page_encrypted(unsigned long address);
extern int set_page_non_present(unsigned long address);
extern unsigned char _pgtable[];
#endif

#ifdef CONFIG_EARLY_PRINTK
extern int early_serial_base;
void console_init(void);
#else
static const int early_serial_base;
static inline void console_init(void)
{ }
#endif

#ifdef CONFIG_AMD_MEM_ENCRYPT
void sev_enable(struct boot_params *bp);
void sev_es_shutdown_ghcb(void);
extern bool sev_es_check_ghcb_fault(unsigned long address);
void snp_set_page_private(unsigned long paddr);
void snp_set_page_shared(unsigned long paddr);
void sev_prep_identity_maps(unsigned long top_level_pgt);
#else
static inline void sev_enable(struct boot_params *bp) { }
static inline void sev_es_shutdown_ghcb(void) { }
static inline bool sev_es_check_ghcb_fault(unsigned long address)
{
	return false;
}
static inline void snp_set_page_private(unsigned long paddr) { }
static inline void snp_set_page_shared(unsigned long paddr) { }
static inline void sev_prep_identity_maps(unsigned long top_level_pgt) { }
#endif

#ifdef CONFIG_ACPI
acpi_physical_address get_rsdp_addr(void);
#else
static inline acpi_physical_address get_rsdp_addr(void) { return 0; }
#endif

#if defined(CONFIG_RANDOMIZE_BASE) && defined(CONFIG_MEMORY_HOTREMOVE) && defined(CONFIG_ACPI)
extern struct mem_vector immovable_mem[MAX_NUMNODES*2];
int count_immovable_mem_regions(void);
#else
static inline int count_immovable_mem_regions(void) { return 0; }
#endif

#ifdef CONFIG_X86_5LEVEL
extern unsigned int __pgtable_l5_enabled, pgdir_shift, ptrs_per_p4d;
#endif
extern void kernel_add_identity_map(unsigned long start, unsigned long end);

extern pteval_t __default_kernel_pte_mask;

extern gate_desc boot_idt[BOOT_IDT_ENTRIES];
extern struct desc_ptr boot_idt_desc;

#ifdef CONFIG_X86_64
void cleanup_exception_handling(void);
#else
static inline void cleanup_exception_handling(void) { }
#endif

void boot_page_fault(void);
void boot_stage1_vc(void);
void boot_stage2_vc(void);

unsigned long sev_verify_cbit(unsigned long cr3);

enum efi_type {
	EFI_TYPE_64,
	EFI_TYPE_32,
	EFI_TYPE_NONE,
};

#ifdef CONFIG_EFI
enum efi_type efi_get_type(struct boot_params *bp);
unsigned long efi_get_system_table(struct boot_params *bp);
int efi_get_conf_table(struct boot_params *bp, unsigned long *cfg_tbl_pa,
		       unsigned int *cfg_tbl_len);
unsigned long efi_find_vendor_table(struct boot_params *bp,
				    unsigned long cfg_tbl_pa,
				    unsigned int cfg_tbl_len,
				    efi_guid_t guid);
#else
static inline enum efi_type efi_get_type(struct boot_params *bp)
{
	return EFI_TYPE_NONE;
}

static inline unsigned long efi_get_system_table(struct boot_params *bp)
{
	return 0;
}

static inline int efi_get_conf_table(struct boot_params *bp,
				     unsigned long *cfg_tbl_pa,
				     unsigned int *cfg_tbl_len)
{
	return -ENOENT;
}

static inline unsigned long efi_find_vendor_table(struct boot_params *bp,
						  unsigned long cfg_tbl_pa,
						  unsigned int cfg_tbl_len,
						  efi_guid_t guid)
{
	return 0;
}
#endif /* CONFIG_EFI */

#endif /* BOOT_COMPRESSED_MISC_H */
