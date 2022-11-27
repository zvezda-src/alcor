
#define __pa(x)  ((unsigned long)(x))
#define __va(x)  ((void *)((unsigned long)(x)))

#undef CONFIG_PAGE_TABLE_ISOLATION

#include "error.h"
#include "misc.h"

#include <linux/pgtable.h>
#include <asm/cmpxchg.h>
#include <asm/trap_pf.h>
#include <asm/trapnr.h>
#include <asm/init.h>
#undef __PAGE_OFFSET
#define __PAGE_OFFSET __PAGE_OFFSET_BASE
#include "../../mm/ident_map.c"

#define _SETUP
#include <asm/setup.h>	/* For COMMAND_LINE_SIZE */
#undef _SETUP

extern unsigned long get_cmd_line_ptr(void);

pteval_t __default_kernel_pte_mask __read_mostly = ~0;

struct alloc_pgt_data {
	unsigned char *pgt_buf;
	unsigned long pgt_buf_size;
	unsigned long pgt_buf_offset;
};

static void *alloc_pgt_page(void *context)
{
	struct alloc_pgt_data *pages = (struct alloc_pgt_data *)context;
	unsigned char *entry;

	/* Validate there is space available for a new page. */
	if (pages->pgt_buf_offset >= pages->pgt_buf_size) {
		debug_putstr("out of pgt_buf in " __FILE__ "!?\n");
		debug_putaddr(pages->pgt_buf_offset);
		debug_putaddr(pages->pgt_buf_size);
		return NULL;
	}

	entry = pages->pgt_buf + pages->pgt_buf_offset;
	pages->pgt_buf_offset += PAGE_SIZE;

	return entry;
}

static struct alloc_pgt_data pgt_data;

static unsigned long top_level_pgt;

phys_addr_t physical_mask = (1ULL << __PHYSICAL_MASK_SHIFT) - 1;

static struct x86_mapping_info mapping_info;

void kernel_add_identity_map(unsigned long start, unsigned long end)
{
	int ret;

	/* Align boundary to 2M. */
	start = round_down(start, PMD_SIZE);
	end = round_up(end, PMD_SIZE);
	if (start >= end)
		return;

	/* Build the mapping. */
	ret = kernel_ident_mapping_init(&mapping_info, (pgd_t *)top_level_pgt, start, end);
	if (ret)
		error("Error: kernel_ident_mapping_init() failed\n");
}

void initialize_identity_maps(void *rmode)
{
	unsigned long cmdline;
	struct setup_data *sd;

	/* Exclude the encryption mask from __PHYSICAL_MASK */
	physical_mask &= ~sme_me_mask;

	/* Init mapping_info with run-time function/buffer pointers. */
	mapping_info.alloc_pgt_page = alloc_pgt_page;
	mapping_info.context = &pgt_data;
	mapping_info.page_flag = __PAGE_KERNEL_LARGE_EXEC | sme_me_mask;
	mapping_info.kernpg_flag = _KERNPG_TABLE;

	/*
	pgt_data.pgt_buf_offset = 0;

	/*
	top_level_pgt = read_cr3_pa();
	if (p4d_offset((pgd_t *)top_level_pgt, 0) == (p4d_t *)_pgtable) {
		pgt_data.pgt_buf = _pgtable + BOOT_INIT_PGT_SIZE;
		pgt_data.pgt_buf_size = BOOT_PGT_SIZE - BOOT_INIT_PGT_SIZE;
		memset(pgt_data.pgt_buf, 0, pgt_data.pgt_buf_size);
	} else {
		pgt_data.pgt_buf = _pgtable;
		pgt_data.pgt_buf_size = BOOT_PGT_SIZE;
		memset(pgt_data.pgt_buf, 0, pgt_data.pgt_buf_size);
		top_level_pgt = (unsigned long)alloc_pgt_page(&pgt_data);
	}

	/*
	kernel_add_identity_map((unsigned long)_head, (unsigned long)_end);
	boot_params = rmode;
	kernel_add_identity_map((unsigned long)boot_params, (unsigned long)(boot_params + 1));
	cmdline = get_cmd_line_ptr();
	kernel_add_identity_map(cmdline, cmdline + COMMAND_LINE_SIZE);

	/*
	sd = (struct setup_data *)boot_params->hdr.setup_data;
	while (sd) {
		unsigned long sd_addr = (unsigned long)sd;

		kernel_add_identity_map(sd_addr, sd_addr + sizeof(*sd) + sd->len);
		sd = (struct setup_data *)sd->next;
	}

	sev_prep_identity_maps(top_level_pgt);

	/* Load the new page-table. */
	write_cr3(top_level_pgt);
}

static pte_t *split_large_pmd(struct x86_mapping_info *info,
			      pmd_t *pmdp, unsigned long __address)
{
	unsigned long page_flags;
	unsigned long address;
	pte_t *pte;
	pmd_t pmd;
	int i;

	pte = (pte_t *)info->alloc_pgt_page(info->context);
	if (!pte)
		return NULL;

	address     = __address & PMD_MASK;
	/* No large page - clear PSE flag */
	page_flags  = info->page_flag & ~_PAGE_PSE;

	/* Populate the PTEs */
	for (i = 0; i < PTRS_PER_PMD; i++) {
		set_pte(&pte[i], __pte(address | page_flags));
		address += PAGE_SIZE;
	}

	/*
	pmd = __pmd((unsigned long)pte | info->kernpg_flag);
	set_pmd(pmdp, pmd);
	/* Flush TLB to establish the new PMD */
	write_cr3(top_level_pgt);

	return pte + pte_index(__address);
}

static void clflush_page(unsigned long address)
{
	unsigned int flush_size;
	char *cl, *start, *end;

	/*
	flush_size = 64;
	start      = (char *)(address & PAGE_MASK);
	end        = start + PAGE_SIZE;

	/*
	asm volatile("mfence" : : : "memory");

	for (cl = start; cl != end; cl += flush_size)
		clflush(cl);
}

static int set_clr_page_flags(struct x86_mapping_info *info,
			      unsigned long address,
			      pteval_t set, pteval_t clr)
{
	pgd_t *pgdp = (pgd_t *)top_level_pgt;
	p4d_t *p4dp;
	pud_t *pudp;
	pmd_t *pmdp;
	pte_t *ptep, pte;

	/*
	asm volatile("mov %[address], %%r9"
		     :: [address] "g" (*(unsigned long *)address)
		     : "r9", "memory");

	/*
	p4dp = p4d_offset(pgdp, address);
	pudp = pud_offset(p4dp, address);
	pmdp = pmd_offset(pudp, address);

	if (pmd_large(*pmdp))
		ptep = split_large_pmd(info, pmdp, address);
	else
		ptep = pte_offset_kernel(pmdp, address);

	if (!ptep)
		return -ENOMEM;

	/*
	if ((set | clr) & _PAGE_ENC) {
		clflush_page(address);

		/*
		if (clr)
			snp_set_page_shared(__pa(address & PAGE_MASK));
	}

	/* Update PTE */
	pte = *ptep;
	pte = pte_set_flags(pte, set);
	pte = pte_clear_flags(pte, clr);
	set_pte(ptep, pte);

	/*
	if (set & _PAGE_ENC)
		snp_set_page_private(__pa(address & PAGE_MASK));

	/* Flush TLB after changing encryption attribute */
	write_cr3(top_level_pgt);

	return 0;
}

int set_page_decrypted(unsigned long address)
{
	return set_clr_page_flags(&mapping_info, address, 0, _PAGE_ENC);
}

int set_page_encrypted(unsigned long address)
{
	return set_clr_page_flags(&mapping_info, address, _PAGE_ENC, 0);
}

int set_page_non_present(unsigned long address)
{
	return set_clr_page_flags(&mapping_info, address, 0, _PAGE_PRESENT);
}

static void do_pf_error(const char *msg, unsigned long error_code,
			unsigned long address, unsigned long ip)
{
	error_putstr(msg);

	error_putstr("\nError Code: ");
	error_puthex(error_code);
	error_putstr("\nCR2: 0x");
	error_puthex(address);
	error_putstr("\nRIP relative to _head: 0x");
	error_puthex(ip - (unsigned long)_head);
	error_putstr("\n");

	error("Stopping.\n");
}

void do_boot_page_fault(struct pt_regs *regs, unsigned long error_code)
{
	unsigned long address = native_read_cr2();
	unsigned long end;
	bool ghcb_fault;

	ghcb_fault = sev_es_check_ghcb_fault(address);

	address   &= PMD_MASK;
	end        = address + PMD_SIZE;

	/*
	if (error_code & (X86_PF_PROT | X86_PF_USER | X86_PF_RSVD))
		do_pf_error("Unexpected page-fault:", error_code, address, regs->ip);
	else if (ghcb_fault)
		do_pf_error("Page-fault on GHCB page:", error_code, address, regs->ip);

	/*
	kernel_add_identity_map(address, end);
}
