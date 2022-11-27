#ifndef _X86_SGX_H
#define _X86_SGX_H

#include <linux/bitops.h>
#include <linux/err.h>
#include <linux/io.h>
#include <linux/rwsem.h>
#include <linux/types.h>
#include <asm/asm.h>
#include <asm/sgx.h>

#undef pr_fmt
#define pr_fmt(fmt) "sgx: " fmt

#define EREMOVE_ERROR_MESSAGE \
	"EREMOVE returned %d (0x%x) and an EPC page was leaked. SGX may become unusable. " \
	"Refer to Documentation/x86/sgx.rst for more information."

#define SGX_MAX_EPC_SECTIONS		8
#define SGX_EEXTEND_BLOCK_SIZE		256
#define SGX_NR_TO_SCAN			16
#define SGX_NR_LOW_PAGES		32
#define SGX_NR_HIGH_PAGES		64

#define SGX_EPC_PAGE_RECLAIMER_TRACKED	BIT(0)

#define SGX_EPC_PAGE_IS_FREE		BIT(1)

struct sgx_epc_page {
	unsigned int section;
	u16 flags;
	u16 poison;
	struct sgx_encl_page *owner;
	struct list_head list;
};

struct sgx_numa_node {
	struct list_head free_page_list;
	struct list_head sgx_poison_page_list;
	unsigned long size;
	spinlock_t lock;
};

struct sgx_epc_section {
	unsigned long phys_addr;
	void *virt_addr;
	struct sgx_epc_page *pages;
	struct sgx_numa_node *node;
};

extern struct sgx_epc_section sgx_epc_sections[SGX_MAX_EPC_SECTIONS];

static inline unsigned long sgx_get_epc_phys_addr(struct sgx_epc_page *page)
{
	struct sgx_epc_section *section = &sgx_epc_sections[page->section];
	unsigned long index;

	index = ((unsigned long)page - (unsigned long)section->pages) / sizeof(*page);

	return section->phys_addr + index * PAGE_SIZE;
}

static inline void *sgx_get_epc_virt_addr(struct sgx_epc_page *page)
{
	struct sgx_epc_section *section = &sgx_epc_sections[page->section];
	unsigned long index;

	index = ((unsigned long)page - (unsigned long)section->pages) / sizeof(*page);

	return section->virt_addr + index * PAGE_SIZE;
}

struct sgx_epc_page *__sgx_alloc_epc_page(void);
void sgx_free_epc_page(struct sgx_epc_page *page);

void sgx_reclaim_direct(void);
void sgx_mark_page_reclaimable(struct sgx_epc_page *page);
int sgx_unmark_page_reclaimable(struct sgx_epc_page *page);
struct sgx_epc_page *sgx_alloc_epc_page(void *owner, bool reclaim);

void sgx_ipi_cb(void *info);

#ifdef CONFIG_X86_SGX_KVM
int __init sgx_vepc_init(void);
#else
static inline int __init sgx_vepc_init(void)
{
	return -ENODEV;
}
#endif

void sgx_update_lepubkeyhash(u64 *lepubkeyhash);

#endif /* _X86_SGX_H */
