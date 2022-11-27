#ifndef _ASM_X86_SPARSEMEM_H
#define _ASM_X86_SPARSEMEM_H

#ifdef CONFIG_SPARSEMEM

#ifdef CONFIG_X86_32
# ifdef CONFIG_X86_PAE
#  define SECTION_SIZE_BITS	29
#  define MAX_PHYSMEM_BITS	36
# else
#  define SECTION_SIZE_BITS	26
#  define MAX_PHYSMEM_BITS	32
# endif
#else /* CONFIG_X86_32 */
# define SECTION_SIZE_BITS	27 /* matt - 128 is convenient right now */
# define MAX_PHYSMEM_BITS	(pgtable_l5_enabled() ? 52 : 46)
#endif

#endif /* CONFIG_SPARSEMEM */

#ifndef __ASSEMBLY__
#ifdef CONFIG_NUMA_KEEP_MEMINFO
extern int phys_to_target_node(phys_addr_t start);
#define phys_to_target_node phys_to_target_node
extern int memory_add_physaddr_to_nid(u64 start);
#define memory_add_physaddr_to_nid memory_add_physaddr_to_nid
#endif
#endif /* __ASSEMBLY__ */

#endif /* _ASM_X86_SPARSEMEM_H */
