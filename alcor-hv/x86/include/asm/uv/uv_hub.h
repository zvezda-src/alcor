
#ifndef _ASM_X86_UV_UV_HUB_H
#define _ASM_X86_UV_UV_HUB_H

#ifdef CONFIG_X86_64
#include <linux/numa.h>
#include <linux/percpu.h>
#include <linux/timer.h>
#include <linux/io.h>
#include <linux/topology.h>
#include <asm/types.h>
#include <asm/percpu.h>
#include <asm/uv/uv.h>
#include <asm/uv/uv_mmrs.h>
#include <asm/uv/bios.h>
#include <asm/irq_vectors.h>
#include <asm/io_apic.h>



#define UV_MAX_NUMALINK_BLADES	16384

#define UV_MAX_SSI_BLADES	256

#define UV_MAX_NASID_VALUE	(UV_MAX_NUMALINK_BLADES * 2)

struct uv_gam_range_s {
	u32	limit;		/* PA bits 56:26 (GAM_RANGE_SHFT) */
	u16	nasid;		/* node's global physical address */
	s8	base;		/* entry index of node's base addr */
	u8	reserved;
};

struct uv_hub_info_s {
	unsigned int		hub_type;
	unsigned char		hub_revision;
	unsigned long		global_mmr_base;
	unsigned long		global_mmr_shift;
	unsigned long		gpa_mask;
	unsigned short		*socket_to_node;
	unsigned short		*socket_to_pnode;
	unsigned short		*pnode_to_socket;
	struct uv_gam_range_s	*gr_table;
	unsigned short		min_socket;
	unsigned short		min_pnode;
	unsigned char		m_val;
	unsigned char		n_val;
	unsigned char		gr_table_len;
	unsigned char		apic_pnode_shift;
	unsigned char		gpa_shift;
	unsigned char		nasid_shift;
	unsigned char		m_shift;
	unsigned char		n_lshift;
	unsigned int		gnode_extra;
	unsigned long		gnode_upper;
	unsigned long		lowmem_remap_top;
	unsigned long		lowmem_remap_base;
	unsigned long		global_gru_base;
	unsigned long		global_gru_shift;
	unsigned short		pnode;
	unsigned short		pnode_mask;
	unsigned short		coherency_domain_number;
	unsigned short		numa_blade_id;
	unsigned short		nr_possible_cpus;
	unsigned short		nr_online_cpus;
	short			memory_nid;
};

struct uv_cpu_info_s {
	void			*p_uv_hub_info;
	unsigned char		blade_cpu_id;
	void			*reserved;
};
DECLARE_PER_CPU(struct uv_cpu_info_s, __uv_cpu_info);

#define uv_cpu_info		this_cpu_ptr(&__uv_cpu_info)
#define uv_cpu_info_per(cpu)	(&per_cpu(__uv_cpu_info, cpu))

extern void **__uv_hub_info_list;
static inline struct uv_hub_info_s *uv_hub_info_list(int node)
{
	return (struct uv_hub_info_s *)__uv_hub_info_list[node];
}

static inline struct uv_hub_info_s *_uv_hub_info(void)
{
	return (struct uv_hub_info_s *)uv_cpu_info->p_uv_hub_info;
}
#define	uv_hub_info	_uv_hub_info()

static inline struct uv_hub_info_s *uv_cpu_hub_info(int cpu)
{
	return (struct uv_hub_info_s *)uv_cpu_info_per(cpu)->p_uv_hub_info;
}

static inline int uv_hub_type(void)
{
	return uv_hub_info->hub_type;
}

static inline __init void uv_hub_type_set(int uvmask)
{
	uv_hub_info->hub_type = uvmask;
}


#define UV2_HUB_REVISION_BASE		3
#define UV3_HUB_REVISION_BASE		5
#define UV4_HUB_REVISION_BASE		7
#define UV4A_HUB_REVISION_BASE		8	/* UV4 (fixed) rev 2 */
#define UV5_HUB_REVISION_BASE		9

static inline int is_uv(int uvmask) { return uv_hub_type() & uvmask; }
static inline int is_uv1_hub(void) { return 0; }
static inline int is_uv2_hub(void) { return is_uv(UV2); }
static inline int is_uv3_hub(void) { return is_uv(UV3); }
static inline int is_uv4a_hub(void) { return is_uv(UV4A); }
static inline int is_uv4_hub(void) { return is_uv(UV4); }
static inline int is_uv5_hub(void) { return is_uv(UV5); }


static inline int is_uvx_hub(void) { return is_uv(UVX); }

static inline int is_uvy_hub(void) { return is_uv(UVY); }

static inline int is_uv_hub(void) { return is_uv(UV_ANY); }

union uvh_apicid {
    unsigned long       v;
    struct uvh_apicid_s {
        unsigned long   local_apic_mask  : 24;
        unsigned long   local_apic_shift :  5;
        unsigned long   unused1          :  3;
        unsigned long   pnode_mask       : 24;
        unsigned long   pnode_shift      :  5;
        unsigned long   unused2          :  3;
    } s;
};

#define UV_NASID_TO_PNODE(n)		\
		(((n) >> uv_hub_info->nasid_shift) & uv_hub_info->pnode_mask)
#define UV_PNODE_TO_GNODE(p)		((p) |uv_hub_info->gnode_extra)
#define UV_PNODE_TO_NASID(p)		\
		(UV_PNODE_TO_GNODE(p) << uv_hub_info->nasid_shift)

#define UV2_LOCAL_MMR_BASE		0xfa000000UL
#define UV2_GLOBAL_MMR32_BASE		0xfc000000UL
#define UV2_LOCAL_MMR_SIZE		(32UL * 1024 * 1024)
#define UV2_GLOBAL_MMR32_SIZE		(32UL * 1024 * 1024)

#define UV3_LOCAL_MMR_BASE		0xfa000000UL
#define UV3_GLOBAL_MMR32_BASE		0xfc000000UL
#define UV3_LOCAL_MMR_SIZE		(32UL * 1024 * 1024)
#define UV3_GLOBAL_MMR32_SIZE		(32UL * 1024 * 1024)

#define UV4_LOCAL_MMR_BASE		0xfa000000UL
#define UV4_GLOBAL_MMR32_BASE		0
#define UV4_LOCAL_MMR_SIZE		(32UL * 1024 * 1024)
#define UV4_GLOBAL_MMR32_SIZE		0

#define UV5_LOCAL_MMR_BASE		0xfa000000UL
#define UV5_GLOBAL_MMR32_BASE		0
#define UV5_LOCAL_MMR_SIZE		(32UL * 1024 * 1024)
#define UV5_GLOBAL_MMR32_SIZE		0

#define UV_LOCAL_MMR_BASE		(				\
					is_uv(UV2) ? UV2_LOCAL_MMR_BASE : \
					is_uv(UV3) ? UV3_LOCAL_MMR_BASE : \
					is_uv(UV4) ? UV4_LOCAL_MMR_BASE : \
					is_uv(UV5) ? UV5_LOCAL_MMR_BASE : \
					0)

#define UV_GLOBAL_MMR32_BASE		(				\
					is_uv(UV2) ? UV2_GLOBAL_MMR32_BASE : \
					is_uv(UV3) ? UV3_GLOBAL_MMR32_BASE : \
					is_uv(UV4) ? UV4_GLOBAL_MMR32_BASE : \
					is_uv(UV5) ? UV5_GLOBAL_MMR32_BASE : \
					0)

#define UV_LOCAL_MMR_SIZE		(				\
					is_uv(UV2) ? UV2_LOCAL_MMR_SIZE : \
					is_uv(UV3) ? UV3_LOCAL_MMR_SIZE : \
					is_uv(UV4) ? UV4_LOCAL_MMR_SIZE : \
					is_uv(UV5) ? UV5_LOCAL_MMR_SIZE : \
					0)

#define UV_GLOBAL_MMR32_SIZE		(				\
					is_uv(UV2) ? UV2_GLOBAL_MMR32_SIZE : \
					is_uv(UV3) ? UV3_GLOBAL_MMR32_SIZE : \
					is_uv(UV4) ? UV4_GLOBAL_MMR32_SIZE : \
					is_uv(UV5) ? UV5_GLOBAL_MMR32_SIZE : \
					0)

#define UV_GLOBAL_MMR64_BASE		(uv_hub_info->global_mmr_base)

#define UV_GLOBAL_GRU_MMR_BASE		0x4000000

#define UV_GLOBAL_MMR32_PNODE_SHIFT	15
#define _UV_GLOBAL_MMR64_PNODE_SHIFT	26
#define UV_GLOBAL_MMR64_PNODE_SHIFT	(uv_hub_info->global_mmr_shift)

#define UV_GLOBAL_MMR32_PNODE_BITS(p)	((p) << (UV_GLOBAL_MMR32_PNODE_SHIFT))

#define UV_GLOBAL_MMR64_PNODE_BITS(p)					\
	(((unsigned long)(p)) << UV_GLOBAL_MMR64_PNODE_SHIFT)

#define UVH_APICID		0x002D0E00L
#define UV_APIC_PNODE_SHIFT	6

#define LOCAL_BUS_BASE		0x1c00000
#define LOCAL_BUS_SIZE		(4 * 1024 * 1024)

#define SCIR_WINDOW_COUNT	64
#define SCIR_LOCAL_MMR_BASE	(LOCAL_BUS_BASE + \
				 LOCAL_BUS_SIZE - \
				 SCIR_WINDOW_COUNT)

#define SCIR_CPU_HEARTBEAT	0x01	/* timer interrupt */
#define SCIR_CPU_ACTIVITY	0x02	/* not idle */
#define SCIR_CPU_HB_INTERVAL	(HZ)	/* once per second */

#define for_each_possible_blade(bid)		\
	for ((bid) = 0; (bid) < uv_num_possible_blades(); (bid)++)


static inline unsigned int uv_gpa_shift(void)
{
	return uv_hub_info->gpa_shift;
}
#define	_uv_gpa_shift

static inline struct uv_gam_range_s *uv_gam_range(unsigned long pa)
{
	struct uv_gam_range_s *gr = uv_hub_info->gr_table;
	unsigned long pal = (pa & uv_hub_info->gpa_mask) >> UV_GAM_RANGE_SHFT;
	int i, num = uv_hub_info->gr_table_len;

	if (gr) {
		for (i = 0; i < num; i++, gr++) {
			if (pal < gr->limit)
				return gr;
		}
	}
	pr_crit("UV: GAM Range for 0x%lx not found at %p!\n", pa, gr);
	BUG();
}

static inline unsigned long uv_gam_range_base(unsigned long pa)
{
	struct uv_gam_range_s *gr = uv_gam_range(pa);
	int base = gr->base;

	if (base < 0)
		return 0UL;

	return uv_hub_info->gr_table[base].limit;
}

static inline unsigned long uv_soc_phys_ram_to_nasid(unsigned long paddr)
{
	return uv_gam_range(paddr)->nasid;
}
#define	_uv_soc_phys_ram_to_nasid

static inline unsigned long uv_gpa_nasid(void *v)
{
	return uv_soc_phys_ram_to_nasid(__pa(v));
}

static inline unsigned long uv_soc_phys_ram_to_gpa(unsigned long paddr)
{
	unsigned int m_val = uv_hub_info->m_val;

	if (paddr < uv_hub_info->lowmem_remap_top)
		paddr |= uv_hub_info->lowmem_remap_base;

	if (m_val) {
		paddr |= uv_hub_info->gnode_upper;
		paddr = ((paddr << uv_hub_info->m_shift)
						>> uv_hub_info->m_shift) |
			((paddr >> uv_hub_info->m_val)
						<< uv_hub_info->n_lshift);
	} else {
		paddr |= uv_soc_phys_ram_to_nasid(paddr)
						<< uv_hub_info->gpa_shift;
	}
	return paddr;
}

static inline unsigned long uv_gpa(void *v)
{
	return uv_soc_phys_ram_to_gpa(__pa(v));
}

static inline int
uv_gpa_in_mmr_space(unsigned long gpa)
{
	return (gpa >> 62) == 0x3UL;
}

static inline unsigned long uv_gpa_to_soc_phys_ram(unsigned long gpa)
{
	unsigned long paddr;
	unsigned long remap_base = uv_hub_info->lowmem_remap_base;
	unsigned long remap_top =  uv_hub_info->lowmem_remap_top;
	unsigned int m_val = uv_hub_info->m_val;

	if (m_val)
		gpa = ((gpa << uv_hub_info->m_shift) >> uv_hub_info->m_shift) |
			((gpa >> uv_hub_info->n_lshift) << uv_hub_info->m_val);

	paddr = gpa & uv_hub_info->gpa_mask;
	if (paddr >= remap_base && paddr < remap_base + remap_top)
		paddr -= remap_base;
	return paddr;
}

static inline unsigned long uv_gpa_to_gnode(unsigned long gpa)
{
	unsigned int n_lshift = uv_hub_info->n_lshift;

	if (n_lshift)
		return gpa >> n_lshift;

	return uv_gam_range(gpa)->nasid >> 1;
}

static inline int uv_gpa_to_pnode(unsigned long gpa)
{
	return uv_gpa_to_gnode(gpa) & uv_hub_info->pnode_mask;
}

static inline unsigned long uv_gpa_to_offset(unsigned long gpa)
{
	unsigned int m_shift = uv_hub_info->m_shift;

	if (m_shift)
		return (gpa << m_shift) >> m_shift;

	return (gpa & uv_hub_info->gpa_mask) - uv_gam_range_base(gpa);
}

static inline int _uv_socket_to_node(int socket, unsigned short *s2nid)
{
	return s2nid ? s2nid[socket - uv_hub_info->min_socket] : socket;
}

static inline int uv_socket_to_node(int socket)
{
	return _uv_socket_to_node(socket, uv_hub_info->socket_to_node);
}

static inline void *uv_pnode_offset_to_vaddr(int pnode, unsigned long offset)
{
	unsigned int m_val = uv_hub_info->m_val;
	unsigned long base;
	unsigned short sockid, node, *p2s;

	if (m_val)
		return __va(((unsigned long)pnode << m_val) | offset);

	p2s = uv_hub_info->pnode_to_socket;
	sockid = p2s ? p2s[pnode - uv_hub_info->min_pnode] : pnode;
	node = uv_socket_to_node(sockid);

	/* limit address of previous socket is our base, except node 0 is 0 */
	if (!node)
		return __va((unsigned long)offset);

	base = (unsigned long)(uv_hub_info->gr_table[node - 1].limit);
	return __va(base << UV_GAM_RANGE_SHFT | offset);
}

static inline int uv_apicid_to_pnode(int apicid)
{
	int pnode = apicid >> uv_hub_info->apic_pnode_shift;
	unsigned short *s2pn = uv_hub_info->socket_to_pnode;

	return s2pn ? s2pn[pnode - uv_hub_info->min_socket] : pnode;
}

static inline unsigned long *uv_global_mmr32_address(int pnode, unsigned long offset)
{
	return __va(UV_GLOBAL_MMR32_BASE |
		       UV_GLOBAL_MMR32_PNODE_BITS(pnode) | offset);
}

static inline void uv_write_global_mmr32(int pnode, unsigned long offset, unsigned long val)
{
	writeq(val, uv_global_mmr32_address(pnode, offset));
}

static inline unsigned long uv_read_global_mmr32(int pnode, unsigned long offset)
{
	return readq(uv_global_mmr32_address(pnode, offset));
}

static inline volatile void __iomem *uv_global_mmr64_address(int pnode, unsigned long offset)
{
	return __va(UV_GLOBAL_MMR64_BASE |
		    UV_GLOBAL_MMR64_PNODE_BITS(pnode) | offset);
}

static inline void uv_write_global_mmr64(int pnode, unsigned long offset, unsigned long val)
{
	writeq(val, uv_global_mmr64_address(pnode, offset));
}

static inline unsigned long uv_read_global_mmr64(int pnode, unsigned long offset)
{
	return readq(uv_global_mmr64_address(pnode, offset));
}

static inline void uv_write_global_mmr8(int pnode, unsigned long offset, unsigned char val)
{
	writeb(val, uv_global_mmr64_address(pnode, offset));
}

static inline unsigned char uv_read_global_mmr8(int pnode, unsigned long offset)
{
	return readb(uv_global_mmr64_address(pnode, offset));
}

static inline unsigned long *uv_local_mmr_address(unsigned long offset)
{
	return __va(UV_LOCAL_MMR_BASE | offset);
}

static inline unsigned long uv_read_local_mmr(unsigned long offset)
{
	return readq(uv_local_mmr_address(offset));
}

static inline void uv_write_local_mmr(unsigned long offset, unsigned long val)
{
	writeq(val, uv_local_mmr_address(offset));
}

static inline unsigned char uv_read_local_mmr8(unsigned long offset)
{
	return readb(uv_local_mmr_address(offset));
}

static inline void uv_write_local_mmr8(unsigned long offset, unsigned char val)
{
	writeb(val, uv_local_mmr_address(offset));
}

static inline int uv_blade_processor_id(void)
{
	return uv_cpu_info->blade_cpu_id;
}

static inline int uv_cpu_blade_processor_id(int cpu)
{
	return uv_cpu_info_per(cpu)->blade_cpu_id;
}

static inline int uv_blade_to_node(int blade)
{
	return blade;
}

static inline int uv_numa_blade_id(void)
{
	return uv_hub_info->numa_blade_id;
}

static inline int uv_node_to_blade_id(int nid)
{
	return nid;
}

static inline int uv_cpu_to_blade_id(int cpu)
{
	return uv_node_to_blade_id(cpu_to_node(cpu));
}

static inline int uv_blade_to_pnode(int bid)
{
	return uv_hub_info_list(uv_blade_to_node(bid))->pnode;
}

static inline int uv_blade_to_memory_nid(int bid)
{
	return uv_hub_info_list(uv_blade_to_node(bid))->memory_nid;
}

static inline int uv_blade_nr_possible_cpus(int bid)
{
	return uv_hub_info_list(uv_blade_to_node(bid))->nr_possible_cpus;
}

static inline int uv_blade_nr_online_cpus(int bid)
{
	return uv_hub_info_list(uv_blade_to_node(bid))->nr_online_cpus;
}

static inline int uv_cpu_to_pnode(int cpu)
{
	return uv_cpu_hub_info(cpu)->pnode;
}

static inline int uv_node_to_pnode(int nid)
{
	return uv_hub_info_list(nid)->pnode;
}

extern short uv_possible_blades;
static inline int uv_num_possible_blades(void)
{
	return uv_possible_blades;
}

extern void uv_nmi_setup(void);
extern void uv_nmi_setup_hubless(void);

#define UVH_BIOS_KERNEL_MMR		UVH_SCRATCH5
#define UVH_BIOS_KERNEL_MMR_ALIAS	UVH_SCRATCH5_ALIAS
#define UVH_BIOS_KERNEL_MMR_ALIAS_2	UVH_SCRATCH5_ALIAS_2

#define UVH_TSC_SYNC_MMR	UVH_BIOS_KERNEL_MMR
#define UVH_TSC_SYNC_SHIFT	10
#define UVH_TSC_SYNC_SHIFT_UV2K	16	/* UV2/3k have different bits */
#define UVH_TSC_SYNC_MASK	3	/* 0011 */
#define UVH_TSC_SYNC_VALID	3	/* 0011 */
#define UVH_TSC_SYNC_UNKNOWN	0	/* 0000 */

#define UVH_NMI_MMR		UVH_BIOS_KERNEL_MMR
#define UVH_NMI_MMR_CLEAR	UVH_BIOS_KERNEL_MMR_ALIAS
#define UVH_NMI_MMR_SHIFT	63
#define UVH_NMI_MMR_TYPE	"SCRATCH5"

struct uv_hub_nmi_s {
	raw_spinlock_t	nmi_lock;
	atomic_t	in_nmi;		/* flag this node in UV NMI IRQ */
	atomic_t	cpu_owner;	/* last locker of this struct */
	atomic_t	read_mmr_count;	/* count of MMR reads */
	atomic_t	nmi_count;	/* count of true UV NMIs */
	unsigned long	nmi_value;	/* last value read from NMI MMR */
	bool		hub_present;	/* false means UV hubless system */
	bool		pch_owner;	/* indicates this hub owns PCH */
};

struct uv_cpu_nmi_s {
	struct uv_hub_nmi_s	*hub;
	int			state;
	int			pinging;
	int			queries;
	int			pings;
};

DECLARE_PER_CPU(struct uv_cpu_nmi_s, uv_cpu_nmi);

#define uv_hub_nmi			this_cpu_read(uv_cpu_nmi.hub)
#define uv_cpu_nmi_per(cpu)		(per_cpu(uv_cpu_nmi, cpu))
#define uv_hub_nmi_per(cpu)		(uv_cpu_nmi_per(cpu).hub)

#define	UV_NMI_STATE_OUT		0
#define	UV_NMI_STATE_IN			1
#define	UV_NMI_STATE_DUMP		2
#define	UV_NMI_STATE_DUMP_DONE		3

static inline int uv_get_min_hub_revision_id(void)
{
	return uv_hub_info->hub_revision;
}

#endif /* CONFIG_X86_64 */
#endif /* _ASM_X86_UV_UV_HUB_H */
