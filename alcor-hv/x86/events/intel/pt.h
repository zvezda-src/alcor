
#ifndef __INTEL_PT_H__
#define __INTEL_PT_H__

#define TOPA_PMI_MARGIN 512

#define TOPA_SHIFT 12

static inline unsigned int sizes(unsigned int tsz)
{
	return 1 << (tsz + TOPA_SHIFT);
};

struct topa_entry {
	u64	end	: 1;
	u64	rsvd0	: 1;
	u64	intr	: 1;
	u64	rsvd1	: 1;
	u64	stop	: 1;
	u64	rsvd2	: 1;
	u64	size	: 4;
	u64	rsvd3	: 2;
	u64	base	: 36;
	u64	rsvd4	: 16;
};

#define CPUID_TSC_LEAF		0x15

struct pt_pmu {
	struct pmu		pmu;
	u32			caps[PT_CPUID_REGS_NUM * PT_CPUID_LEAVES];
	bool			vmx;
	bool			branch_en_always_on;
	unsigned long		max_nonturbo_ratio;
	unsigned int		tsc_art_num;
	unsigned int		tsc_art_den;
};

struct pt_buffer {
	struct list_head	tables;
	struct topa		*first, *last, *cur;
	unsigned int		cur_idx;
	size_t			output_off;
	unsigned long		nr_pages;
	local_t			data_size;
	local64_t		head;
	bool			snapshot;
	bool			single;
	long			stop_pos, intr_pos;
	struct topa_entry	*stop_te, *intr_te;
	void			**data_pages;
};

#define PT_FILTERS_NUM	4

struct pt_filter {
	unsigned long	msr_a;
	unsigned long	msr_b;
	unsigned long	config;
};

struct pt_filters {
	struct pt_filter	filter[PT_FILTERS_NUM];
	unsigned int		nr_filters;
};

struct pt {
	struct perf_output_handle handle;
	struct pt_filters	filters;
	int			handle_nmi;
	int			vmx_on;
	u64			output_base;
	u64			output_mask;
};

#endif /* __INTEL_PT_H__ */
