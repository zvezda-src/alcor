
#undef pr_fmt
#define pr_fmt(fmt)     "tdx: " fmt

#include <linux/cpufeature.h>
#include <asm/coco.h>
#include <asm/tdx.h>
#include <asm/vmx.h>
#include <asm/insn.h>
#include <asm/insn-eval.h>
#include <asm/pgtable.h>

#define TDX_GET_INFO			1
#define TDX_GET_VEINFO			3
#define TDX_ACCEPT_PAGE			6

#define TDVMCALL_MAP_GPA		0x10001

#define EPT_READ	0
#define EPT_WRITE	1

#define PORT_READ	0
#define PORT_WRITE	1

#define VE_IS_IO_IN(e)		((e) & BIT(3))
#define VE_GET_IO_SIZE(e)	(((e) & GENMASK(2, 0)) + 1)
#define VE_GET_PORT_NUM(e)	((e) >> 16)
#define VE_IS_IO_STRING(e)	((e) & BIT(4))

static inline u64 _tdx_hypercall(u64 fn, u64 r12, u64 r13, u64 r14, u64 r15)
{
	struct tdx_hypercall_args args = {
		.r10 = TDX_HYPERCALL_STANDARD,
		.r11 = fn,
		.r12 = r12,
		.r13 = r13,
		.r14 = r14,
		.r15 = r15,
	};

	return __tdx_hypercall(&args, 0);
}

void __tdx_hypercall_failed(void)
{
	panic("TDVMCALL failed. TDX module bug?");
}

static u64 hcall_func(u64 exit_reason)
{
	return exit_reason;
}

#ifdef CONFIG_KVM_GUEST
long tdx_kvm_hypercall(unsigned int nr, unsigned long p1, unsigned long p2,
		       unsigned long p3, unsigned long p4)
{
	struct tdx_hypercall_args args = {
		.r10 = nr,
		.r11 = p1,
		.r12 = p2,
		.r13 = p3,
		.r14 = p4,
	};

	return __tdx_hypercall(&args, 0);
}
EXPORT_SYMBOL_GPL(tdx_kvm_hypercall);
#endif

static inline void tdx_module_call(u64 fn, u64 rcx, u64 rdx, u64 r8, u64 r9,
				   struct tdx_module_output *out)
{
	if (__tdx_module_call(fn, rcx, rdx, r8, r9, out))
		panic("TDCALL %lld failed (Buggy TDX module!)\n", fn);
}

static u64 get_cc_mask(void)
{
	struct tdx_module_output out;
	unsigned int gpa_width;

	/*
	tdx_module_call(TDX_GET_INFO, 0, 0, 0, 0, &out);

	gpa_width = out.rcx & GENMASK(5, 0);

	/*
	return BIT_ULL(gpa_width - 1);
}

static int ve_instr_len(struct ve_info *ve)
{
	switch (ve->exit_reason) {
	case EXIT_REASON_HLT:
	case EXIT_REASON_MSR_READ:
	case EXIT_REASON_MSR_WRITE:
	case EXIT_REASON_CPUID:
	case EXIT_REASON_IO_INSTRUCTION:
		/* It is safe to use ve->instr_len for #VE due instructions */
		return ve->instr_len;
	case EXIT_REASON_EPT_VIOLATION:
		/*
		WARN_ONCE(1, "ve->instr_len is not defined for EPT violations");
		return 0;
	default:
		WARN_ONCE(1, "Unexpected #VE-type: %lld\n", ve->exit_reason);
		return ve->instr_len;
	}
}

static u64 __cpuidle __halt(const bool irq_disabled, const bool do_sti)
{
	struct tdx_hypercall_args args = {
		.r10 = TDX_HYPERCALL_STANDARD,
		.r11 = hcall_func(EXIT_REASON_HLT),
		.r12 = irq_disabled,
	};

	/*
	return __tdx_hypercall(&args, do_sti ? TDX_HCALL_ISSUE_STI : 0);
}

static int handle_halt(struct ve_info *ve)
{
	/*
	const bool irq_disabled = irqs_disabled();
	const bool do_sti = false;

	if (__halt(irq_disabled, do_sti))
		return -EIO;

	return ve_instr_len(ve);
}

void __cpuidle tdx_safe_halt(void)
{
	 /*
	const bool irq_disabled = false;
	const bool do_sti = true;

	/*
	if (__halt(irq_disabled, do_sti))
		WARN_ONCE(1, "HLT instruction emulation failed\n");
}

static int read_msr(struct pt_regs *regs, struct ve_info *ve)
{
	struct tdx_hypercall_args args = {
		.r10 = TDX_HYPERCALL_STANDARD,
		.r11 = hcall_func(EXIT_REASON_MSR_READ),
		.r12 = regs->cx,
	};

	/*
	if (__tdx_hypercall(&args, TDX_HCALL_HAS_OUTPUT))
		return -EIO;

	regs->ax = lower_32_bits(args.r11);
	regs->dx = upper_32_bits(args.r11);
	return ve_instr_len(ve);
}

static int write_msr(struct pt_regs *regs, struct ve_info *ve)
{
	struct tdx_hypercall_args args = {
		.r10 = TDX_HYPERCALL_STANDARD,
		.r11 = hcall_func(EXIT_REASON_MSR_WRITE),
		.r12 = regs->cx,
		.r13 = (u64)regs->dx << 32 | regs->ax,
	};

	/*
	if (__tdx_hypercall(&args, 0))
		return -EIO;

	return ve_instr_len(ve);
}

static int handle_cpuid(struct pt_regs *regs, struct ve_info *ve)
{
	struct tdx_hypercall_args args = {
		.r10 = TDX_HYPERCALL_STANDARD,
		.r11 = hcall_func(EXIT_REASON_CPUID),
		.r12 = regs->ax,
		.r13 = regs->cx,
	};

	/*
	if (regs->ax < 0x40000000 || regs->ax > 0x4FFFFFFF) {
		regs->ax = regs->bx = regs->cx = regs->dx = 0;
		return ve_instr_len(ve);
	}

	/*
	if (__tdx_hypercall(&args, TDX_HCALL_HAS_OUTPUT))
		return -EIO;

	/*
	regs->ax = args.r12;
	regs->bx = args.r13;
	regs->cx = args.r14;
	regs->dx = args.r15;

	return ve_instr_len(ve);
}

static bool mmio_read(int size, unsigned long addr, unsigned long *val)
{
	struct tdx_hypercall_args args = {
		.r10 = TDX_HYPERCALL_STANDARD,
		.r11 = hcall_func(EXIT_REASON_EPT_VIOLATION),
		.r12 = size,
		.r13 = EPT_READ,
		.r14 = addr,
		.r15 = *val,
	};

	if (__tdx_hypercall(&args, TDX_HCALL_HAS_OUTPUT))
		return false;
	return true;
}

static bool mmio_write(int size, unsigned long addr, unsigned long val)
{
	return !_tdx_hypercall(hcall_func(EXIT_REASON_EPT_VIOLATION), size,
			       EPT_WRITE, addr, val);
}

static int handle_mmio(struct pt_regs *regs, struct ve_info *ve)
{
	unsigned long *reg, val, vaddr;
	char buffer[MAX_INSN_SIZE];
	struct insn insn = {};
	enum mmio_type mmio;
	int size, extend_size;
	u8 extend_val = 0;

	/* Only in-kernel MMIO is supported */
	if (WARN_ON_ONCE(user_mode(regs)))
		return -EFAULT;

	if (copy_from_kernel_nofault(buffer, (void *)regs->ip, MAX_INSN_SIZE))
		return -EFAULT;

	if (insn_decode(&insn, buffer, MAX_INSN_SIZE, INSN_MODE_64))
		return -EINVAL;

	mmio = insn_decode_mmio(&insn, &size);
	if (WARN_ON_ONCE(mmio == MMIO_DECODE_FAILED))
		return -EINVAL;

	if (mmio != MMIO_WRITE_IMM && mmio != MMIO_MOVS) {
		reg = insn_get_modrm_reg_ptr(&insn, regs);
		if (!reg)
			return -EINVAL;
	}

	/*
	vaddr = (unsigned long)insn_get_addr_ref(&insn, regs);
	if (vaddr / PAGE_SIZE != (vaddr + size - 1) / PAGE_SIZE)
		return -EFAULT;

	/* Handle writes first */
	switch (mmio) {
	case MMIO_WRITE:
		memcpy(&val, reg, size);
		if (!mmio_write(size, ve->gpa, val))
			return -EIO;
		return insn.length;
	case MMIO_WRITE_IMM:
		val = insn.immediate.value;
		if (!mmio_write(size, ve->gpa, val))
			return -EIO;
		return insn.length;
	case MMIO_READ:
	case MMIO_READ_ZERO_EXTEND:
	case MMIO_READ_SIGN_EXTEND:
		/* Reads are handled below */
		break;
	case MMIO_MOVS:
	case MMIO_DECODE_FAILED:
		/*
		return -EINVAL;
	default:
		WARN_ONCE(1, "Unknown insn_decode_mmio() decode value?");
		return -EINVAL;
	}

	/* Handle reads */
	if (!mmio_read(size, ve->gpa, &val))
		return -EIO;

	switch (mmio) {
	case MMIO_READ:
		/* Zero-extend for 32-bit operation */
		extend_size = size == 4 ? sizeof(*reg) : 0;
		break;
	case MMIO_READ_ZERO_EXTEND:
		/* Zero extend based on operand size */
		extend_size = insn.opnd_bytes;
		break;
	case MMIO_READ_SIGN_EXTEND:
		/* Sign extend based on operand size */
		extend_size = insn.opnd_bytes;
		if (size == 1 && val & BIT(7))
			extend_val = 0xFF;
		else if (size > 1 && val & BIT(15))
			extend_val = 0xFF;
		break;
	default:
		/* All other cases has to be covered with the first switch() */
		WARN_ON_ONCE(1);
		return -EINVAL;
	}

	if (extend_size)
		memset(reg, extend_val, extend_size);
	memcpy(reg, &val, size);
	return insn.length;
}

static bool handle_in(struct pt_regs *regs, int size, int port)
{
	struct tdx_hypercall_args args = {
		.r10 = TDX_HYPERCALL_STANDARD,
		.r11 = hcall_func(EXIT_REASON_IO_INSTRUCTION),
		.r12 = size,
		.r13 = PORT_READ,
		.r14 = port,
	};
	u64 mask = GENMASK(BITS_PER_BYTE * size, 0);
	bool success;

	/*
	success = !__tdx_hypercall(&args, TDX_HCALL_HAS_OUTPUT);

	/* Update part of the register affected by the emulated instruction */
	regs->ax &= ~mask;
	if (success)
		regs->ax |= args.r11 & mask;

	return success;
}

static bool handle_out(struct pt_regs *regs, int size, int port)
{
	u64 mask = GENMASK(BITS_PER_BYTE * size, 0);

	/*
	return !_tdx_hypercall(hcall_func(EXIT_REASON_IO_INSTRUCTION), size,
			       PORT_WRITE, port, regs->ax & mask);
}

static int handle_io(struct pt_regs *regs, struct ve_info *ve)
{
	u32 exit_qual = ve->exit_qual;
	int size, port;
	bool in, ret;

	if (VE_IS_IO_STRING(exit_qual))
		return -EIO;

	in   = VE_IS_IO_IN(exit_qual);
	size = VE_GET_IO_SIZE(exit_qual);
	port = VE_GET_PORT_NUM(exit_qual);


	if (in)
		ret = handle_in(regs, size, port);
	else
		ret = handle_out(regs, size, port);
	if (!ret)
		return -EIO;

	return ve_instr_len(ve);
}

__init bool tdx_early_handle_ve(struct pt_regs *regs)
{
	struct ve_info ve;
	int insn_len;

	tdx_get_ve_info(&ve);

	if (ve.exit_reason != EXIT_REASON_IO_INSTRUCTION)
		return false;

	insn_len = handle_io(regs, &ve);
	if (insn_len < 0)
		return false;

	regs->ip += insn_len;
	return true;
}

void tdx_get_ve_info(struct ve_info *ve)
{
	struct tdx_module_output out;

	/*
	tdx_module_call(TDX_GET_VEINFO, 0, 0, 0, 0, &out);

	/* Transfer the output parameters */
	ve->exit_reason = out.rcx;
	ve->exit_qual   = out.rdx;
	ve->gla         = out.r8;
	ve->gpa         = out.r9;
	ve->instr_len   = lower_32_bits(out.r10);
	ve->instr_info  = upper_32_bits(out.r10);
}

static int virt_exception_user(struct pt_regs *regs, struct ve_info *ve)
{
	switch (ve->exit_reason) {
	case EXIT_REASON_CPUID:
		return handle_cpuid(regs, ve);
	default:
		pr_warn("Unexpected #VE: %lld\n", ve->exit_reason);
		return -EIO;
	}
}

static int virt_exception_kernel(struct pt_regs *regs, struct ve_info *ve)
{
	switch (ve->exit_reason) {
	case EXIT_REASON_HLT:
		return handle_halt(ve);
	case EXIT_REASON_MSR_READ:
		return read_msr(regs, ve);
	case EXIT_REASON_MSR_WRITE:
		return write_msr(regs, ve);
	case EXIT_REASON_CPUID:
		return handle_cpuid(regs, ve);
	case EXIT_REASON_EPT_VIOLATION:
		return handle_mmio(regs, ve);
	case EXIT_REASON_IO_INSTRUCTION:
		return handle_io(regs, ve);
	default:
		pr_warn("Unexpected #VE: %lld\n", ve->exit_reason);
		return -EIO;
	}
}

bool tdx_handle_virt_exception(struct pt_regs *regs, struct ve_info *ve)
{
	int insn_len;

	if (user_mode(regs))
		insn_len = virt_exception_user(regs, ve);
	else
		insn_len = virt_exception_kernel(regs, ve);
	if (insn_len < 0)
		return false;

	/* After successful #VE handling, move the IP */
	regs->ip += insn_len;

	return true;
}

static bool tdx_tlb_flush_required(bool private)
{
	/*
	return !private;
}

static bool tdx_cache_flush_required(void)
{
	/*
	return true;
}

static bool try_accept_one(phys_addr_t *start, unsigned long len,
			  enum pg_level pg_level)
{
	unsigned long accept_size = page_level_size(pg_level);
	u64 tdcall_rcx;
	u8 page_size;

	if (!IS_ALIGNED(*start, accept_size))
		return false;

	if (len < accept_size)
		return false;

	/*
	switch (pg_level) {
	case PG_LEVEL_4K:
		page_size = 0;
		break;
	case PG_LEVEL_2M:
		page_size = 1;
		break;
	case PG_LEVEL_1G:
		page_size = 2;
		break;
	default:
		return false;
	}

	tdcall_rcx = *start | page_size;
	if (__tdx_module_call(TDX_ACCEPT_PAGE, tdcall_rcx, 0, 0, 0, NULL))
		return false;

	return true;
}

static bool tdx_enc_status_changed(unsigned long vaddr, int numpages, bool enc)
{
	phys_addr_t start = __pa(vaddr);
	phys_addr_t end   = __pa(vaddr + numpages * PAGE_SIZE);

	if (!enc) {
		/* Set the shared (decrypted) bits: */
		start |= cc_mkdec(0);
		end   |= cc_mkdec(0);
	}

	/*
	if (_tdx_hypercall(TDVMCALL_MAP_GPA, start, end - start, 0, 0))
		return false;

	/* private->shared conversion  requires only MapGPA call */
	if (!enc)
		return true;

	/*
	while (start < end) {
		unsigned long len = end - start;

		/*

		if (try_accept_one(&start, len, PG_LEVEL_1G))
			continue;

		if (try_accept_one(&start, len, PG_LEVEL_2M))
			continue;

		if (!try_accept_one(&start, len, PG_LEVEL_4K))
			return false;
	}

	return true;
}

void __init tdx_early_init(void)
{
	u64 cc_mask;
	u32 eax, sig[3];

	cpuid_count(TDX_CPUID_LEAF_ID, 0, &eax, &sig[0], &sig[2],  &sig[1]);

	if (memcmp(TDX_IDENT, sig, sizeof(sig)))
		return;

	setup_force_cpu_cap(X86_FEATURE_TDX_GUEST);

	cc_set_vendor(CC_VENDOR_INTEL);
	cc_mask = get_cc_mask();
	cc_set_mask(cc_mask);

	/*
	physical_mask &= cc_mask - 1;

	x86_platform.guest.enc_cache_flush_required = tdx_cache_flush_required;
	x86_platform.guest.enc_tlb_flush_required   = tdx_tlb_flush_required;
	x86_platform.guest.enc_status_change_finish = tdx_enc_status_changed;

	pr_info("Guest detected\n");
}
