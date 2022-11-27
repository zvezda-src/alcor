#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/ptrace.h>
#include <linux/uprobes.h>
#include <linux/uaccess.h>

#include <linux/kdebug.h>
#include <asm/processor.h>
#include <asm/insn.h>
#include <asm/mmu_context.h>


#define UPROBE_FIX_IP		0x01

#define UPROBE_FIX_CALL		0x02

#define UPROBE_FIX_SETF		0x04

#define UPROBE_FIX_RIP_SI	0x08
#define UPROBE_FIX_RIP_DI	0x10
#define UPROBE_FIX_RIP_BX	0x20
#define UPROBE_FIX_RIP_MASK	\
	(UPROBE_FIX_RIP_SI | UPROBE_FIX_RIP_DI | UPROBE_FIX_RIP_BX)

#define	UPROBE_TRAP_NR		UINT_MAX

#define OPCODE1(insn)		((insn)->opcode.bytes[0])
#define OPCODE2(insn)		((insn)->opcode.bytes[1])
#define OPCODE3(insn)		((insn)->opcode.bytes[2])
#define MODRM_REG(insn)		X86_MODRM_REG((insn)->modrm.value)

#define W(row, b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, ba, bb, bc, bd, be, bf)\
	(((b0##UL << 0x0)|(b1##UL << 0x1)|(b2##UL << 0x2)|(b3##UL << 0x3) |   \
	  (b4##UL << 0x4)|(b5##UL << 0x5)|(b6##UL << 0x6)|(b7##UL << 0x7) |   \
	  (b8##UL << 0x8)|(b9##UL << 0x9)|(ba##UL << 0xa)|(bb##UL << 0xb) |   \
	  (bc##UL << 0xc)|(bd##UL << 0xd)|(be##UL << 0xe)|(bf##UL << 0xf))    \
	 << (row % 32))

#if defined(CONFIG_X86_32) || defined(CONFIG_IA32_EMULATION)
static volatile u32 good_insns_32[256 / 32] = {
	/*      0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f         */
	/*      ----------------------------------------------         */
	W(0x00, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1) | /* 00 */
	W(0x10, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0) , /* 10 */
	W(0x20, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1) | /* 20 */
	W(0x30, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1) , /* 30 */
	W(0x40, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1) | /* 40 */
	W(0x50, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1) , /* 50 */
	W(0x60, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0) | /* 60 */
	W(0x70, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1) , /* 70 */
	W(0x80, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1) | /* 80 */
	W(0x90, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1) , /* 90 */
	W(0xa0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1) | /* a0 */
	W(0xb0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1) , /* b0 */
	W(0xc0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0) | /* c0 */
	W(0xd0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1) , /* d0 */
	W(0xe0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0) | /* e0 */
	W(0xf0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1)   /* f0 */
	/*      ----------------------------------------------         */
	/*      0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f         */
};
#else
#define good_insns_32	NULL
#endif

#if defined(CONFIG_X86_64)
static volatile u32 good_insns_64[256 / 32] = {
	/*      0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f         */
	/*      ----------------------------------------------         */
	W(0x00, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1) | /* 00 */
	W(0x10, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0) , /* 10 */
	W(0x20, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0) | /* 20 */
	W(0x30, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0) , /* 30 */
	W(0x40, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1) | /* 40 */
	W(0x50, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1) , /* 50 */
	W(0x60, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0) | /* 60 */
	W(0x70, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1) , /* 70 */
	W(0x80, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1) | /* 80 */
	W(0x90, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1) , /* 90 */
	W(0xa0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1) | /* a0 */
	W(0xb0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1) , /* b0 */
	W(0xc0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0) | /* c0 */
	W(0xd0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1) , /* d0 */
	W(0xe0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0) | /* e0 */
	W(0xf0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1)   /* f0 */
	/*      ----------------------------------------------         */
	/*      0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f         */
};
#else
#define good_insns_64	NULL
#endif

static volatile u32 good_2byte_insns[256 / 32] = {
	/*      0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f         */
	/*      ----------------------------------------------         */
	W(0x00, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1) | /* 00 */
	W(0x10, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1) , /* 10 */
	W(0x20, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1) | /* 20 */
	W(0x30, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1) , /* 30 */
	W(0x40, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1) | /* 40 */
	W(0x50, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1) , /* 50 */
	W(0x60, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1) | /* 60 */
	W(0x70, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1) , /* 70 */
	W(0x80, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1) | /* 80 */
	W(0x90, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1) , /* 90 */
	W(0xa0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1) | /* a0 */
	W(0xb0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1) , /* b0 */
	W(0xc0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1) | /* c0 */
	W(0xd0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1) , /* d0 */
	W(0xe0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1) | /* e0 */
	W(0xf0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1)   /* f0 */
	/*      ----------------------------------------------         */
	/*      0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f         */
};
#undef W



static bool is_prefix_bad(struct insn *insn)
{
	insn_byte_t p;
	int i;

	for_each_insn_prefix(insn, i, p) {
		insn_attr_t attr;

		attr = inat_get_opcode_attribute(p);
		switch (attr) {
		case INAT_MAKE_PREFIX(INAT_PFX_ES):
		case INAT_MAKE_PREFIX(INAT_PFX_CS):
		case INAT_MAKE_PREFIX(INAT_PFX_DS):
		case INAT_MAKE_PREFIX(INAT_PFX_SS):
		case INAT_MAKE_PREFIX(INAT_PFX_LOCK):
			return true;
		}
	}
	return false;
}

static int uprobe_init_insn(struct arch_uprobe *auprobe, struct insn *insn, bool x86_64)
{
	enum insn_mode m = x86_64 ? INSN_MODE_64 : INSN_MODE_32;
	u32 volatile *good_insns;
	int ret;

	ret = insn_decode(insn, auprobe->insn, sizeof(auprobe->insn), m);
	if (ret < 0)
		return -ENOEXEC;

	if (is_prefix_bad(insn))
		return -ENOTSUPP;

	/* We should not singlestep on the exception masking instructions */
	if (insn_masking_exception(insn))
		return -ENOTSUPP;

	if (x86_64)
		good_insns = good_insns_64;
	else
		good_insns = good_insns_32;

	if (test_bit(OPCODE1(insn), (unsigned long *)good_insns))
		return 0;

	if (insn->opcode.nbytes == 2) {
		if (test_bit(OPCODE2(insn), (unsigned long *)good_2byte_insns))
			return 0;
	}

	return -ENOTSUPP;
}

#ifdef CONFIG_X86_64
static void riprel_analyze(struct arch_uprobe *auprobe, struct insn *insn)
{
	u8 *cursor;
	u8 reg;
	u8 reg2;

	if (!insn_rip_relative(insn))
		return;

	/*
	if (insn->rex_prefix.nbytes) {
		cursor = auprobe->insn + insn_offset_rex_prefix(insn);
		/* REX byte has 0100wrxb layout, clearing REX.b bit */
		*cursor &= 0xfe;
	}
	/*
	if (insn->vex_prefix.nbytes >= 3) {
		/*
		cursor = auprobe->insn + insn_offset_vex_prefix(insn) + 1;
		*cursor |= 0x60;
	}

	/*

	reg = MODRM_REG(insn);	/* Fetch modrm.reg */
	reg2 = 0xff;		/* Fetch vex.vvvv */
	if (insn->vex_prefix.nbytes)
		reg2 = insn->vex_prefix.bytes[2];
	/*
	reg2 = ((reg2 >> 3) & 0x7) ^ 0x7;
	/*
	if (reg != 6 && reg2 != 6) {
		reg2 = 6;
		auprobe->defparam.fixups |= UPROBE_FIX_RIP_SI;
	} else if (reg != 7 && reg2 != 7) {
		reg2 = 7;
		auprobe->defparam.fixups |= UPROBE_FIX_RIP_DI;
		/* TODO (paranoia): force maskmovq to not use di */
	} else {
		reg2 = 3;
		auprobe->defparam.fixups |= UPROBE_FIX_RIP_BX;
	}
	/*
	cursor = auprobe->insn + insn_offset_modrm(insn);
	/*
}

static inline unsigned long *
scratch_reg(struct arch_uprobe *auprobe, struct pt_regs *regs)
{
	if (auprobe->defparam.fixups & UPROBE_FIX_RIP_SI)
		return &regs->si;
	if (auprobe->defparam.fixups & UPROBE_FIX_RIP_DI)
		return &regs->di;
	return &regs->bx;
}

static void riprel_pre_xol(struct arch_uprobe *auprobe, struct pt_regs *regs)
{
	if (auprobe->defparam.fixups & UPROBE_FIX_RIP_MASK) {
		struct uprobe_task *utask = current->utask;
		unsigned long *sr = scratch_reg(auprobe, regs);

		utask->autask.saved_scratch_register = *sr;
		*sr = utask->vaddr + auprobe->defparam.ilen;
	}
}

static void riprel_post_xol(struct arch_uprobe *auprobe, struct pt_regs *regs)
{
	if (auprobe->defparam.fixups & UPROBE_FIX_RIP_MASK) {
		struct uprobe_task *utask = current->utask;
		unsigned long *sr = scratch_reg(auprobe, regs);

		*sr = utask->autask.saved_scratch_register;
	}
}
#else /* 32-bit: */
static void riprel_analyze(struct arch_uprobe *auprobe, struct insn *insn)
{
}
static void riprel_pre_xol(struct arch_uprobe *auprobe, struct pt_regs *regs)
{
}
static void riprel_post_xol(struct arch_uprobe *auprobe, struct pt_regs *regs)
{
}
#endif /* CONFIG_X86_64 */

struct uprobe_xol_ops {
	bool	(*emulate)(struct arch_uprobe *, struct pt_regs *);
	int	(*pre_xol)(struct arch_uprobe *, struct pt_regs *);
	int	(*post_xol)(struct arch_uprobe *, struct pt_regs *);
	void	(*abort)(struct arch_uprobe *, struct pt_regs *);
};

static inline int sizeof_long(struct pt_regs *regs)
{
	/*
	return user_64bit_mode(regs) ? 8 : 4;
}

static int default_pre_xol_op(struct arch_uprobe *auprobe, struct pt_regs *regs)
{
	riprel_pre_xol(auprobe, regs);
	return 0;
}

static int emulate_push_stack(struct pt_regs *regs, unsigned long val)
{
	unsigned long new_sp = regs->sp - sizeof_long(regs);

	if (copy_to_user((void __user *)new_sp, &val, sizeof_long(regs)))
		return -EFAULT;

	regs->sp = new_sp;
	return 0;
}

static int default_post_xol_op(struct arch_uprobe *auprobe, struct pt_regs *regs)
{
	struct uprobe_task *utask = current->utask;

	riprel_post_xol(auprobe, regs);
	if (auprobe->defparam.fixups & UPROBE_FIX_IP) {
		long correction = utask->vaddr - utask->xol_vaddr;
		regs->ip += correction;
	} else if (auprobe->defparam.fixups & UPROBE_FIX_CALL) {
		regs->sp += sizeof_long(regs); /* Pop incorrect return address */
		if (emulate_push_stack(regs, utask->vaddr + auprobe->defparam.ilen))
			return -ERESTART;
	}
	/* popf; tell the caller to not touch TF */
	if (auprobe->defparam.fixups & UPROBE_FIX_SETF)
		utask->autask.saved_tf = true;

	return 0;
}

static void default_abort_op(struct arch_uprobe *auprobe, struct pt_regs *regs)
{
	riprel_post_xol(auprobe, regs);
}

static const struct uprobe_xol_ops default_xol_ops = {
	.pre_xol  = default_pre_xol_op,
	.post_xol = default_post_xol_op,
	.abort	  = default_abort_op,
};

static bool branch_is_call(struct arch_uprobe *auprobe)
{
	return auprobe->branch.opc1 == 0xe8;
}

#define CASE_COND					\
	COND(70, 71, XF(OF))				\
	COND(72, 73, XF(CF))				\
	COND(74, 75, XF(ZF))				\
	COND(78, 79, XF(SF))				\
	COND(7a, 7b, XF(PF))				\
	COND(76, 77, XF(CF) || XF(ZF))			\
	COND(7c, 7d, XF(SF) != XF(OF))			\
	COND(7e, 7f, XF(ZF) || XF(SF) != XF(OF))

#define COND(op_y, op_n, expr)				\
	case 0x ## op_y: DO((expr) != 0)		\
	case 0x ## op_n: DO((expr) == 0)

#define XF(xf)	(!!(flags & X86_EFLAGS_ ## xf))

static bool is_cond_jmp_opcode(u8 opcode)
{
	switch (opcode) {
	#define DO(expr)	\
		return true;
	CASE_COND
	#undef	DO

	default:
		return false;
	}
}

static bool check_jmp_cond(struct arch_uprobe *auprobe, struct pt_regs *regs)
{
	unsigned long flags = regs->flags;

	switch (auprobe->branch.opc1) {
	#define DO(expr)	\
		return expr;
	CASE_COND
	#undef	DO

	default:	/* not a conditional jmp */
		return true;
	}
}

#undef	XF
#undef	COND
#undef	CASE_COND

static bool branch_emulate_op(struct arch_uprobe *auprobe, struct pt_regs *regs)
{
	unsigned long new_ip = regs->ip += auprobe->branch.ilen;
	unsigned long offs = (long)auprobe->branch.offs;

	if (branch_is_call(auprobe)) {
		/*
		if (emulate_push_stack(regs, new_ip))
			return false;
	} else if (!check_jmp_cond(auprobe, regs)) {
		offs = 0;
	}

	regs->ip = new_ip + offs;
	return true;
}

static bool push_emulate_op(struct arch_uprobe *auprobe, struct pt_regs *regs)
{
	unsigned long *src_ptr = (void *)regs + auprobe->push.reg_offset;

	if (emulate_push_stack(regs, *src_ptr))
		return false;
	regs->ip += auprobe->push.ilen;
	return true;
}

static int branch_post_xol_op(struct arch_uprobe *auprobe, struct pt_regs *regs)
{
	BUG_ON(!branch_is_call(auprobe));
	/*
	regs->sp += sizeof_long(regs);
	return -ERESTART;
}

static void branch_clear_offset(struct arch_uprobe *auprobe, struct insn *insn)
{
	/*
	memset(auprobe->insn + insn_offset_immediate(insn),
		0, insn->immediate.nbytes);
}

static const struct uprobe_xol_ops branch_xol_ops = {
	.emulate  = branch_emulate_op,
	.post_xol = branch_post_xol_op,
};

static const struct uprobe_xol_ops push_xol_ops = {
	.emulate  = push_emulate_op,
};

static int branch_setup_xol_ops(struct arch_uprobe *auprobe, struct insn *insn)
{
	u8 opc1 = OPCODE1(insn);
	insn_byte_t p;
	int i;

	switch (opc1) {
	case 0xeb:	/* jmp 8 */
	case 0xe9:	/* jmp 32 */
	case 0x90:	/* prefix* + nop; same as jmp with .offs = 0 */
		break;

	case 0xe8:	/* call relative */
		branch_clear_offset(auprobe, insn);
		break;

	case 0x0f:
		if (insn->opcode.nbytes != 2)
			return -ENOSYS;
		/*
		opc1 = OPCODE2(insn) - 0x10;
		fallthrough;
	default:
		if (!is_cond_jmp_opcode(opc1))
			return -ENOSYS;
	}

	/*
	for_each_insn_prefix(insn, i, p) {
		if (p == 0x66)
			return -ENOTSUPP;
	}

	auprobe->branch.opc1 = opc1;
	auprobe->branch.ilen = insn->length;
	auprobe->branch.offs = insn->immediate.value;

	auprobe->ops = &branch_xol_ops;
	return 0;
}

static int push_setup_xol_ops(struct arch_uprobe *auprobe, struct insn *insn)
{
	u8 opc1 = OPCODE1(insn), reg_offset = 0;

	if (opc1 < 0x50 || opc1 > 0x57)
		return -ENOSYS;

	if (insn->length > 2)
		return -ENOSYS;
	if (insn->length == 2) {
		/* only support rex_prefix 0x41 (x64 only) */
#ifdef CONFIG_X86_64
		if (insn->rex_prefix.nbytes != 1 ||
		    insn->rex_prefix.bytes[0] != 0x41)
			return -ENOSYS;

		switch (opc1) {
		case 0x50:
			reg_offset = offsetof(struct pt_regs, r8);
			break;
		case 0x51:
			reg_offset = offsetof(struct pt_regs, r9);
			break;
		case 0x52:
			reg_offset = offsetof(struct pt_regs, r10);
			break;
		case 0x53:
			reg_offset = offsetof(struct pt_regs, r11);
			break;
		case 0x54:
			reg_offset = offsetof(struct pt_regs, r12);
			break;
		case 0x55:
			reg_offset = offsetof(struct pt_regs, r13);
			break;
		case 0x56:
			reg_offset = offsetof(struct pt_regs, r14);
			break;
		case 0x57:
			reg_offset = offsetof(struct pt_regs, r15);
			break;
		}
#else
		return -ENOSYS;
#endif
	} else {
		switch (opc1) {
		case 0x50:
			reg_offset = offsetof(struct pt_regs, ax);
			break;
		case 0x51:
			reg_offset = offsetof(struct pt_regs, cx);
			break;
		case 0x52:
			reg_offset = offsetof(struct pt_regs, dx);
			break;
		case 0x53:
			reg_offset = offsetof(struct pt_regs, bx);
			break;
		case 0x54:
			reg_offset = offsetof(struct pt_regs, sp);
			break;
		case 0x55:
			reg_offset = offsetof(struct pt_regs, bp);
			break;
		case 0x56:
			reg_offset = offsetof(struct pt_regs, si);
			break;
		case 0x57:
			reg_offset = offsetof(struct pt_regs, di);
			break;
		}
	}

	auprobe->push.reg_offset = reg_offset;
	auprobe->push.ilen = insn->length;
	auprobe->ops = &push_xol_ops;
	return 0;
}

int arch_uprobe_analyze_insn(struct arch_uprobe *auprobe, struct mm_struct *mm, unsigned long addr)
{
	struct insn insn;
	u8 fix_ip_or_call = UPROBE_FIX_IP;
	int ret;

	ret = uprobe_init_insn(auprobe, &insn, is_64bit_mm(mm));
	if (ret)
		return ret;

	ret = branch_setup_xol_ops(auprobe, &insn);
	if (ret != -ENOSYS)
		return ret;

	ret = push_setup_xol_ops(auprobe, &insn);
	if (ret != -ENOSYS)
		return ret;

	/*
	switch (OPCODE1(&insn)) {
	case 0x9d:		/* popf */
		auprobe->defparam.fixups |= UPROBE_FIX_SETF;
		break;
	case 0xc3:		/* ret or lret -- ip is correct */
	case 0xcb:
	case 0xc2:
	case 0xca:
	case 0xea:		/* jmp absolute -- ip is correct */
		fix_ip_or_call = 0;
		break;
	case 0x9a:		/* call absolute - Fix return addr, not ip */
		fix_ip_or_call = UPROBE_FIX_CALL;
		break;
	case 0xff:
		switch (MODRM_REG(&insn)) {
		case 2: case 3:			/* call or lcall, indirect */
			fix_ip_or_call = UPROBE_FIX_CALL;
			break;
		case 4: case 5:			/* jmp or ljmp, indirect */
			fix_ip_or_call = 0;
			break;
		}
		fallthrough;
	default:
		riprel_analyze(auprobe, &insn);
	}

	auprobe->defparam.ilen = insn.length;
	auprobe->defparam.fixups |= fix_ip_or_call;

	auprobe->ops = &default_xol_ops;
	return 0;
}

int arch_uprobe_pre_xol(struct arch_uprobe *auprobe, struct pt_regs *regs)
{
	struct uprobe_task *utask = current->utask;

	if (auprobe->ops->pre_xol) {
		int err = auprobe->ops->pre_xol(auprobe, regs);
		if (err)
			return err;
	}

	regs->ip = utask->xol_vaddr;
	utask->autask.saved_trap_nr = current->thread.trap_nr;
	current->thread.trap_nr = UPROBE_TRAP_NR;

	utask->autask.saved_tf = !!(regs->flags & X86_EFLAGS_TF);
	regs->flags |= X86_EFLAGS_TF;
	if (test_tsk_thread_flag(current, TIF_BLOCKSTEP))
		set_task_blockstep(current, false);

	return 0;
}

bool arch_uprobe_xol_was_trapped(struct task_struct *t)
{
	if (t->thread.trap_nr != UPROBE_TRAP_NR)
		return true;

	return false;
}

int arch_uprobe_post_xol(struct arch_uprobe *auprobe, struct pt_regs *regs)
{
	struct uprobe_task *utask = current->utask;
	bool send_sigtrap = utask->autask.saved_tf;
	int err = 0;

	WARN_ON_ONCE(current->thread.trap_nr != UPROBE_TRAP_NR);
	current->thread.trap_nr = utask->autask.saved_trap_nr;

	if (auprobe->ops->post_xol) {
		err = auprobe->ops->post_xol(auprobe, regs);
		if (err) {
			/*
			regs->ip = utask->vaddr;
			if (err == -ERESTART)
				err = 0;
			send_sigtrap = false;
		}
	}
	/*
	if (send_sigtrap)
		send_sig(SIGTRAP, current, 0);

	if (!utask->autask.saved_tf)
		regs->flags &= ~X86_EFLAGS_TF;

	return err;
}

int arch_uprobe_exception_notify(struct notifier_block *self, unsigned long val, void *data)
{
	struct die_args *args = data;
	struct pt_regs *regs = args->regs;
	int ret = NOTIFY_DONE;

	/* We are only interested in userspace traps */
	if (regs && !user_mode(regs))
		return NOTIFY_DONE;

	switch (val) {
	case DIE_INT3:
		if (uprobe_pre_sstep_notifier(regs))
			ret = NOTIFY_STOP;

		break;

	case DIE_DEBUG:
		if (uprobe_post_sstep_notifier(regs))
			ret = NOTIFY_STOP;

		break;

	default:
		break;
	}

	return ret;
}

void arch_uprobe_abort_xol(struct arch_uprobe *auprobe, struct pt_regs *regs)
{
	struct uprobe_task *utask = current->utask;

	if (auprobe->ops->abort)
		auprobe->ops->abort(auprobe, regs);

	current->thread.trap_nr = utask->autask.saved_trap_nr;
	regs->ip = utask->vaddr;
	/* clear TF if it was set by us in arch_uprobe_pre_xol() */
	if (!utask->autask.saved_tf)
		regs->flags &= ~X86_EFLAGS_TF;
}

static bool __skip_sstep(struct arch_uprobe *auprobe, struct pt_regs *regs)
{
	if (auprobe->ops->emulate)
		return auprobe->ops->emulate(auprobe, regs);
	return false;
}

bool arch_uprobe_skip_sstep(struct arch_uprobe *auprobe, struct pt_regs *regs)
{
	bool ret = __skip_sstep(auprobe, regs);
	if (ret && (regs->flags & X86_EFLAGS_TF))
		send_sig(SIGTRAP, current, 0);
	return ret;
}

unsigned long
arch_uretprobe_hijack_return_addr(unsigned long trampoline_vaddr, struct pt_regs *regs)
{
	int rasize = sizeof_long(regs), nleft;
	unsigned long orig_ret_vaddr = 0; /* clear high bits for 32-bit apps */

	if (copy_from_user(&orig_ret_vaddr, (void __user *)regs->sp, rasize))
		return -1;

	/* check whether address has been already hijacked */
	if (orig_ret_vaddr == trampoline_vaddr)
		return orig_ret_vaddr;

	nleft = copy_to_user((void __user *)regs->sp, &trampoline_vaddr, rasize);
	if (likely(!nleft))
		return orig_ret_vaddr;

	if (nleft != rasize) {
		pr_err("return address clobbered: pid=%d, %%sp=%#lx, %%ip=%#lx\n",
		       current->pid, regs->sp, regs->ip);

		force_sig(SIGSEGV);
	}

	return -1;
}

bool arch_uretprobe_is_alive(struct return_instance *ret, enum rp_check ctx,
				struct pt_regs *regs)
{
	if (ctx == RP_CHECK_CALL) /* sp was just decremented by "call" insn */
		return regs->sp < ret->stack;
	else
		return regs->sp <= ret->stack;
}
