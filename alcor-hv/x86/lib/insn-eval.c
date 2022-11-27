#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/ratelimit.h>
#include <linux/mmu_context.h>
#include <asm/desc_defs.h>
#include <asm/desc.h>
#include <asm/inat.h>
#include <asm/insn.h>
#include <asm/insn-eval.h>
#include <asm/ldt.h>
#include <asm/vm86.h>

#undef pr_fmt
#define pr_fmt(fmt) "insn: " fmt

enum reg_type {
	REG_TYPE_RM = 0,
	REG_TYPE_REG,
	REG_TYPE_INDEX,
	REG_TYPE_BASE,
};

static bool is_string_insn(struct insn *insn)
{
	/* All string instructions have a 1-byte opcode. */
	if (insn->opcode.nbytes != 1)
		return false;

	switch (insn->opcode.bytes[0]) {
	case 0x6c ... 0x6f:	/* INS, OUTS */
	case 0xa4 ... 0xa7:	/* MOVS, CMPS */
	case 0xaa ... 0xaf:	/* STOS, LODS, SCAS */
		return true;
	default:
		return false;
	}
}

bool insn_has_rep_prefix(struct insn *insn)
{
	insn_byte_t p;
	int i;

	insn_get_prefixes(insn);

	for_each_insn_prefix(insn, i, p) {
		if (p == 0xf2 || p == 0xf3)
			return true;
	}

	return false;
}

static int get_seg_reg_override_idx(struct insn *insn)
{
	int idx = INAT_SEG_REG_DEFAULT;
	int num_overrides = 0, i;
	insn_byte_t p;

	insn_get_prefixes(insn);

	/* Look for any segment override prefixes. */
	for_each_insn_prefix(insn, i, p) {
		insn_attr_t attr;

		attr = inat_get_opcode_attribute(p);
		switch (attr) {
		case INAT_MAKE_PREFIX(INAT_PFX_CS):
			idx = INAT_SEG_REG_CS;
			num_overrides++;
			break;
		case INAT_MAKE_PREFIX(INAT_PFX_SS):
			idx = INAT_SEG_REG_SS;
			num_overrides++;
			break;
		case INAT_MAKE_PREFIX(INAT_PFX_DS):
			idx = INAT_SEG_REG_DS;
			num_overrides++;
			break;
		case INAT_MAKE_PREFIX(INAT_PFX_ES):
			idx = INAT_SEG_REG_ES;
			num_overrides++;
			break;
		case INAT_MAKE_PREFIX(INAT_PFX_FS):
			idx = INAT_SEG_REG_FS;
			num_overrides++;
			break;
		case INAT_MAKE_PREFIX(INAT_PFX_GS):
			idx = INAT_SEG_REG_GS;
			num_overrides++;
			break;
		/* No default action needed. */
		}
	}

	/* More than one segment override prefix leads to undefined behavior. */
	if (num_overrides > 1)
		return -EINVAL;

	return idx;
}

static bool check_seg_overrides(struct insn *insn, int regoff)
{
	if (regoff == offsetof(struct pt_regs, di) && is_string_insn(insn))
		return false;

	return true;
}

static int resolve_default_seg(struct insn *insn, struct pt_regs *regs, int off)
{
	if (any_64bit_mode(regs))
		return INAT_SEG_REG_IGNORE;
	/*

	switch (off) {
	case offsetof(struct pt_regs, ax):
	case offsetof(struct pt_regs, cx):
	case offsetof(struct pt_regs, dx):
		/* Need insn to verify address size. */
		if (insn->addr_bytes == 2)
			return -EINVAL;

		fallthrough;

	case -EDOM:
	case offsetof(struct pt_regs, bx):
	case offsetof(struct pt_regs, si):
		return INAT_SEG_REG_DS;

	case offsetof(struct pt_regs, di):
		if (is_string_insn(insn))
			return INAT_SEG_REG_ES;
		return INAT_SEG_REG_DS;

	case offsetof(struct pt_regs, bp):
	case offsetof(struct pt_regs, sp):
		return INAT_SEG_REG_SS;

	case offsetof(struct pt_regs, ip):
		return INAT_SEG_REG_CS;

	default:
		return -EINVAL;
	}
}

static int resolve_seg_reg(struct insn *insn, struct pt_regs *regs, int regoff)
{
	int idx;

	/*
	if (regoff == offsetof(struct pt_regs, ip)) {
		if (any_64bit_mode(regs))
			return INAT_SEG_REG_IGNORE;
		else
			return INAT_SEG_REG_CS;
	}

	if (!insn)
		return -EINVAL;

	if (!check_seg_overrides(insn, regoff))
		return resolve_default_seg(insn, regs, regoff);

	idx = get_seg_reg_override_idx(insn);
	if (idx < 0)
		return idx;

	if (idx == INAT_SEG_REG_DEFAULT)
		return resolve_default_seg(insn, regs, regoff);

	/*
	if (any_64bit_mode(regs)) {
		if (idx != INAT_SEG_REG_FS &&
		    idx != INAT_SEG_REG_GS)
			idx = INAT_SEG_REG_IGNORE;
	}

	return idx;
}

static short get_segment_selector(struct pt_regs *regs, int seg_reg_idx)
{
	unsigned short sel;

#ifdef CONFIG_X86_64
	switch (seg_reg_idx) {
	case INAT_SEG_REG_IGNORE:
		return 0;
	case INAT_SEG_REG_CS:
		return (unsigned short)(regs->cs & 0xffff);
	case INAT_SEG_REG_SS:
		return (unsigned short)(regs->ss & 0xffff);
	case INAT_SEG_REG_DS:
		savesegment(ds, sel);
		return sel;
	case INAT_SEG_REG_ES:
		savesegment(es, sel);
		return sel;
	case INAT_SEG_REG_FS:
		savesegment(fs, sel);
		return sel;
	case INAT_SEG_REG_GS:
		savesegment(gs, sel);
		return sel;
	default:
		return -EINVAL;
	}
#else /* CONFIG_X86_32 */
	struct kernel_vm86_regs *vm86regs = (struct kernel_vm86_regs *)regs;

	if (v8086_mode(regs)) {
		switch (seg_reg_idx) {
		case INAT_SEG_REG_CS:
			return (unsigned short)(regs->cs & 0xffff);
		case INAT_SEG_REG_SS:
			return (unsigned short)(regs->ss & 0xffff);
		case INAT_SEG_REG_DS:
			return vm86regs->ds;
		case INAT_SEG_REG_ES:
			return vm86regs->es;
		case INAT_SEG_REG_FS:
			return vm86regs->fs;
		case INAT_SEG_REG_GS:
			return vm86regs->gs;
		case INAT_SEG_REG_IGNORE:
		default:
			return -EINVAL;
		}
	}

	switch (seg_reg_idx) {
	case INAT_SEG_REG_CS:
		return (unsigned short)(regs->cs & 0xffff);
	case INAT_SEG_REG_SS:
		return (unsigned short)(regs->ss & 0xffff);
	case INAT_SEG_REG_DS:
		return (unsigned short)(regs->ds & 0xffff);
	case INAT_SEG_REG_ES:
		return (unsigned short)(regs->es & 0xffff);
	case INAT_SEG_REG_FS:
		return (unsigned short)(regs->fs & 0xffff);
	case INAT_SEG_REG_GS:
		savesegment(gs, sel);
		return sel;
	case INAT_SEG_REG_IGNORE:
	default:
		return -EINVAL;
	}
#endif /* CONFIG_X86_64 */
}

static const int pt_regoff[] = {
	offsetof(struct pt_regs, ax),
	offsetof(struct pt_regs, cx),
	offsetof(struct pt_regs, dx),
	offsetof(struct pt_regs, bx),
	offsetof(struct pt_regs, sp),
	offsetof(struct pt_regs, bp),
	offsetof(struct pt_regs, si),
	offsetof(struct pt_regs, di),
#ifdef CONFIG_X86_64
	offsetof(struct pt_regs, r8),
	offsetof(struct pt_regs, r9),
	offsetof(struct pt_regs, r10),
	offsetof(struct pt_regs, r11),
	offsetof(struct pt_regs, r12),
	offsetof(struct pt_regs, r13),
	offsetof(struct pt_regs, r14),
	offsetof(struct pt_regs, r15),
#else
	offsetof(struct pt_regs, ds),
	offsetof(struct pt_regs, es),
	offsetof(struct pt_regs, fs),
	offsetof(struct pt_regs, gs),
#endif
};

int pt_regs_offset(struct pt_regs *regs, int regno)
{
	if ((unsigned)regno < ARRAY_SIZE(pt_regoff))
		return pt_regoff[regno];
	return -EDOM;
}

static int get_regno(struct insn *insn, enum reg_type type)
{
	int nr_registers = ARRAY_SIZE(pt_regoff);
	int regno = 0;

	/*
	if (IS_ENABLED(CONFIG_X86_64) && !insn->x86_64)
		nr_registers -= 8;

	switch (type) {
	case REG_TYPE_RM:
		regno = X86_MODRM_RM(insn->modrm.value);

		/*
		if (!X86_MODRM_MOD(insn->modrm.value) && regno == 5)
			return -EDOM;

		if (X86_REX_B(insn->rex_prefix.value))
			regno += 8;
		break;

	case REG_TYPE_REG:
		regno = X86_MODRM_REG(insn->modrm.value);

		if (X86_REX_R(insn->rex_prefix.value))
			regno += 8;
		break;

	case REG_TYPE_INDEX:
		regno = X86_SIB_INDEX(insn->sib.value);
		if (X86_REX_X(insn->rex_prefix.value))
			regno += 8;

		/*
		if (X86_MODRM_MOD(insn->modrm.value) != 3 && regno == 4)
			return -EDOM;
		break;

	case REG_TYPE_BASE:
		regno = X86_SIB_BASE(insn->sib.value);
		/*
		if (!X86_MODRM_MOD(insn->modrm.value) && regno == 5)
			return -EDOM;

		if (X86_REX_B(insn->rex_prefix.value))
			regno += 8;
		break;

	default:
		pr_err_ratelimited("invalid register type: %d\n", type);
		return -EINVAL;
	}

	if (regno >= nr_registers) {
		WARN_ONCE(1, "decoded an instruction with an invalid register");
		return -EINVAL;
	}
	return regno;
}

static int get_reg_offset(struct insn *insn, struct pt_regs *regs,
			  enum reg_type type)
{
	int regno = get_regno(insn, type);

	if (regno < 0)
		return regno;

	return pt_regs_offset(regs, regno);
}

static int get_reg_offset_16(struct insn *insn, struct pt_regs *regs,
			     int *offs1, int *offs2)
{
	/*
	static const int regoff1[] = {
		offsetof(struct pt_regs, bx),
		offsetof(struct pt_regs, bx),
		offsetof(struct pt_regs, bp),
		offsetof(struct pt_regs, bp),
		offsetof(struct pt_regs, si),
		offsetof(struct pt_regs, di),
		offsetof(struct pt_regs, bp),
		offsetof(struct pt_regs, bx),
	};

	static const int regoff2[] = {
		offsetof(struct pt_regs, si),
		offsetof(struct pt_regs, di),
		offsetof(struct pt_regs, si),
		offsetof(struct pt_regs, di),
		-EDOM,
		-EDOM,
		-EDOM,
		-EDOM,
	};

	if (!offs1 || !offs2)
		return -EINVAL;

	/* Operand is a register, use the generic function. */
	if (X86_MODRM_MOD(insn->modrm.value) == 3) {
		*offs1 = insn_get_modrm_rm_off(insn, regs);
		*offs2 = -EDOM;
		return 0;
	}


	/*
	if ((X86_MODRM_MOD(insn->modrm.value) == 0) &&
	    (X86_MODRM_RM(insn->modrm.value) == 6))
		*offs1 = -EDOM;

	return 0;
}

static bool get_desc(struct desc_struct *out, unsigned short sel)
{
	struct desc_ptr gdt_desc = {0, 0};
	unsigned long desc_base;

#ifdef CONFIG_MODIFY_LDT_SYSCALL
	if ((sel & SEGMENT_TI_MASK) == SEGMENT_LDT) {
		bool success = false;
		struct ldt_struct *ldt;

		/* Bits [15:3] contain the index of the desired entry. */
		sel >>= 3;

		mutex_lock(&current->active_mm->context.lock);
		ldt = current->active_mm->context.ldt;
		if (ldt && sel < ldt->nr_entries) {
			*out = ldt->entries[sel];
			success = true;
		}

		mutex_unlock(&current->active_mm->context.lock);

		return success;
	}
#endif
	native_store_gdt(&gdt_desc);

	/*
	desc_base = sel & ~(SEGMENT_RPL_MASK | SEGMENT_TI_MASK);

	if (desc_base > gdt_desc.size)
		return false;

	return true;
}

unsigned long insn_get_seg_base(struct pt_regs *regs, int seg_reg_idx)
{
	struct desc_struct desc;
	short sel;

	sel = get_segment_selector(regs, seg_reg_idx);
	if (sel < 0)
		return -1L;

	if (v8086_mode(regs))
		/*
		return (unsigned long)(sel << 4);

	if (any_64bit_mode(regs)) {
		/*
		unsigned long base;

		if (seg_reg_idx == INAT_SEG_REG_FS) {
			rdmsrl(MSR_FS_BASE, base);
		} else if (seg_reg_idx == INAT_SEG_REG_GS) {
			/*
			if (user_mode(regs))
				rdmsrl(MSR_KERNEL_GS_BASE, base);
			else
				rdmsrl(MSR_GS_BASE, base);
		} else {
			base = 0;
		}
		return base;
	}

	/* In protected mode the segment selector cannot be null. */
	if (!sel)
		return -1L;

	if (!get_desc(&desc, sel))
		return -1L;

	return get_desc_base(&desc);
}

static unsigned long get_seg_limit(struct pt_regs *regs, int seg_reg_idx)
{
	struct desc_struct desc;
	unsigned long limit;
	short sel;

	sel = get_segment_selector(regs, seg_reg_idx);
	if (sel < 0)
		return 0;

	if (any_64bit_mode(regs) || v8086_mode(regs))
		return -1L;

	if (!sel)
		return 0;

	if (!get_desc(&desc, sel))
		return 0;

	/*
	limit = get_desc_limit(&desc);
	if (desc.g)
		limit = (limit << 12) + 0xfff;

	return limit;
}

int insn_get_code_seg_params(struct pt_regs *regs)
{
	struct desc_struct desc;
	short sel;

	if (v8086_mode(regs))
		/* Address and operand size are both 16-bit. */
		return INSN_CODE_SEG_PARAMS(2, 2);

	sel = get_segment_selector(regs, INAT_SEG_REG_CS);
	if (sel < 0)
		return sel;

	if (!get_desc(&desc, sel))
		return -EINVAL;

	/*
	if (!(desc.type & BIT(3)))
		return -EINVAL;

	switch ((desc.l << 1) | desc.d) {
	case 0: /*
		return INSN_CODE_SEG_PARAMS(2, 2);
	case 1: /*
		return INSN_CODE_SEG_PARAMS(4, 4);
	case 2: /*
		return INSN_CODE_SEG_PARAMS(4, 8);
	case 3: /* Invalid setting. CS.L=1, CS.D=1 */
		fallthrough;
	default:
		return -EINVAL;
	}
}

int insn_get_modrm_rm_off(struct insn *insn, struct pt_regs *regs)
{
	return get_reg_offset(insn, regs, REG_TYPE_RM);
}

int insn_get_modrm_reg_off(struct insn *insn, struct pt_regs *regs)
{
	return get_reg_offset(insn, regs, REG_TYPE_REG);
}

unsigned long *insn_get_modrm_reg_ptr(struct insn *insn, struct pt_regs *regs)
{
	int offset;

	offset = insn_get_modrm_reg_off(insn, regs);
	if (offset < 0)
		return NULL;
	return (void *)regs + offset;
}

static int get_seg_base_limit(struct insn *insn, struct pt_regs *regs,
			      int regoff, unsigned long *base,
			      unsigned long *limit)
{
	int seg_reg_idx;

	if (!base)
		return -EINVAL;

	seg_reg_idx = resolve_seg_reg(insn, regs, regoff);
	if (seg_reg_idx < 0)
		return seg_reg_idx;

	if (*base == -1L)
		return -EINVAL;

	if (!limit)
		return 0;

	if (!(*limit))
		return -EINVAL;

	return 0;
}

static int get_eff_addr_reg(struct insn *insn, struct pt_regs *regs,
			    int *regoff, long *eff_addr)
{
	int ret;

	ret = insn_get_modrm(insn);
	if (ret)
		return ret;

	if (X86_MODRM_MOD(insn->modrm.value) != 3)
		return -EINVAL;

	if (*regoff < 0)
		return -EINVAL;

	/* Ignore bytes that are outside the address size. */
	if (insn->addr_bytes == 2)
		*eff_addr = regs_get_register(regs, *regoff) & 0xffff;
	else if (insn->addr_bytes == 4)
		*eff_addr = regs_get_register(regs, *regoff) & 0xffffffff;
	else /* 64-bit address */
		*eff_addr = regs_get_register(regs, *regoff);

	return 0;
}

static int get_eff_addr_modrm(struct insn *insn, struct pt_regs *regs,
			      int *regoff, long *eff_addr)
{
	long tmp;
	int ret;

	if (insn->addr_bytes != 8 && insn->addr_bytes != 4)
		return -EINVAL;

	ret = insn_get_modrm(insn);
	if (ret)
		return ret;

	if (X86_MODRM_MOD(insn->modrm.value) > 2)
		return -EINVAL;


	/*
	if (*regoff == -EDOM) {
		if (any_64bit_mode(regs))
			tmp = regs->ip + insn->length;
		else
			tmp = 0;
	} else if (*regoff < 0) {
		return -EINVAL;
	} else {
		tmp = regs_get_register(regs, *regoff);
	}

	if (insn->addr_bytes == 4) {
		int addr32 = (int)(tmp & 0xffffffff) + insn->displacement.value;

		*eff_addr = addr32 & 0xffffffff;
	} else {
		*eff_addr = tmp + insn->displacement.value;
	}

	return 0;
}

static int get_eff_addr_modrm_16(struct insn *insn, struct pt_regs *regs,
				 int *regoff, short *eff_addr)
{
	int addr_offset1, addr_offset2, ret;
	short addr1 = 0, addr2 = 0, displacement;

	if (insn->addr_bytes != 2)
		return -EINVAL;

	insn_get_modrm(insn);

	if (!insn->modrm.nbytes)
		return -EINVAL;

	if (X86_MODRM_MOD(insn->modrm.value) > 2)
		return -EINVAL;

	ret = get_reg_offset_16(insn, regs, &addr_offset1, &addr_offset2);
	if (ret < 0)
		return -EINVAL;

	/*
	if (addr_offset1 != -EDOM)
		addr1 = regs_get_register(regs, addr_offset1) & 0xffff;

	if (addr_offset2 != -EDOM)
		addr2 = regs_get_register(regs, addr_offset2) & 0xffff;

	displacement = insn->displacement.value & 0xffff;

	/*

	return 0;
}

static int get_eff_addr_sib(struct insn *insn, struct pt_regs *regs,
			    int *base_offset, long *eff_addr)
{
	long base, indx;
	int indx_offset;
	int ret;

	if (insn->addr_bytes != 8 && insn->addr_bytes != 4)
		return -EINVAL;

	ret = insn_get_modrm(insn);
	if (ret)
		return ret;

	if (!insn->modrm.nbytes)
		return -EINVAL;

	if (X86_MODRM_MOD(insn->modrm.value) > 2)
		return -EINVAL;

	ret = insn_get_sib(insn);
	if (ret)
		return ret;

	if (!insn->sib.nbytes)
		return -EINVAL;

	indx_offset = get_reg_offset(insn, regs, REG_TYPE_INDEX);

	/*
	if (*base_offset == -EDOM)
		base = 0;
	else if (*base_offset < 0)
		return -EINVAL;
	else
		base = regs_get_register(regs, *base_offset);

	if (indx_offset == -EDOM)
		indx = 0;
	else if (indx_offset < 0)
		return -EINVAL;
	else
		indx = regs_get_register(regs, indx_offset);

	if (insn->addr_bytes == 4) {
		int addr32, base32, idx32;

		base32 = base & 0xffffffff;
		idx32 = indx & 0xffffffff;

		addr32 = base32 + idx32 * (1 << X86_SIB_SCALE(insn->sib.value));
		addr32 += insn->displacement.value;

		*eff_addr = addr32 & 0xffffffff;
	} else {
		*eff_addr = base + indx * (1 << X86_SIB_SCALE(insn->sib.value));
		*eff_addr += insn->displacement.value;
	}

	return 0;
}

static void __user *get_addr_ref_16(struct insn *insn, struct pt_regs *regs)
{
	unsigned long linear_addr = -1L, seg_base, seg_limit;
	int ret, regoff;
	short eff_addr;
	long tmp;

	if (insn_get_displacement(insn))
		goto out;

	if (insn->addr_bytes != 2)
		goto out;

	if (X86_MODRM_MOD(insn->modrm.value) == 3) {
		ret = get_eff_addr_reg(insn, regs, &regoff, &tmp);
		if (ret)
			goto out;

		eff_addr = tmp;
	} else {
		ret = get_eff_addr_modrm_16(insn, regs, &regoff, &eff_addr);
		if (ret)
			goto out;
	}

	ret = get_seg_base_limit(insn, regs, regoff, &seg_base, &seg_limit);
	if (ret)
		goto out;

	/*
	if ((unsigned long)(eff_addr & 0xffff) > seg_limit)
		goto out;

	linear_addr = (unsigned long)(eff_addr & 0xffff) + seg_base;

	/* Limit linear address to 20 bits */
	if (v8086_mode(regs))
		linear_addr &= 0xfffff;

out:
	return (void __user *)linear_addr;
}

static void __user *get_addr_ref_32(struct insn *insn, struct pt_regs *regs)
{
	unsigned long linear_addr = -1L, seg_base, seg_limit;
	int eff_addr, regoff;
	long tmp;
	int ret;

	if (insn->addr_bytes != 4)
		goto out;

	if (X86_MODRM_MOD(insn->modrm.value) == 3) {
		ret = get_eff_addr_reg(insn, regs, &regoff, &tmp);
		if (ret)
			goto out;

		eff_addr = tmp;

	} else {
		if (insn->sib.nbytes) {
			ret = get_eff_addr_sib(insn, regs, &regoff, &tmp);
			if (ret)
				goto out;

			eff_addr = tmp;
		} else {
			ret = get_eff_addr_modrm(insn, regs, &regoff, &tmp);
			if (ret)
				goto out;

			eff_addr = tmp;
		}
	}

	ret = get_seg_base_limit(insn, regs, regoff, &seg_base, &seg_limit);
	if (ret)
		goto out;

	/*
	if (!any_64bit_mode(regs) && ((unsigned int)eff_addr > seg_limit))
		goto out;

	/*
	if (v8086_mode(regs) && (eff_addr & ~0xffff))
		goto out;

	/*
	linear_addr = (unsigned long)(eff_addr & 0xffffffff) + seg_base;

	/* Limit linear address to 20 bits */
	if (v8086_mode(regs))
		linear_addr &= 0xfffff;

out:
	return (void __user *)linear_addr;
}

#ifndef CONFIG_X86_64
static void __user *get_addr_ref_64(struct insn *insn, struct pt_regs *regs)
{
	return (void __user *)-1L;
}
#else
static void __user *get_addr_ref_64(struct insn *insn, struct pt_regs *regs)
{
	unsigned long linear_addr = -1L, seg_base;
	int regoff, ret;
	long eff_addr;

	if (insn->addr_bytes != 8)
		goto out;

	if (X86_MODRM_MOD(insn->modrm.value) == 3) {
		ret = get_eff_addr_reg(insn, regs, &regoff, &eff_addr);
		if (ret)
			goto out;

	} else {
		if (insn->sib.nbytes) {
			ret = get_eff_addr_sib(insn, regs, &regoff, &eff_addr);
			if (ret)
				goto out;
		} else {
			ret = get_eff_addr_modrm(insn, regs, &regoff, &eff_addr);
			if (ret)
				goto out;
		}

	}

	ret = get_seg_base_limit(insn, regs, regoff, &seg_base, NULL);
	if (ret)
		goto out;

	linear_addr = (unsigned long)eff_addr + seg_base;

out:
	return (void __user *)linear_addr;
}
#endif /* CONFIG_X86_64 */

void __user *insn_get_addr_ref(struct insn *insn, struct pt_regs *regs)
{
	if (!insn || !regs)
		return (void __user *)-1L;

	if (insn_get_opcode(insn))
		return (void __user *)-1L;

	switch (insn->addr_bytes) {
	case 2:
		return get_addr_ref_16(insn, regs);
	case 4:
		return get_addr_ref_32(insn, regs);
	case 8:
		return get_addr_ref_64(insn, regs);
	default:
		return (void __user *)-1L;
	}
}

int insn_get_effective_ip(struct pt_regs *regs, unsigned long *ip)
{
	unsigned long seg_base = 0;

	/*
	if (!user_64bit_mode(regs)) {
		seg_base = insn_get_seg_base(regs, INAT_SEG_REG_CS);
		if (seg_base == -1L)
			return -EINVAL;
	}


	return 0;
}

int insn_fetch_from_user(struct pt_regs *regs, unsigned char buf[MAX_INSN_SIZE])
{
	unsigned long ip;
	int not_copied;

	if (insn_get_effective_ip(regs, &ip))
		return -EINVAL;

	not_copied = copy_from_user(buf, (void __user *)ip, MAX_INSN_SIZE);

	return MAX_INSN_SIZE - not_copied;
}

int insn_fetch_from_user_inatomic(struct pt_regs *regs, unsigned char buf[MAX_INSN_SIZE])
{
	unsigned long ip;
	int not_copied;

	if (insn_get_effective_ip(regs, &ip))
		return -EINVAL;

	not_copied = __copy_from_user_inatomic(buf, (void __user *)ip, MAX_INSN_SIZE);

	return MAX_INSN_SIZE - not_copied;
}

bool insn_decode_from_regs(struct insn *insn, struct pt_regs *regs,
			   unsigned char buf[MAX_INSN_SIZE], int buf_size)
{
	int seg_defs;

	insn_init(insn, buf, buf_size, user_64bit_mode(regs));

	/*
	seg_defs = insn_get_code_seg_params(regs);
	if (seg_defs == -EINVAL)
		return false;

	insn->addr_bytes = INSN_CODE_SEG_ADDR_SZ(seg_defs);
	insn->opnd_bytes = INSN_CODE_SEG_OPND_SZ(seg_defs);

	if (insn_get_length(insn))
		return false;

	if (buf_size < insn->length)
		return false;

	return true;
}

enum mmio_type insn_decode_mmio(struct insn *insn, int *bytes)
{
	enum mmio_type type = MMIO_DECODE_FAILED;


	if (insn_get_opcode(insn))
		return MMIO_DECODE_FAILED;

	switch (insn->opcode.bytes[0]) {
	case 0x88: /* MOV m8,r8 */
		*bytes = 1;
		fallthrough;
	case 0x89: /* MOV m16/m32/m64, r16/m32/m64 */
		if (!*bytes)
			*bytes = insn->opnd_bytes;
		type = MMIO_WRITE;
		break;

	case 0xc6: /* MOV m8, imm8 */
		*bytes = 1;
		fallthrough;
	case 0xc7: /* MOV m16/m32/m64, imm16/imm32/imm64 */
		if (!*bytes)
			*bytes = insn->opnd_bytes;
		type = MMIO_WRITE_IMM;
		break;

	case 0x8a: /* MOV r8, m8 */
		*bytes = 1;
		fallthrough;
	case 0x8b: /* MOV r16/r32/r64, m16/m32/m64 */
		if (!*bytes)
			*bytes = insn->opnd_bytes;
		type = MMIO_READ;
		break;

	case 0xa4: /* MOVS m8, m8 */
		*bytes = 1;
		fallthrough;
	case 0xa5: /* MOVS m16/m32/m64, m16/m32/m64 */
		if (!*bytes)
			*bytes = insn->opnd_bytes;
		type = MMIO_MOVS;
		break;

	case 0x0f: /* Two-byte instruction */
		switch (insn->opcode.bytes[1]) {
		case 0xb6: /* MOVZX r16/r32/r64, m8 */
			*bytes = 1;
			fallthrough;
		case 0xb7: /* MOVZX r32/r64, m16 */
			if (!*bytes)
				*bytes = 2;
			type = MMIO_READ_ZERO_EXTEND;
			break;

		case 0xbe: /* MOVSX r16/r32/r64, m8 */
			*bytes = 1;
			fallthrough;
		case 0xbf: /* MOVSX r32/r64, m16 */
			if (!*bytes)
				*bytes = 2;
			type = MMIO_READ_SIGN_EXTEND;
			break;
		}
		break;
	}

	return type;
}
