
#include <linux/uaccess.h>
#include <asm/umip.h>
#include <asm/traps.h>
#include <asm/insn.h>
#include <asm/insn-eval.h>
#include <linux/ratelimit.h>

#undef pr_fmt
#define pr_fmt(fmt) "umip: " fmt


#define UMIP_DUMMY_GDT_BASE 0xfffffffffffe0000ULL
#define UMIP_DUMMY_IDT_BASE 0xffffffffffff0000ULL

#define UMIP_GDT_IDT_BASE_SIZE_64BIT 8
#define UMIP_GDT_IDT_BASE_SIZE_32BIT 4
#define UMIP_GDT_IDT_LIMIT_SIZE 2

#define	UMIP_INST_SGDT	0	/* 0F 01 /0 */
#define	UMIP_INST_SIDT	1	/* 0F 01 /1 */
#define	UMIP_INST_SMSW	2	/* 0F 01 /4 */
#define	UMIP_INST_SLDT  3       /* 0F 00 /0 */
#define	UMIP_INST_STR   4       /* 0F 00 /1 */

static const char * const umip_insns[5] = {
	[UMIP_INST_SGDT] = "SGDT",
	[UMIP_INST_SIDT] = "SIDT",
	[UMIP_INST_SMSW] = "SMSW",
	[UMIP_INST_SLDT] = "SLDT",
	[UMIP_INST_STR] = "STR",
};

#define umip_pr_err(regs, fmt, ...) \
	umip_printk(regs, KERN_ERR, fmt, ##__VA_ARGS__)
#define umip_pr_debug(regs, fmt, ...) \
	umip_printk(regs, KERN_DEBUG, fmt,  ##__VA_ARGS__)

static __printf(3, 4)
void umip_printk(const struct pt_regs *regs, const char *log_level,
		 const char *fmt, ...)
{
	/* Bursts of 5 messages every two minutes */
	static DEFINE_RATELIMIT_STATE(ratelimit, 2 * 60 * HZ, 5);
	struct task_struct *tsk = current;
	struct va_format vaf;
	va_list args;

	if (!__ratelimit(&ratelimit))
		return;

	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;
	printk("%s" pr_fmt("%s[%d] ip:%lx sp:%lx: %pV"), log_level, tsk->comm,
	       task_pid_nr(tsk), regs->ip, regs->sp, &vaf);
	va_end(args);
}

static int identify_insn(struct insn *insn)
{
	/* By getting modrm we also get the opcode. */
	insn_get_modrm(insn);

	if (!insn->modrm.nbytes)
		return -EINVAL;

	/* All the instructions of interest start with 0x0f. */
	if (insn->opcode.bytes[0] != 0xf)
		return -EINVAL;

	if (insn->opcode.bytes[1] == 0x1) {
		switch (X86_MODRM_REG(insn->modrm.value)) {
		case 0:
			return UMIP_INST_SGDT;
		case 1:
			return UMIP_INST_SIDT;
		case 4:
			return UMIP_INST_SMSW;
		default:
			return -EINVAL;
		}
	} else if (insn->opcode.bytes[1] == 0x0) {
		if (X86_MODRM_REG(insn->modrm.value) == 0)
			return UMIP_INST_SLDT;
		else if (X86_MODRM_REG(insn->modrm.value) == 1)
			return UMIP_INST_STR;
		else
			return -EINVAL;
	} else {
		return -EINVAL;
	}
}

static int emulate_umip_insn(struct insn *insn, int umip_inst,
			     unsigned char *data, int *data_size, bool x86_64)
{
	if (!data || !data_size || !insn)
		return -EINVAL;
	/*
	if (umip_inst == UMIP_INST_SGDT || umip_inst == UMIP_INST_SIDT) {
		u64 dummy_base_addr;
		u16 dummy_limit = 0;

		/* SGDT and SIDT do not use registers operands. */
		if (X86_MODRM_MOD(insn->modrm.value) == 3)
			return -EINVAL;

		if (umip_inst == UMIP_INST_SGDT)
			dummy_base_addr = UMIP_DUMMY_GDT_BASE;
		else
			dummy_base_addr = UMIP_DUMMY_IDT_BASE;

		/*
		if (x86_64)
			*data_size = UMIP_GDT_IDT_BASE_SIZE_64BIT;
		else
			*data_size = UMIP_GDT_IDT_BASE_SIZE_32BIT;

		memcpy(data + 2, &dummy_base_addr, *data_size);

		*data_size += UMIP_GDT_IDT_LIMIT_SIZE;
		memcpy(data, &dummy_limit, UMIP_GDT_IDT_LIMIT_SIZE);

	} else if (umip_inst == UMIP_INST_SMSW || umip_inst == UMIP_INST_SLDT ||
		   umip_inst == UMIP_INST_STR) {
		unsigned long dummy_value;

		if (umip_inst == UMIP_INST_SMSW) {
			dummy_value = CR0_STATE;
		} else if (umip_inst == UMIP_INST_STR) {
			dummy_value = GDT_ENTRY_TSS * 8;
		} else if (umip_inst == UMIP_INST_SLDT) {
#ifdef CONFIG_MODIFY_LDT_SYSCALL
			down_read(&current->mm->context.ldt_usr_sem);
			if (current->mm->context.ldt)
				dummy_value = GDT_ENTRY_LDT * 8;
			else
				dummy_value = 0;
			up_read(&current->mm->context.ldt_usr_sem);
#else
			dummy_value = 0;
#endif
		}

		/*
		if (X86_MODRM_MOD(insn->modrm.value) == 3)
			*data_size = insn->opnd_bytes;
		else
			*data_size = 2;

		memcpy(data, &dummy_value, *data_size);
	} else {
		return -EINVAL;
	}

	return 0;
}

static void force_sig_info_umip_fault(void __user *addr, struct pt_regs *regs)
{
	struct task_struct *tsk = current;

	tsk->thread.cr2		= (unsigned long)addr;
	tsk->thread.error_code	= X86_PF_USER | X86_PF_WRITE;
	tsk->thread.trap_nr	= X86_TRAP_PF;

	force_sig_fault(SIGSEGV, SEGV_MAPERR, addr);

	if (!(show_unhandled_signals && unhandled_signal(tsk, SIGSEGV)))
		return;

	umip_pr_err(regs, "segfault in emulation. error%x\n",
		    X86_PF_USER | X86_PF_WRITE);
}

bool fixup_umip_exception(struct pt_regs *regs)
{
	int nr_copied, reg_offset, dummy_data_size, umip_inst;
	/* 10 bytes is the maximum size of the result of UMIP instructions */
	unsigned char dummy_data[10] = { 0 };
	unsigned char buf[MAX_INSN_SIZE];
	unsigned long *reg_addr;
	void __user *uaddr;
	struct insn insn;

	if (!regs)
		return false;

	/*
	nr_copied = insn_fetch_from_user(regs, buf);
	if (nr_copied <= 0)
		return false;

	if (!insn_decode_from_regs(&insn, regs, buf, nr_copied))
		return false;

	umip_inst = identify_insn(&insn);
	if (umip_inst < 0)
		return false;

	umip_pr_debug(regs, "%s instruction cannot be used by applications.\n",
			umip_insns[umip_inst]);

	umip_pr_debug(regs, "For now, expensive software emulation returns the result.\n");

	if (emulate_umip_insn(&insn, umip_inst, dummy_data, &dummy_data_size,
			      user_64bit_mode(regs)))
		return false;

	/*
	if (X86_MODRM_MOD(insn.modrm.value) == 3) {
		reg_offset = insn_get_modrm_rm_off(&insn, regs);

		/*
		if (reg_offset < 0)
			return false;

		reg_addr = (unsigned long *)((unsigned long)regs + reg_offset);
		memcpy(reg_addr, dummy_data, dummy_data_size);
	} else {
		uaddr = insn_get_addr_ref(&insn, regs);
		if ((unsigned long)uaddr == -1L)
			return false;

		nr_copied = copy_to_user(uaddr, dummy_data, dummy_data_size);
		if (nr_copied  > 0) {
			/*
			force_sig_info_umip_fault(uaddr, regs);
			return true;
		}
	}

	/* increase IP to let the program keep going */
	regs->ip += insn.length;
	return true;
}
