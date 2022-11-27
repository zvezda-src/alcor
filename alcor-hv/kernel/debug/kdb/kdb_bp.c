
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kdb.h>
#include <linux/kgdb.h>
#include <linux/smp.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#include "kdb_private.h"

kdb_bp_t kdb_breakpoints[KDB_MAXBPT];

static void kdb_setsinglestep(struct pt_regs *regs)
{
	KDB_STATE_SET(DOING_SS);
}

static char *kdb_rwtypes[] = {
	"Instruction(i)",
	"Instruction(Register)",
	"Data Write",
	"I/O",
	"Data Access"
};

static char *kdb_bptype(kdb_bp_t *bp)
{
	if (bp->bp_type < 0 || bp->bp_type > 4)
		return "";

	return kdb_rwtypes[bp->bp_type];
}

static int kdb_parsebp(int argc, const char **argv, int *nextargp, kdb_bp_t *bp)
{
	int nextarg = *nextargp;
	int diag;

	bp->bph_length = 1;
	if ((argc + 1) != nextarg) {
		if (strncasecmp(argv[nextarg], "datar", sizeof("datar")) == 0)
			bp->bp_type = BP_ACCESS_WATCHPOINT;
		else if (strncasecmp(argv[nextarg], "dataw", sizeof("dataw")) == 0)
			bp->bp_type = BP_WRITE_WATCHPOINT;
		else if (strncasecmp(argv[nextarg], "inst", sizeof("inst")) == 0)
			bp->bp_type = BP_HARDWARE_BREAKPOINT;
		else
			return KDB_ARGCOUNT;

		bp->bph_length = 1;

		nextarg++;

		if ((argc + 1) != nextarg) {
			unsigned long len;

			diag = kdbgetularg((char *)argv[nextarg],
					   &len);
			if (diag)
				return diag;


			if (len > 8)
				return KDB_BADLENGTH;

			bp->bph_length = len;
			nextarg++;
		}

		if ((argc + 1) != nextarg)
			return KDB_ARGCOUNT;
	}

	return 0;
}

static int _kdb_bp_remove(kdb_bp_t *bp)
{
	int ret = 1;
	if (!bp->bp_installed)
		return ret;
	if (!bp->bp_type)
		ret = dbg_remove_sw_break(bp->bp_addr);
	else
		ret = arch_kgdb_ops.remove_hw_breakpoint(bp->bp_addr,
			 bp->bph_length,
			 bp->bp_type);
	if (ret == 0)
		bp->bp_installed = 0;
	return ret;
}

static void kdb_handle_bp(struct pt_regs *regs, kdb_bp_t *bp)
{
	if (KDB_DEBUG(BP))
		kdb_printf("regs->ip = 0x%lx\n", instruction_pointer(regs));

	/*
	kdb_setsinglestep(regs);

	/*
	bp->bp_delay = 0;
	bp->bp_delayed = 1;
}

static int _kdb_bp_install(struct pt_regs *regs, kdb_bp_t *bp)
{
	int ret;
	/*

	if (KDB_DEBUG(BP))
		kdb_printf("%s: bp_installed %d\n",
			   __func__, bp->bp_installed);
	if (!KDB_STATE(SSBPT))
		bp->bp_delay = 0;
	if (bp->bp_installed)
		return 1;
	if (bp->bp_delay || (bp->bp_delayed && KDB_STATE(DOING_SS))) {
		if (KDB_DEBUG(BP))
			kdb_printf("%s: delayed bp\n", __func__);
		kdb_handle_bp(regs, bp);
		return 0;
	}
	if (!bp->bp_type)
		ret = dbg_set_sw_break(bp->bp_addr);
	else
		ret = arch_kgdb_ops.set_hw_breakpoint(bp->bp_addr,
			 bp->bph_length,
			 bp->bp_type);
	if (ret == 0) {
		bp->bp_installed = 1;
	} else {
		kdb_printf("%s: failed to set breakpoint at 0x%lx\n",
			   __func__, bp->bp_addr);
		if (!bp->bp_type) {
			kdb_printf("Software breakpoints are unavailable.\n"
				   "  Boot the kernel with rodata=off\n"
				   "  OR use hw breaks: help bph\n");
		}
		return 1;
	}
	return 0;
}

void kdb_bp_install(struct pt_regs *regs)
{
	int i;

	for (i = 0; i < KDB_MAXBPT; i++) {
		kdb_bp_t *bp = &kdb_breakpoints[i];

		if (KDB_DEBUG(BP)) {
			kdb_printf("%s: bp %d bp_enabled %d\n",
				   __func__, i, bp->bp_enabled);
		}
		if (bp->bp_enabled)
			_kdb_bp_install(regs, bp);
	}
}

void kdb_bp_remove(void)
{
	int i;

	for (i = KDB_MAXBPT - 1; i >= 0; i--) {
		kdb_bp_t *bp = &kdb_breakpoints[i];

		if (KDB_DEBUG(BP)) {
			kdb_printf("%s: bp %d bp_enabled %d\n",
				   __func__, i, bp->bp_enabled);
		}
		if (bp->bp_enabled)
			_kdb_bp_remove(bp);
	}
}



static void kdb_printbp(kdb_bp_t *bp, int i)
{
	kdb_printf("%s ", kdb_bptype(bp));
	kdb_printf("BP #%d at ", i);
	kdb_symbol_print(bp->bp_addr, NULL, KDB_SP_DEFAULT);

	if (bp->bp_enabled)
		kdb_printf("\n    is enabled ");
	else
		kdb_printf("\n    is disabled");

	kdb_printf("  addr at %016lx, hardtype=%d installed=%d\n",
		   bp->bp_addr, bp->bp_type, bp->bp_installed);

	kdb_printf("\n");
}


static int kdb_bp(int argc, const char **argv)
{
	int i, bpno;
	kdb_bp_t *bp, *bp_check;
	int diag;
	char *symname = NULL;
	long offset = 0ul;
	int nextarg;
	kdb_bp_t template = {0};

	if (argc == 0) {
		/*
		for (bpno = 0, bp = kdb_breakpoints; bpno < KDB_MAXBPT;
		     bpno++, bp++) {
			if (bp->bp_free)
				continue;
			kdb_printbp(bp, bpno);
		}

		return 0;
	}

	nextarg = 1;
	diag = kdbgetaddrarg(argc, argv, &nextarg, &template.bp_addr,
			     &offset, &symname);
	if (diag)
		return diag;
	if (!template.bp_addr)
		return KDB_BADINT;

	/*
	diag = kgdb_validate_break_address(template.bp_addr);
	if (diag)
		return diag;

	/*
	for (bpno = 0, bp = kdb_breakpoints; bpno < KDB_MAXBPT; bpno++, bp++) {
		if (bp->bp_free)
			break;
	}

	if (bpno == KDB_MAXBPT)
		return KDB_TOOMANYBPT;

	if (strcmp(argv[0], "bph") == 0) {
		template.bp_type = BP_HARDWARE_BREAKPOINT;
		diag = kdb_parsebp(argc, argv, &nextarg, &template);
		if (diag)
			return diag;
	} else {
		template.bp_type = BP_BREAKPOINT;
	}

	/*
	for (i = 0, bp_check = kdb_breakpoints; i < KDB_MAXBPT;
	     i++, bp_check++) {
		if (!bp_check->bp_free &&
		    bp_check->bp_addr == template.bp_addr) {
			kdb_printf("You already have a breakpoint at "
				   kdb_bfd_vma_fmt0 "\n", template.bp_addr);
			return KDB_DUPBPT;
		}
	}

	template.bp_enabled = 1;

	/*
	bp->bp_free = 0;

	kdb_printbp(bp, bpno);

	return 0;
}

static int kdb_bc(int argc, const char **argv)
{
	unsigned long addr;
	kdb_bp_t *bp = NULL;
	int lowbp = KDB_MAXBPT;
	int highbp = 0;
	int done = 0;
	int i;
	int diag = 0;

	int cmd;			/* KDBCMD_B? */
#define KDBCMD_BC	0
#define KDBCMD_BE	1
#define KDBCMD_BD	2

	if (strcmp(argv[0], "be") == 0)
		cmd = KDBCMD_BE;
	else if (strcmp(argv[0], "bd") == 0)
		cmd = KDBCMD_BD;
	else
		cmd = KDBCMD_BC;

	if (argc != 1)
		return KDB_ARGCOUNT;

	if (strcmp(argv[1], "*") == 0) {
		lowbp = 0;
		highbp = KDB_MAXBPT;
	} else {
		diag = kdbgetularg(argv[1], &addr);
		if (diag)
			return diag;

		/*
		if (addr < KDB_MAXBPT) {
			lowbp = highbp = addr;
			highbp++;
		} else {
			for (i = 0, bp = kdb_breakpoints; i < KDB_MAXBPT;
			    i++, bp++) {
				if (bp->bp_addr == addr) {
					lowbp = highbp = i;
					highbp++;
					break;
				}
			}
		}
	}

	/*
	for (bp = &kdb_breakpoints[lowbp], i = lowbp;
	    i < highbp;
	    i++, bp++) {
		if (bp->bp_free)
			continue;

		done++;

		switch (cmd) {
		case KDBCMD_BC:
			bp->bp_enabled = 0;

			kdb_printf("Breakpoint %d at "
				   kdb_bfd_vma_fmt " cleared\n",
				   i, bp->bp_addr);

			bp->bp_addr = 0;
			bp->bp_free = 1;

			break;
		case KDBCMD_BE:
			bp->bp_enabled = 1;

			kdb_printf("Breakpoint %d at "
				   kdb_bfd_vma_fmt " enabled",
				   i, bp->bp_addr);

			kdb_printf("\n");
			break;
		case KDBCMD_BD:
			if (!bp->bp_enabled)
				break;

			bp->bp_enabled = 0;

			kdb_printf("Breakpoint %d at "
				   kdb_bfd_vma_fmt " disabled\n",
				   i, bp->bp_addr);

			break;
		}
		if (bp->bp_delay && (cmd == KDBCMD_BC || cmd == KDBCMD_BD)) {
			bp->bp_delay = 0;
			KDB_STATE_CLEAR(SSBPT);
		}
	}

	return (!done) ? KDB_BPTNOTFOUND : 0;
}


static int kdb_ss(int argc, const char **argv)
{
	if (argc != 0)
		return KDB_ARGCOUNT;
	/*
	KDB_STATE_SET(DOING_SS);
	return KDB_CMD_SS;
}

static kdbtab_t bptab[] = {
	{	.name = "bp",
		.func = kdb_bp,
		.usage = "[<vaddr>]",
		.help = "Set/Display breakpoints",
		.flags = KDB_ENABLE_FLOW_CTRL | KDB_REPEAT_NO_ARGS,
	},
	{	.name = "bl",
		.func = kdb_bp,
		.usage = "[<vaddr>]",
		.help = "Display breakpoints",
		.flags = KDB_ENABLE_FLOW_CTRL | KDB_REPEAT_NO_ARGS,
	},
	{	.name = "bc",
		.func = kdb_bc,
		.usage = "<bpnum>",
		.help = "Clear Breakpoint",
		.flags = KDB_ENABLE_FLOW_CTRL,
	},
	{	.name = "be",
		.func = kdb_bc,
		.usage = "<bpnum>",
		.help = "Enable Breakpoint",
		.flags = KDB_ENABLE_FLOW_CTRL,
	},
	{	.name = "bd",
		.func = kdb_bc,
		.usage = "<bpnum>",
		.help = "Disable Breakpoint",
		.flags = KDB_ENABLE_FLOW_CTRL,
	},
	{	.name = "ss",
		.func = kdb_ss,
		.usage = "",
		.help = "Single Step",
		.minlen = 1,
		.flags = KDB_ENABLE_FLOW_CTRL | KDB_REPEAT_NO_ARGS,
	},
};

static kdbtab_t bphcmd = {
	.name = "bph",
	.func = kdb_bp,
	.usage = "[<vaddr>]",
	.help = "[datar [length]|dataw [length]]   Set hw brk",
	.flags = KDB_ENABLE_FLOW_CTRL | KDB_REPEAT_NO_ARGS,
};


void __init kdb_initbptab(void)
{
	int i;
	kdb_bp_t *bp;

	/*
	memset(&kdb_breakpoints, '\0', sizeof(kdb_breakpoints));

	for (i = 0, bp = kdb_breakpoints; i < KDB_MAXBPT; i++, bp++)
		bp->bp_free = 1;

	kdb_register_table(bptab, ARRAY_SIZE(bptab));
	if (arch_kgdb_ops.flags & KGDB_HW_BREAKPOINT)
		kdb_register_table(&bphcmd, 1);
}
