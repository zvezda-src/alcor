
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/kallsyms.h>
#include <linux/stddef.h>
#include <linux/vmalloc.h>
#include <linux/ptrace.h>
#include <linux/highmem.h>
#include <linux/hardirq.h>
#include <linux/delay.h>
#include <linux/uaccess.h>
#include <linux/kdb.h>
#include <linux/slab.h>
#include <linux/ctype.h>
#include "kdb_private.h"

int kdbgetsymval(const char *symname, kdb_symtab_t *symtab)
{
	kdb_dbg_printf(AR, "symname=%s, symtab=%px\n", symname, symtab);
	memset(symtab, 0, sizeof(*symtab));
	symtab->sym_start = kallsyms_lookup_name(symname);
	if (symtab->sym_start) {
		kdb_dbg_printf(AR, "returns 1, symtab->sym_start=0x%lx\n",
			       symtab->sym_start);
		return 1;
	}
	kdb_dbg_printf(AR, "returns 0\n");
	return 0;
}
EXPORT_SYMBOL(kdbgetsymval);

int kdbnearsym(unsigned long addr, kdb_symtab_t *symtab)
{
	int ret = 0;
	unsigned long symbolsize = 0;
	unsigned long offset = 0;
	static char namebuf[KSYM_NAME_LEN];

	kdb_dbg_printf(AR, "addr=0x%lx, symtab=%px\n", addr, symtab);
	memset(symtab, 0, sizeof(*symtab));

	if (addr < 4096)
		goto out;

	symtab->sym_name = kallsyms_lookup(addr, &symbolsize , &offset,
				(char **)(&symtab->mod_name), namebuf);
	if (offset > 8*1024*1024) {
		symtab->sym_name = NULL;
		addr = offset = symbolsize = 0;
	}
	symtab->sym_start = addr - offset;
	symtab->sym_end = symtab->sym_start + symbolsize;
	ret = symtab->sym_name != NULL && *(symtab->sym_name) != '\0';

	if (symtab->mod_name == NULL)
		symtab->mod_name = "kernel";
	kdb_dbg_printf(AR, "returns %d symtab->sym_start=0x%lx, symtab->mod_name=%px, symtab->sym_name=%px (%s)\n",
		       ret, symtab->sym_start, symtab->mod_name, symtab->sym_name, symtab->sym_name);
out:
	return ret;
}

static char ks_namebuf[KSYM_NAME_LEN+1], ks_namebuf_prev[KSYM_NAME_LEN+1];

int kallsyms_symbol_complete(char *prefix_name, int max_len)
{
	loff_t pos = 0;
	int prefix_len = strlen(prefix_name), prev_len = 0;
	int i, number = 0;
	const char *name;

	while ((name = kdb_walk_kallsyms(&pos))) {
		if (strncmp(name, prefix_name, prefix_len) == 0) {
			strscpy(ks_namebuf, name, sizeof(ks_namebuf));
			/* Work out the longest name that matches the prefix */
			if (++number == 1) {
				prev_len = min_t(int, max_len-1,
						 strlen(ks_namebuf));
				memcpy(ks_namebuf_prev, ks_namebuf, prev_len);
				ks_namebuf_prev[prev_len] = '\0';
				continue;
			}
			for (i = 0; i < prev_len; i++) {
				if (ks_namebuf[i] != ks_namebuf_prev[i]) {
					prev_len = i;
					ks_namebuf_prev[i] = '\0';
					break;
				}
			}
		}
	}
	if (prev_len > prefix_len)
		memcpy(prefix_name, ks_namebuf_prev, prev_len+1);
	return number;
}

int kallsyms_symbol_next(char *prefix_name, int flag, int buf_size)
{
	int prefix_len = strlen(prefix_name);
	static loff_t pos;
	const char *name;

	if (!flag)
		pos = 0;

	while ((name = kdb_walk_kallsyms(&pos))) {
		if (!strncmp(name, prefix_name, prefix_len))
			return strscpy(prefix_name, name, buf_size);
	}
	return 0;
}

void kdb_symbol_print(unsigned long addr, const kdb_symtab_t *symtab_p,
		      unsigned int punc)
{
	kdb_symtab_t symtab, *symtab_p2;
	if (symtab_p) {
		symtab_p2 = (kdb_symtab_t *)symtab_p;
	} else {
		symtab_p2 = &symtab;
		kdbnearsym(addr, symtab_p2);
	}
	if (!(symtab_p2->sym_name || (punc & KDB_SP_VALUE)))
		return;
	if (punc & KDB_SP_SPACEB)
		kdb_printf(" ");
	if (punc & KDB_SP_VALUE)
		kdb_printf(kdb_machreg_fmt0, addr);
	if (symtab_p2->sym_name) {
		if (punc & KDB_SP_VALUE)
			kdb_printf(" ");
		if (punc & KDB_SP_PAREN)
			kdb_printf("(");
		if (strcmp(symtab_p2->mod_name, "kernel"))
			kdb_printf("[%s]", symtab_p2->mod_name);
		kdb_printf("%s", symtab_p2->sym_name);
		if (addr != symtab_p2->sym_start)
			kdb_printf("+0x%lx", addr - symtab_p2->sym_start);
		if (punc & KDB_SP_SYMSIZE)
			kdb_printf("/0x%lx",
				   symtab_p2->sym_end - symtab_p2->sym_start);
		if (punc & KDB_SP_PAREN)
			kdb_printf(")");
	}
	if (punc & KDB_SP_SPACEA)
		kdb_printf(" ");
	if (punc & KDB_SP_NEWLINE)
		kdb_printf("\n");
}

char *kdb_strdup(const char *str, gfp_t type)
{
	int n = strlen(str)+1;
	char *s = kmalloc(n, type);
	if (!s)
		return NULL;
	return strcpy(s, str);
}

int kdb_getarea_size(void *res, unsigned long addr, size_t size)
{
	int ret = copy_from_kernel_nofault((char *)res, (char *)addr, size);
	if (ret) {
		if (!KDB_STATE(SUPPRESS)) {
			kdb_func_printf("Bad address 0x%lx\n", addr);
			KDB_STATE_SET(SUPPRESS);
		}
		ret = KDB_BADADDR;
	} else {
		KDB_STATE_CLEAR(SUPPRESS);
	}
	return ret;
}

int kdb_putarea_size(unsigned long addr, void *res, size_t size)
{
	int ret = copy_to_kernel_nofault((char *)addr, (char *)res, size);
	if (ret) {
		if (!KDB_STATE(SUPPRESS)) {
			kdb_func_printf("Bad address 0x%lx\n", addr);
			KDB_STATE_SET(SUPPRESS);
		}
		ret = KDB_BADADDR;
	} else {
		KDB_STATE_CLEAR(SUPPRESS);
	}
	return ret;
}

static int kdb_getphys(void *res, unsigned long addr, size_t size)
{
	unsigned long pfn;
	void *vaddr;
	struct page *page;

	pfn = (addr >> PAGE_SHIFT);
	if (!pfn_valid(pfn))
		return 1;
	page = pfn_to_page(pfn);
	vaddr = kmap_atomic(page);
	memcpy(res, vaddr + (addr & (PAGE_SIZE - 1)), size);
	kunmap_atomic(vaddr);

	return 0;
}

int kdb_getphysword(unsigned long *word, unsigned long addr, size_t size)
{
	int diag;
	__u8  w1;
	__u16 w2;
	__u32 w4;
	__u64 w8;

	switch (size) {
	case 1:
		diag = kdb_getphys(&w1, addr, sizeof(w1));
		if (!diag)
			*word = w1;
		break;
	case 2:
		diag = kdb_getphys(&w2, addr, sizeof(w2));
		if (!diag)
			*word = w2;
		break;
	case 4:
		diag = kdb_getphys(&w4, addr, sizeof(w4));
		if (!diag)
			*word = w4;
		break;
	case 8:
		if (size <= sizeof(*word)) {
			diag = kdb_getphys(&w8, addr, sizeof(w8));
			if (!diag)
				*word = w8;
			break;
		}
		fallthrough;
	default:
		diag = KDB_BADWIDTH;
		kdb_func_printf("bad width %zu\n", size);
	}
	return diag;
}

int kdb_getword(unsigned long *word, unsigned long addr, size_t size)
{
	int diag;
	__u8  w1;
	__u16 w2;
	__u32 w4;
	__u64 w8;
	switch (size) {
	case 1:
		diag = kdb_getarea(w1, addr);
		if (!diag)
			*word = w1;
		break;
	case 2:
		diag = kdb_getarea(w2, addr);
		if (!diag)
			*word = w2;
		break;
	case 4:
		diag = kdb_getarea(w4, addr);
		if (!diag)
			*word = w4;
		break;
	case 8:
		if (size <= sizeof(*word)) {
			diag = kdb_getarea(w8, addr);
			if (!diag)
				*word = w8;
			break;
		}
		fallthrough;
	default:
		diag = KDB_BADWIDTH;
		kdb_func_printf("bad width %zu\n", size);
	}
	return diag;
}

int kdb_putword(unsigned long addr, unsigned long word, size_t size)
{
	int diag;
	__u8  w1;
	__u16 w2;
	__u32 w4;
	__u64 w8;
	switch (size) {
	case 1:
		w1 = word;
		diag = kdb_putarea(addr, w1);
		break;
	case 2:
		w2 = word;
		diag = kdb_putarea(addr, w2);
		break;
	case 4:
		w4 = word;
		diag = kdb_putarea(addr, w4);
		break;
	case 8:
		if (size <= sizeof(word)) {
			w8 = word;
			diag = kdb_putarea(addr, w8);
			break;
		}
		fallthrough;
	default:
		diag = KDB_BADWIDTH;
		kdb_func_printf("bad width %zu\n", size);
	}
	return diag;
}



char kdb_task_state_char (const struct task_struct *p)
{
	unsigned long tmp;
	char state;
	int cpu;

	if (!p ||
	    copy_from_kernel_nofault(&tmp, (char *)p, sizeof(unsigned long)))
		return 'E';

	state = task_state_to_char((struct task_struct *) p);

	if (is_idle_task(p)) {
		/* Idle task.  Is it really idle, apart from the kdb
		 * interrupt? */
		cpu = kdb_process_cpu(p);
		if (!kdb_task_has_cpu(p) || kgdb_info[cpu].irq_depth == 1) {
			if (cpu != kdb_initial_cpu)
				state = '-';	/* idle task */
		}
	} else if (!p->mm && strchr("IMS", state)) {
		state = tolower(state);		/* sleeping system daemon */
	}
	return state;
}

bool kdb_task_state(const struct task_struct *p, const char *mask)
{
	char state = kdb_task_state_char(p);

	/* If there is no mask, then we will filter code that runs when the
	 * scheduler is idling and any system daemons that are currently
	 * sleeping.
	 */
	if (!mask || mask[0] == '\0')
		return !strchr("-ims", state);

	/* A is a special case that matches all states */
	if (strchr(mask, 'A'))
		return true;

	return strchr(mask, state);
}


static int kdb_flags_stack[4], kdb_flags_index;

void kdb_save_flags(void)
{
	BUG_ON(kdb_flags_index >= ARRAY_SIZE(kdb_flags_stack));
	kdb_flags_stack[kdb_flags_index++] = kdb_flags;
}

void kdb_restore_flags(void)
{
	BUG_ON(kdb_flags_index <= 0);
	kdb_flags = kdb_flags_stack[--kdb_flags_index];
}
