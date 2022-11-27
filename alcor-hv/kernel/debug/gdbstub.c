
#include <linux/kernel.h>
#include <linux/sched/signal.h>
#include <linux/kgdb.h>
#include <linux/kdb.h>
#include <linux/serial_core.h>
#include <linux/reboot.h>
#include <linux/uaccess.h>
#include <asm/cacheflush.h>
#include <asm/unaligned.h>
#include "debug_core.h"

#define KGDB_MAX_THREAD_QUERY 17

static char			remcom_in_buffer[BUFMAX];
static char			remcom_out_buffer[BUFMAX];
static int			gdbstub_use_prev_in_buf;
static int			gdbstub_prev_in_buf_pos;

static unsigned long		gdb_regs[(NUMREGBYTES +
					sizeof(unsigned long) - 1) /
					sizeof(unsigned long)];


#ifdef CONFIG_KGDB_KDB
static int gdbstub_read_wait(void)
{
	int ret = -1;
	int i;

	if (unlikely(gdbstub_use_prev_in_buf)) {
		if (gdbstub_prev_in_buf_pos < gdbstub_use_prev_in_buf)
			return remcom_in_buffer[gdbstub_prev_in_buf_pos++];
		else
			gdbstub_use_prev_in_buf = 0;
	}

	/* poll any additional I/O interfaces that are defined */
	while (ret < 0)
		for (i = 0; kdb_poll_funcs[i] != NULL; i++) {
			ret = kdb_poll_funcs[i]();
			if (ret > 0)
				break;
		}
	return ret;
}
#else
static int gdbstub_read_wait(void)
{
	int ret = dbg_io_ops->read_char();
	while (ret == NO_POLL_CHAR)
		ret = dbg_io_ops->read_char();
	return ret;
}
#endif
static void get_packet(char *buffer)
{
	unsigned char checksum;
	unsigned char xmitcsum;
	int count;
	char ch;

	do {
		/*
		while ((ch = (gdbstub_read_wait())) != '$')
			/* nothing */;

		kgdb_connected = 1;
		checksum = 0;
		xmitcsum = -1;

		count = 0;

		/*
		while (count < (BUFMAX - 1)) {
			ch = gdbstub_read_wait();
			if (ch == '#')
				break;
			checksum = checksum + ch;
			buffer[count] = ch;
			count = count + 1;
		}

		if (ch == '#') {
			xmitcsum = hex_to_bin(gdbstub_read_wait()) << 4;
			xmitcsum += hex_to_bin(gdbstub_read_wait());

			if (checksum != xmitcsum)
				/* failed checksum */
				dbg_io_ops->write_char('-');
			else
				/* successful transfer */
				dbg_io_ops->write_char('+');
			if (dbg_io_ops->flush)
				dbg_io_ops->flush();
		}
		buffer[count] = 0;
	} while (checksum != xmitcsum);
}

static void put_packet(char *buffer)
{
	unsigned char checksum;
	int count;
	char ch;

	/*
	while (1) {
		dbg_io_ops->write_char('$');
		checksum = 0;
		count = 0;

		while ((ch = buffer[count])) {
			dbg_io_ops->write_char(ch);
			checksum += ch;
			count++;
		}

		dbg_io_ops->write_char('#');
		dbg_io_ops->write_char(hex_asc_hi(checksum));
		dbg_io_ops->write_char(hex_asc_lo(checksum));
		if (dbg_io_ops->flush)
			dbg_io_ops->flush();

		/* Now see what we get in reply. */
		ch = gdbstub_read_wait();

		if (ch == 3)
			ch = gdbstub_read_wait();

		/* If we get an ACK, we are done. */
		if (ch == '+')
			return;

		/*
		if (ch == '$') {
			dbg_io_ops->write_char('-');
			if (dbg_io_ops->flush)
				dbg_io_ops->flush();
			return;
		}
	}
}

static char gdbmsgbuf[BUFMAX + 1];

void gdbstub_msg_write(const char *s, int len)
{
	char *bufptr;
	int wcount;
	int i;

	if (len == 0)
		len = strlen(s);

	/* 'O'utput */
	gdbmsgbuf[0] = 'O';

	/* Fill and send buffers... */
	while (len > 0) {
		bufptr = gdbmsgbuf + 1;

		/* Calculate how many this time */
		if ((len << 1) > (BUFMAX - 2))
			wcount = (BUFMAX - 2) >> 1;
		else
			wcount = len;

		/* Pack in hex chars */
		for (i = 0; i < wcount; i++)
			bufptr = hex_byte_pack(bufptr, s[i]);
		*bufptr = '\0';

		/* Move up */
		s += wcount;
		len -= wcount;

		/* Write packet */
		put_packet(gdbmsgbuf);
	}
}

char *kgdb_mem2hex(char *mem, char *buf, int count)
{
	char *tmp;
	int err;

	/*
	tmp = buf + count;

	err = copy_from_kernel_nofault(tmp, mem, count);
	if (err)
		return NULL;
	while (count > 0) {
		buf = hex_byte_pack(buf, *tmp);
		tmp++;
		count--;
	}

	return buf;
}

int kgdb_hex2mem(char *buf, char *mem, int count)
{
	char *tmp_raw;
	char *tmp_hex;

	/*
	tmp_raw = buf + count * 2;

	tmp_hex = tmp_raw - 1;
	while (tmp_hex >= buf) {
		tmp_raw--;
		*tmp_raw = hex_to_bin(*tmp_hex--);
		*tmp_raw |= hex_to_bin(*tmp_hex--) << 4;
	}

	return copy_to_kernel_nofault(mem, tmp_raw, count);
}

int kgdb_hex2long(char **ptr, unsigned long *long_val)
{
	int hex_val;
	int num = 0;
	int negate = 0;


	if (**ptr == '-') {
		negate = 1;
		(*ptr)++;
	}
	while (**ptr) {
		hex_val = hex_to_bin(**ptr);
		if (hex_val < 0)
			break;

		*long_val = (*long_val << 4) | hex_val;
		num++;
		(*ptr)++;
	}

	if (negate)
		*long_val = -*long_val;

	return num;
}

static int kgdb_ebin2mem(char *buf, char *mem, int count)
{
	int size = 0;
	char *c = buf;

	while (count-- > 0) {
		c[size] = *buf++;
		if (c[size] == 0x7d)
			c[size] = *buf++ ^ 0x20;
		size++;
	}

	return copy_to_kernel_nofault(mem, c, size);
}

#if DBG_MAX_REG_NUM > 0
void pt_regs_to_gdb_regs(unsigned long *gdb_regs, struct pt_regs *regs)
{
	int i;
	int idx = 0;
	char *ptr = (char *)gdb_regs;

	for (i = 0; i < DBG_MAX_REG_NUM; i++) {
		dbg_get_reg(i, ptr + idx, regs);
		idx += dbg_reg_def[i].size;
	}
}

void gdb_regs_to_pt_regs(unsigned long *gdb_regs, struct pt_regs *regs)
{
	int i;
	int idx = 0;
	char *ptr = (char *)gdb_regs;

	for (i = 0; i < DBG_MAX_REG_NUM; i++) {
		dbg_set_reg(i, ptr + idx, regs);
		idx += dbg_reg_def[i].size;
	}
}
#endif /* DBG_MAX_REG_NUM > 0 */

static int write_mem_msg(int binary)
{
	char *ptr = &remcom_in_buffer[1];
	unsigned long addr;
	unsigned long length;
	int err;

	if (kgdb_hex2long(&ptr, &addr) > 0 && *(ptr++) == ',' &&
	    kgdb_hex2long(&ptr, &length) > 0 && *(ptr++) == ':') {
		if (binary)
			err = kgdb_ebin2mem(ptr, (char *)addr, length);
		else
			err = kgdb_hex2mem(ptr, (char *)addr, length);
		if (err)
			return err;
		if (CACHE_FLUSH_IS_SAFE)
			flush_icache_range(addr, addr + length);
		return 0;
	}

	return -EINVAL;
}

static void error_packet(char *pkt, int error)
{
	error = -error;
	pkt[0] = 'E';
	pkt[1] = hex_asc[(error / 10)];
	pkt[2] = hex_asc[(error % 10)];
	pkt[3] = '\0';
}


#define BUF_THREAD_ID_SIZE	8

static char *pack_threadid(char *pkt, unsigned char *id)
{
	unsigned char *limit;
	int lzero = 1;

	limit = id + (BUF_THREAD_ID_SIZE / 2);
	while (id < limit) {
		if (!lzero || *id != 0) {
			pkt = hex_byte_pack(pkt, *id);
			lzero = 0;
		}
		id++;
	}

	if (lzero)
		pkt = hex_byte_pack(pkt, 0);

	return pkt;
}

static void int_to_threadref(unsigned char *id, int value)
{
	put_unaligned_be32(value, id);
}

static struct task_struct *getthread(struct pt_regs *regs, int tid)
{
	/*
	if (tid == 0 || tid == -1)
		tid = -atomic_read(&kgdb_active) - 2;
	if (tid < -1 && tid > -NR_CPUS - 2) {
		if (kgdb_info[-tid - 2].task)
			return kgdb_info[-tid - 2].task;
		else
			return idle_task(-tid - 2);
	}
	if (tid <= 0) {
		printk(KERN_ERR "KGDB: Internal thread select error\n");
		dump_stack();
		return NULL;
	}

	/*
	return find_task_by_pid_ns(tid, &init_pid_ns);
}


static inline int shadow_pid(int realpid)
{
	if (realpid)
		return realpid;

	return -raw_smp_processor_id() - 2;
}


static void gdb_cmd_status(struct kgdb_state *ks)
{
	/*
	dbg_remove_all_break();

	remcom_out_buffer[0] = 'S';
	hex_byte_pack(&remcom_out_buffer[1], ks->signo);
}

static void gdb_get_regs_helper(struct kgdb_state *ks)
{
	struct task_struct *thread;
	void *local_debuggerinfo;
	int i;

	thread = kgdb_usethread;
	if (!thread) {
		thread = kgdb_info[ks->cpu].task;
		local_debuggerinfo = kgdb_info[ks->cpu].debuggerinfo;
	} else {
		local_debuggerinfo = NULL;
		for_each_online_cpu(i) {
			/*
			if (thread == kgdb_info[i].task)
				local_debuggerinfo = kgdb_info[i].debuggerinfo;
		}
	}

	/*
	if (local_debuggerinfo) {
		pt_regs_to_gdb_regs(gdb_regs, local_debuggerinfo);
	} else {
		/*
		sleeping_thread_to_gdb_regs(gdb_regs, thread);
	}
}

static void gdb_cmd_getregs(struct kgdb_state *ks)
{
	gdb_get_regs_helper(ks);
	kgdb_mem2hex((char *)gdb_regs, remcom_out_buffer, NUMREGBYTES);
}

static void gdb_cmd_setregs(struct kgdb_state *ks)
{
	kgdb_hex2mem(&remcom_in_buffer[1], (char *)gdb_regs, NUMREGBYTES);

	if (kgdb_usethread && kgdb_usethread != current) {
		error_packet(remcom_out_buffer, -EINVAL);
	} else {
		gdb_regs_to_pt_regs(gdb_regs, ks->linux_regs);
		strcpy(remcom_out_buffer, "OK");
	}
}

static void gdb_cmd_memread(struct kgdb_state *ks)
{
	char *ptr = &remcom_in_buffer[1];
	unsigned long length;
	unsigned long addr;
	char *err;

	if (kgdb_hex2long(&ptr, &addr) > 0 && *ptr++ == ',' &&
					kgdb_hex2long(&ptr, &length) > 0) {
		err = kgdb_mem2hex((char *)addr, remcom_out_buffer, length);
		if (!err)
			error_packet(remcom_out_buffer, -EINVAL);
	} else {
		error_packet(remcom_out_buffer, -EINVAL);
	}
}

static void gdb_cmd_memwrite(struct kgdb_state *ks)
{
	int err = write_mem_msg(0);

	if (err)
		error_packet(remcom_out_buffer, err);
	else
		strcpy(remcom_out_buffer, "OK");
}

#if DBG_MAX_REG_NUM > 0
static char *gdb_hex_reg_helper(int regnum, char *out)
{
	int i;
	int offset = 0;

	for (i = 0; i < regnum; i++)
		offset += dbg_reg_def[i].size;
	return kgdb_mem2hex((char *)gdb_regs + offset, out,
			    dbg_reg_def[i].size);
}

static void gdb_cmd_reg_get(struct kgdb_state *ks)
{
	unsigned long regnum;
	char *ptr = &remcom_in_buffer[1];

	kgdb_hex2long(&ptr, &regnum);
	if (regnum >= DBG_MAX_REG_NUM) {
		error_packet(remcom_out_buffer, -EINVAL);
		return;
	}
	gdb_get_regs_helper(ks);
	gdb_hex_reg_helper(regnum, remcom_out_buffer);
}

static void gdb_cmd_reg_set(struct kgdb_state *ks)
{
	unsigned long regnum;
	char *ptr = &remcom_in_buffer[1];
	int i = 0;

	kgdb_hex2long(&ptr, &regnum);
	if (*ptr++ != '=' ||
	    !(!kgdb_usethread || kgdb_usethread == current) ||
	    !dbg_get_reg(regnum, gdb_regs, ks->linux_regs)) {
		error_packet(remcom_out_buffer, -EINVAL);
		return;
	}
	memset(gdb_regs, 0, sizeof(gdb_regs));
	while (i < sizeof(gdb_regs) * 2)
		if (hex_to_bin(ptr[i]) >= 0)
			i++;
		else
			break;
	i = i / 2;
	kgdb_hex2mem(ptr, (char *)gdb_regs, i);
	dbg_set_reg(regnum, gdb_regs, ks->linux_regs);
	strcpy(remcom_out_buffer, "OK");
}
#endif /* DBG_MAX_REG_NUM > 0 */

static void gdb_cmd_binwrite(struct kgdb_state *ks)
{
	int err = write_mem_msg(1);

	if (err)
		error_packet(remcom_out_buffer, err);
	else
		strcpy(remcom_out_buffer, "OK");
}

static void gdb_cmd_detachkill(struct kgdb_state *ks)
{
	int error;

	/* The detach case */
	if (remcom_in_buffer[0] == 'D') {
		error = dbg_remove_all_break();
		if (error < 0) {
			error_packet(remcom_out_buffer, error);
		} else {
			strcpy(remcom_out_buffer, "OK");
			kgdb_connected = 0;
		}
		put_packet(remcom_out_buffer);
	} else {
		/*
		dbg_remove_all_break();
		kgdb_connected = 0;
	}
}

static int gdb_cmd_reboot(struct kgdb_state *ks)
{
	/* For now, only honor R0 */
	if (strcmp(remcom_in_buffer, "R0") == 0) {
		printk(KERN_CRIT "Executing emergency reboot\n");
		strcpy(remcom_out_buffer, "OK");
		put_packet(remcom_out_buffer);

		/*
		machine_emergency_restart();
		kgdb_connected = 0;

		return 1;
	}
	return 0;
}

static void gdb_cmd_query(struct kgdb_state *ks)
{
	struct task_struct *g;
	struct task_struct *p;
	unsigned char thref[BUF_THREAD_ID_SIZE];
	char *ptr;
	int i;
	int cpu;
	int finished = 0;

	switch (remcom_in_buffer[1]) {
	case 's':
	case 'f':
		if (memcmp(remcom_in_buffer + 2, "ThreadInfo", 10))
			break;

		i = 0;
		remcom_out_buffer[0] = 'm';
		ptr = remcom_out_buffer + 1;
		if (remcom_in_buffer[1] == 'f') {
			/* Each cpu is a shadow thread */
			for_each_online_cpu(cpu) {
				ks->thr_query = 0;
				int_to_threadref(thref, -cpu - 2);
				ptr = pack_threadid(ptr, thref);
				*(ptr++) = ',';
				i++;
			}
		}

		for_each_process_thread(g, p) {
			if (i >= ks->thr_query && !finished) {
				int_to_threadref(thref, p->pid);
				ptr = pack_threadid(ptr, thref);
				*(ptr++) = ',';
				ks->thr_query++;
				if (ks->thr_query % KGDB_MAX_THREAD_QUERY == 0)
					finished = 1;
			}
			i++;
		}

		*(--ptr) = '\0';
		break;

	case 'C':
		/* Current thread id */
		strcpy(remcom_out_buffer, "QC");
		ks->threadid = shadow_pid(current->pid);
		int_to_threadref(thref, ks->threadid);
		pack_threadid(remcom_out_buffer + 2, thref);
		break;
	case 'T':
		if (memcmp(remcom_in_buffer + 1, "ThreadExtraInfo,", 16))
			break;

		ks->threadid = 0;
		ptr = remcom_in_buffer + 17;
		kgdb_hex2long(&ptr, &ks->threadid);
		if (!getthread(ks->linux_regs, ks->threadid)) {
			error_packet(remcom_out_buffer, -EINVAL);
			break;
		}
		if ((int)ks->threadid > 0) {
			kgdb_mem2hex(getthread(ks->linux_regs,
					ks->threadid)->comm,
					remcom_out_buffer, 16);
		} else {
			static char tmpstr[23 + BUF_THREAD_ID_SIZE];

			sprintf(tmpstr, "shadowCPU%d",
					(int)(-ks->threadid - 2));
			kgdb_mem2hex(tmpstr, remcom_out_buffer, strlen(tmpstr));
		}
		break;
#ifdef CONFIG_KGDB_KDB
	case 'R':
		if (strncmp(remcom_in_buffer, "qRcmd,", 6) == 0) {
			int len = strlen(remcom_in_buffer + 6);

			if ((len % 2) != 0) {
				strcpy(remcom_out_buffer, "E01");
				break;
			}
			kgdb_hex2mem(remcom_in_buffer + 6,
				     remcom_out_buffer, len);
			len = len / 2;
			remcom_out_buffer[len++] = 0;

			kdb_common_init_state(ks);
			kdb_parse(remcom_out_buffer);
			kdb_common_deinit_state();

			strcpy(remcom_out_buffer, "OK");
		}
		break;
#endif
#ifdef CONFIG_HAVE_ARCH_KGDB_QXFER_PKT
	case 'S':
		if (!strncmp(remcom_in_buffer, "qSupported:", 11))
			strcpy(remcom_out_buffer, kgdb_arch_gdb_stub_feature);
		break;
	case 'X':
		if (!strncmp(remcom_in_buffer, "qXfer:", 6))
			kgdb_arch_handle_qxfer_pkt(remcom_in_buffer,
						   remcom_out_buffer);
		break;
#endif
	default:
		break;
	}
}

static void gdb_cmd_task(struct kgdb_state *ks)
{
	struct task_struct *thread;
	char *ptr;

	switch (remcom_in_buffer[1]) {
	case 'g':
		ptr = &remcom_in_buffer[2];
		kgdb_hex2long(&ptr, &ks->threadid);
		thread = getthread(ks->linux_regs, ks->threadid);
		if (!thread && ks->threadid > 0) {
			error_packet(remcom_out_buffer, -EINVAL);
			break;
		}
		kgdb_usethread = thread;
		ks->kgdb_usethreadid = ks->threadid;
		strcpy(remcom_out_buffer, "OK");
		break;
	case 'c':
		ptr = &remcom_in_buffer[2];
		kgdb_hex2long(&ptr, &ks->threadid);
		if (!ks->threadid) {
			kgdb_contthread = NULL;
		} else {
			thread = getthread(ks->linux_regs, ks->threadid);
			if (!thread && ks->threadid > 0) {
				error_packet(remcom_out_buffer, -EINVAL);
				break;
			}
			kgdb_contthread = thread;
		}
		strcpy(remcom_out_buffer, "OK");
		break;
	}
}

static void gdb_cmd_thread(struct kgdb_state *ks)
{
	char *ptr = &remcom_in_buffer[1];
	struct task_struct *thread;

	kgdb_hex2long(&ptr, &ks->threadid);
	thread = getthread(ks->linux_regs, ks->threadid);
	if (thread)
		strcpy(remcom_out_buffer, "OK");
	else
		error_packet(remcom_out_buffer, -EINVAL);
}

static void gdb_cmd_break(struct kgdb_state *ks)
{
	/*
	char *bpt_type = &remcom_in_buffer[1];
	char *ptr = &remcom_in_buffer[2];
	unsigned long addr;
	unsigned long length;
	int error = 0;

	if (arch_kgdb_ops.set_hw_breakpoint && *bpt_type >= '1') {
		/* Unsupported */
		if (*bpt_type > '4')
			return;
	} else {
		if (*bpt_type != '0' && *bpt_type != '1')
			/* Unsupported. */
			return;
	}

	/*
	if (*bpt_type == '1' && !(arch_kgdb_ops.flags & KGDB_HW_BREAKPOINT))
		/* Unsupported. */
		return;

	if (*(ptr++) != ',') {
		error_packet(remcom_out_buffer, -EINVAL);
		return;
	}
	if (!kgdb_hex2long(&ptr, &addr)) {
		error_packet(remcom_out_buffer, -EINVAL);
		return;
	}
	if (*(ptr++) != ',' ||
		!kgdb_hex2long(&ptr, &length)) {
		error_packet(remcom_out_buffer, -EINVAL);
		return;
	}

	if (remcom_in_buffer[0] == 'Z' && *bpt_type == '0')
		error = dbg_set_sw_break(addr);
	else if (remcom_in_buffer[0] == 'z' && *bpt_type == '0')
		error = dbg_remove_sw_break(addr);
	else if (remcom_in_buffer[0] == 'Z')
		error = arch_kgdb_ops.set_hw_breakpoint(addr,
			(int)length, *bpt_type - '0');
	else if (remcom_in_buffer[0] == 'z')
		error = arch_kgdb_ops.remove_hw_breakpoint(addr,
			(int) length, *bpt_type - '0');

	if (error == 0)
		strcpy(remcom_out_buffer, "OK");
	else
		error_packet(remcom_out_buffer, error);
}

static int gdb_cmd_exception_pass(struct kgdb_state *ks)
{
	/* C09 == pass exception
	 * C15 == detach kgdb, pass exception
	 */
	if (remcom_in_buffer[1] == '0' && remcom_in_buffer[2] == '9') {

		ks->pass_exception = 1;
		remcom_in_buffer[0] = 'c';

	} else if (remcom_in_buffer[1] == '1' && remcom_in_buffer[2] == '5') {

		ks->pass_exception = 1;
		remcom_in_buffer[0] = 'D';
		dbg_remove_all_break();
		kgdb_connected = 0;
		return 1;

	} else {
		gdbstub_msg_write("KGDB only knows signal 9 (pass)"
			" and 15 (pass and disconnect)\n"
			"Executing a continue without signal passing\n", 0);
		remcom_in_buffer[0] = 'c';
	}

	/* Indicate fall through */
	return -1;
}

int gdb_serial_stub(struct kgdb_state *ks)
{
	int error = 0;
	int tmp;

	/* Initialize comm buffer and globals. */
	memset(remcom_out_buffer, 0, sizeof(remcom_out_buffer));
	kgdb_usethread = kgdb_info[ks->cpu].task;
	ks->kgdb_usethreadid = shadow_pid(kgdb_info[ks->cpu].task->pid);
	ks->pass_exception = 0;

	if (kgdb_connected) {
		unsigned char thref[BUF_THREAD_ID_SIZE];
		char *ptr;

		/* Reply to host that an exception has occurred */
		ptr = remcom_out_buffer;
		*ptr++ = 'T';
		ptr = hex_byte_pack(ptr, ks->signo);
		ptr += strlen(strcpy(ptr, "thread:"));
		int_to_threadref(thref, shadow_pid(current->pid));
		ptr = pack_threadid(ptr, thref);
		*ptr++ = ';';
		put_packet(remcom_out_buffer);
	}

	while (1) {
		error = 0;

		/* Clear the out buffer. */
		memset(remcom_out_buffer, 0, sizeof(remcom_out_buffer));

		get_packet(remcom_in_buffer);

		switch (remcom_in_buffer[0]) {
		case '?': /* gdbserial status */
			gdb_cmd_status(ks);
			break;
		case 'g': /* return the value of the CPU registers */
			gdb_cmd_getregs(ks);
			break;
		case 'G': /* set the value of the CPU registers - return OK */
			gdb_cmd_setregs(ks);
			break;
		case 'm': /* mAA..AA,LLLL  Read LLLL bytes at address AA..AA */
			gdb_cmd_memread(ks);
			break;
		case 'M': /* MAA..AA,LLLL: Write LLLL bytes at address AA..AA */
			gdb_cmd_memwrite(ks);
			break;
#if DBG_MAX_REG_NUM > 0
		case 'p': /* pXX Return gdb register XX (in hex) */
			gdb_cmd_reg_get(ks);
			break;
		case 'P': /* PXX=aaaa Set gdb register XX to aaaa (in hex) */
			gdb_cmd_reg_set(ks);
			break;
#endif /* DBG_MAX_REG_NUM > 0 */
		case 'X': /* XAA..AA,LLLL: Write LLLL bytes at address AA..AA */
			gdb_cmd_binwrite(ks);
			break;
			/* kill or detach. KGDB should treat this like a
			 * continue.
			 */
		case 'D': /* Debugger detach */
		case 'k': /* Debugger detach via kill */
			gdb_cmd_detachkill(ks);
			goto default_handle;
		case 'R': /* Reboot */
			if (gdb_cmd_reboot(ks))
				goto default_handle;
			break;
		case 'q': /* query command */
			gdb_cmd_query(ks);
			break;
		case 'H': /* task related */
			gdb_cmd_task(ks);
			break;
		case 'T': /* Query thread status */
			gdb_cmd_thread(ks);
			break;
		case 'z': /* Break point remove */
		case 'Z': /* Break point set */
			gdb_cmd_break(ks);
			break;
#ifdef CONFIG_KGDB_KDB
		case '3': /* Escape into back into kdb */
			if (remcom_in_buffer[1] == '\0') {
				gdb_cmd_detachkill(ks);
				return DBG_PASS_EVENT;
			}
			fallthrough;
#endif
		case 'C': /* Exception passing */
			tmp = gdb_cmd_exception_pass(ks);
			if (tmp > 0)
				goto default_handle;
			if (tmp == 0)
				break;
			fallthrough;	/* on tmp < 0 */
		case 'c': /* Continue packet */
		case 's': /* Single step packet */
			if (kgdb_contthread && kgdb_contthread != current) {
				/* Can't switch threads in kgdb */
				error_packet(remcom_out_buffer, -EINVAL);
				break;
			}
			fallthrough;	/* to default processing */
		default:
default_handle:
			error = kgdb_arch_handle_exception(ks->ex_vector,
						ks->signo,
						ks->err_code,
						remcom_in_buffer,
						remcom_out_buffer,
						ks->linux_regs);
			/*
			if (error >= 0 || remcom_in_buffer[0] == 'D' ||
			    remcom_in_buffer[0] == 'k') {
				error = 0;
				goto kgdb_exit;
			}

		}

		/* reply to the request */
		put_packet(remcom_out_buffer);
	}

kgdb_exit:
	if (ks->pass_exception)
		error = 1;
	return error;
}

int gdbstub_state(struct kgdb_state *ks, char *cmd)
{
	int error;

	switch (cmd[0]) {
	case 'e':
		error = kgdb_arch_handle_exception(ks->ex_vector,
						   ks->signo,
						   ks->err_code,
						   remcom_in_buffer,
						   remcom_out_buffer,
						   ks->linux_regs);
		return error;
	case 's':
	case 'c':
		strscpy(remcom_in_buffer, cmd, sizeof(remcom_in_buffer));
		return 0;
	case '$':
		strscpy(remcom_in_buffer, cmd, sizeof(remcom_in_buffer));
		gdbstub_use_prev_in_buf = strlen(remcom_in_buffer);
		gdbstub_prev_in_buf_pos = 0;
		return 0;
	}
	dbg_io_ops->write_char('+');
	put_packet(remcom_out_buffer);
	return 0;
}

void gdbstub_exit(int status)
{
	unsigned char checksum, ch, buffer[3];
	int loop;

	if (!kgdb_connected)
		return;
	kgdb_connected = 0;

	if (!dbg_io_ops || dbg_kdb_mode)
		return;

	buffer[0] = 'W';
	buffer[1] = hex_asc_hi(status);
	buffer[2] = hex_asc_lo(status);

	dbg_io_ops->write_char('$');
	checksum = 0;

	for (loop = 0; loop < 3; loop++) {
		ch = buffer[loop];
		checksum += ch;
		dbg_io_ops->write_char(ch);
	}

	dbg_io_ops->write_char('#');
	dbg_io_ops->write_char(hex_asc_hi(checksum));
	dbg_io_ops->write_char(hex_asc_lo(checksum));

	/* make sure the output is flushed, lest the bootloader clobber it */
	if (dbg_io_ops->flush)
		dbg_io_ops->flush();
}
