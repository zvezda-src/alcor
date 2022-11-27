
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/tty.h>
#include <linux/tty_driver.h>
#include <linux/console.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/nmi.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/delay.h>
#include <linux/smp.h>
#include <linux/security.h>
#include <linux/memblock.h>
#include <linux/syscalls.h>
#include <linux/crash_core.h>
#include <linux/ratelimit.h>
#include <linux/kmsg_dump.h>
#include <linux/syslog.h>
#include <linux/cpu.h>
#include <linux/rculist.h>
#include <linux/poll.h>
#include <linux/irq_work.h>
#include <linux/ctype.h>
#include <linux/uio.h>
#include <linux/sched/clock.h>
#include <linux/sched/debug.h>
#include <linux/sched/task_stack.h>

#include <linux/uaccess.h>
#include <asm/sections.h>

#include <trace/events/initcall.h>
#define CREATE_TRACE_POINTS
#include <trace/events/printk.h>

#include "printk_ringbuffer.h"
#include "console_cmdline.h"
#include "braille.h"
#include "internal.h"

int console_printk[4] = {
	CONSOLE_LOGLEVEL_DEFAULT,	/* console_loglevel */
	MESSAGE_LOGLEVEL_DEFAULT,	/* default_message_loglevel */
	CONSOLE_LOGLEVEL_MIN,		/* minimum_console_loglevel */
	CONSOLE_LOGLEVEL_DEFAULT,	/* default_console_loglevel */
};
EXPORT_SYMBOL_GPL(console_printk);

atomic_t ignore_console_lock_warning __read_mostly = ATOMIC_INIT(0);
EXPORT_SYMBOL(ignore_console_lock_warning);

int oops_in_progress;
EXPORT_SYMBOL(oops_in_progress);

static DEFINE_SEMAPHORE(console_sem);
struct console *console_drivers;
EXPORT_SYMBOL_GPL(console_drivers);

int __read_mostly suppress_printk;

static int __read_mostly suppress_panic_printk;

#ifdef CONFIG_LOCKDEP
static struct lockdep_map console_lock_dep_map = {
	.name = "console_lock"
};
#endif

enum devkmsg_log_bits {
	__DEVKMSG_LOG_BIT_ON = 0,
	__DEVKMSG_LOG_BIT_OFF,
	__DEVKMSG_LOG_BIT_LOCK,
};

enum devkmsg_log_masks {
	DEVKMSG_LOG_MASK_ON             = BIT(__DEVKMSG_LOG_BIT_ON),
	DEVKMSG_LOG_MASK_OFF            = BIT(__DEVKMSG_LOG_BIT_OFF),
	DEVKMSG_LOG_MASK_LOCK           = BIT(__DEVKMSG_LOG_BIT_LOCK),
};

#define DEVKMSG_LOG_MASK_DEFAULT	0

static unsigned int __read_mostly devkmsg_log = DEVKMSG_LOG_MASK_DEFAULT;

static int __control_devkmsg(char *str)
{
	size_t len;

	if (!str)
		return -EINVAL;

	len = str_has_prefix(str, "on");
	if (len) {
		devkmsg_log = DEVKMSG_LOG_MASK_ON;
		return len;
	}

	len = str_has_prefix(str, "off");
	if (len) {
		devkmsg_log = DEVKMSG_LOG_MASK_OFF;
		return len;
	}

	len = str_has_prefix(str, "ratelimit");
	if (len) {
		devkmsg_log = DEVKMSG_LOG_MASK_DEFAULT;
		return len;
	}

	return -EINVAL;
}

static int __init control_devkmsg(char *str)
{
	if (__control_devkmsg(str) < 0) {
		pr_warn("printk.devkmsg: bad option string '%s'\n", str);
		return 1;
	}

	/*
	if (devkmsg_log == DEVKMSG_LOG_MASK_ON)
		strcpy(devkmsg_log_str, "on");
	else if (devkmsg_log == DEVKMSG_LOG_MASK_OFF)
		strcpy(devkmsg_log_str, "off");
	/* else "ratelimit" which is set by default. */

	/*
	devkmsg_log |= DEVKMSG_LOG_MASK_LOCK;

	return 1;
}
__setup("printk.devkmsg=", control_devkmsg);

char devkmsg_log_str[DEVKMSG_STR_MAX_SIZE] = "ratelimit";
#if defined(CONFIG_PRINTK) && defined(CONFIG_SYSCTL)
int devkmsg_sysctl_set_loglvl(struct ctl_table *table, int write,
			      void *buffer, size_t *lenp, loff_t *ppos)
{
	char old_str[DEVKMSG_STR_MAX_SIZE];
	unsigned int old;
	int err;

	if (write) {
		if (devkmsg_log & DEVKMSG_LOG_MASK_LOCK)
			return -EINVAL;

		old = devkmsg_log;
		strncpy(old_str, devkmsg_log_str, DEVKMSG_STR_MAX_SIZE);
	}

	err = proc_dostring(table, write, buffer, lenp, ppos);
	if (err)
		return err;

	if (write) {
		err = __control_devkmsg(devkmsg_log_str);

		/*
		if (err < 0 || (err + 1 != *lenp)) {

			/* ... and restore old setting. */
			devkmsg_log = old;
			strncpy(devkmsg_log_str, old_str, DEVKMSG_STR_MAX_SIZE);

			return -EINVAL;
		}
	}

	return 0;
}
#endif /* CONFIG_PRINTK && CONFIG_SYSCTL */

static int nr_ext_console_drivers;

#define down_console_sem() do { \
	down(&console_sem);\
	mutex_acquire(&console_lock_dep_map, 0, 0, _RET_IP_);\
} while (0)

static int __down_trylock_console_sem(unsigned long ip)
{
	int lock_failed;
	unsigned long flags;

	/*
	printk_safe_enter_irqsave(flags);
	lock_failed = down_trylock(&console_sem);
	printk_safe_exit_irqrestore(flags);

	if (lock_failed)
		return 1;
	mutex_acquire(&console_lock_dep_map, 0, 1, ip);
	return 0;
}
#define down_trylock_console_sem() __down_trylock_console_sem(_RET_IP_)

static void __up_console_sem(unsigned long ip)
{
	unsigned long flags;

	mutex_release(&console_lock_dep_map, ip);

	printk_safe_enter_irqsave(flags);
	up(&console_sem);
	printk_safe_exit_irqrestore(flags);
}
#define up_console_sem() __up_console_sem(_RET_IP_)

static bool panic_in_progress(void)
{
	return unlikely(atomic_read(&panic_cpu) != PANIC_CPU_INVALID);
}

static int console_locked, console_suspended;


#define MAX_CMDLINECONSOLES 8

static struct console_cmdline console_cmdline[MAX_CMDLINECONSOLES];

static int preferred_console = -1;
int console_set_on_cmdline;
EXPORT_SYMBOL(console_set_on_cmdline);

static int console_may_schedule;

enum con_msg_format_flags {
	MSG_FORMAT_DEFAULT	= 0,
	MSG_FORMAT_SYSLOG	= (1 << 0),
};

static int console_msg_format = MSG_FORMAT_DEFAULT;


static DEFINE_MUTEX(syslog_lock);

#ifdef CONFIG_PRINTK
DECLARE_WAIT_QUEUE_HEAD(log_wait);
static u64 syslog_seq;
static size_t syslog_partial;
static bool syslog_time;

struct latched_seq {
	seqcount_latch_t	latch;
	u64			val[2];
};

static struct latched_seq clear_seq = {
	.latch		= SEQCNT_LATCH_ZERO(clear_seq.latch),
	.val[0]		= 0,
	.val[1]		= 0,
};

#ifdef CONFIG_PRINTK_CALLER
#define PREFIX_MAX		48
#else
#define PREFIX_MAX		32
#endif

#define CONSOLE_LOG_MAX		1024

#define DROPPED_TEXT_MAX	64

#define LOG_LINE_MAX		(CONSOLE_LOG_MAX - PREFIX_MAX)

#define LOG_LEVEL(v)		((v) & 0x07)
#define LOG_FACILITY(v)		((v) >> 3 & 0xff)

#define LOG_ALIGN __alignof__(unsigned long)
#define __LOG_BUF_LEN (1 << CONFIG_LOG_BUF_SHIFT)
#define LOG_BUF_LEN_MAX (u32)(1 << 31)
static char __log_buf[__LOG_BUF_LEN] __aligned(LOG_ALIGN);
static char *log_buf = __log_buf;
static u32 log_buf_len = __LOG_BUF_LEN;

#define PRB_AVGBITS 5	/* 32 character average length */

#if CONFIG_LOG_BUF_SHIFT <= PRB_AVGBITS
#error CONFIG_LOG_BUF_SHIFT value too small.
#endif
_DEFINE_PRINTKRB(printk_rb_static, CONFIG_LOG_BUF_SHIFT - PRB_AVGBITS,
		 PRB_AVGBITS, &__log_buf[0]);

static struct printk_ringbuffer printk_rb_dynamic;

static struct printk_ringbuffer *prb = &printk_rb_static;

static bool __printk_percpu_data_ready __read_mostly;

bool printk_percpu_data_ready(void)
{
	return __printk_percpu_data_ready;
}

static void latched_seq_write(struct latched_seq *ls, u64 val)
{
	raw_write_seqcount_latch(&ls->latch);
	ls->val[0] = val;
	raw_write_seqcount_latch(&ls->latch);
	ls->val[1] = val;
}

static u64 latched_seq_read_nolock(struct latched_seq *ls)
{
	unsigned int seq;
	unsigned int idx;
	u64 val;

	do {
		seq = raw_read_seqcount_latch(&ls->latch);
		idx = seq & 0x1;
		val = ls->val[idx];
	} while (read_seqcount_latch_retry(&ls->latch, seq));

	return val;
}

char *log_buf_addr_get(void)
{
	return log_buf;
}

u32 log_buf_len_get(void)
{
	return log_buf_len;
}

#define MAX_LOG_TAKE_PART 4
static const char trunc_msg[] = "<truncated>";

static void truncate_msg(u16 *text_len, u16 *trunc_msg_len)
{
	/*
	u32 max_text_len = log_buf_len / MAX_LOG_TAKE_PART;

	if (*text_len > max_text_len)
		*text_len = max_text_len;

	/* enable the warning message (if there is room) */
	if (*text_len >= *trunc_msg_len)
		*text_len -= *trunc_msg_len;
	else
		*trunc_msg_len = 0;
}

int dmesg_restrict = IS_ENABLED(CONFIG_SECURITY_DMESG_RESTRICT);

static int syslog_action_restricted(int type)
{
	if (dmesg_restrict)
		return 1;
	/*
	return type != SYSLOG_ACTION_READ_ALL &&
	       type != SYSLOG_ACTION_SIZE_BUFFER;
}

static int check_syslog_permissions(int type, int source)
{
	/*
	if (source == SYSLOG_FROM_PROC && type != SYSLOG_ACTION_OPEN)
		goto ok;

	if (syslog_action_restricted(type)) {
		if (capable(CAP_SYSLOG))
			goto ok;
		/*
		if (capable(CAP_SYS_ADMIN)) {
			pr_warn_once("%s (%d): Attempt to access syslog with "
				     "CAP_SYS_ADMIN but no CAP_SYSLOG "
				     "(deprecated).\n",
				 current->comm, task_pid_nr(current));
			goto ok;
		}
		return -EPERM;
	}
ok:
	return security_syslog(type);
}

static void append_char(char **pp, char *e, char c)
{
	if (*pp < e)
		*(*pp)++ = c;
}

static ssize_t info_print_ext_header(char *buf, size_t size,
				     struct printk_info *info)
{
	u64 ts_usec = info->ts_nsec;
	char caller[20];
#ifdef CONFIG_PRINTK_CALLER
	u32 id = info->caller_id;

	snprintf(caller, sizeof(caller), ",caller=%c%u",
		 id & 0x80000000 ? 'C' : 'T', id & ~0x80000000);
#else
	caller[0] = '\0';
#endif

	do_div(ts_usec, 1000);

	return scnprintf(buf, size, "%u,%llu,%llu,%c%s;",
			 (info->facility << 3) | info->level, info->seq,
			 ts_usec, info->flags & LOG_CONT ? 'c' : '-', caller);
}

static ssize_t msg_add_ext_text(char *buf, size_t size,
				const char *text, size_t text_len,
				unsigned char endc)
{
	char *p = buf, *e = buf + size;
	size_t i;

	/* escape non-printable characters */
	for (i = 0; i < text_len; i++) {
		unsigned char c = text[i];

		if (c < ' ' || c >= 127 || c == '\\')
			p += scnprintf(p, e - p, "\\x%02x", c);
		else
			append_char(&p, e, c);
	}
	append_char(&p, e, endc);

	return p - buf;
}

static ssize_t msg_add_dict_text(char *buf, size_t size,
				 const char *key, const char *val)
{
	size_t val_len = strlen(val);
	ssize_t len;

	if (!val_len)
		return 0;

	len = msg_add_ext_text(buf, size, "", 0, ' ');	/* dict prefix */
	len += msg_add_ext_text(buf + len, size - len, key, strlen(key), '=');
	len += msg_add_ext_text(buf + len, size - len, val, val_len, '\n');

	return len;
}

static ssize_t msg_print_ext_body(char *buf, size_t size,
				  char *text, size_t text_len,
				  struct dev_printk_info *dev_info)
{
	ssize_t len;

	len = msg_add_ext_text(buf, size, text, text_len, '\n');

	if (!dev_info)
		goto out;

	len += msg_add_dict_text(buf + len, size - len, "SUBSYSTEM",
				 dev_info->subsystem);
	len += msg_add_dict_text(buf + len, size - len, "DEVICE",
				 dev_info->device);
out:
	return len;
}

struct devkmsg_user {
	atomic64_t seq;
	struct ratelimit_state rs;
	struct mutex lock;
	char buf[CONSOLE_EXT_LOG_MAX];

	struct printk_info info;
	char text_buf[CONSOLE_EXT_LOG_MAX];
	struct printk_record record;
};

static __printf(3, 4) __cold
int devkmsg_emit(int facility, int level, const char *fmt, ...)
{
	va_list args;
	int r;

	va_start(args, fmt);
	r = vprintk_emit(facility, level, NULL, fmt, args);
	va_end(args);

	return r;
}

static ssize_t devkmsg_write(struct kiocb *iocb, struct iov_iter *from)
{
	char *buf, *line;
	int level = default_message_loglevel;
	int facility = 1;	/* LOG_USER */
	struct file *file = iocb->ki_filp;
	struct devkmsg_user *user = file->private_data;
	size_t len = iov_iter_count(from);
	ssize_t ret = len;

	if (!user || len > LOG_LINE_MAX)
		return -EINVAL;

	/* Ignore when user logging is disabled. */
	if (devkmsg_log & DEVKMSG_LOG_MASK_OFF)
		return len;

	/* Ratelimit when not explicitly enabled. */
	if (!(devkmsg_log & DEVKMSG_LOG_MASK_ON)) {
		if (!___ratelimit(&user->rs, current->comm))
			return ret;
	}

	buf = kmalloc(len+1, GFP_KERNEL);
	if (buf == NULL)
		return -ENOMEM;

	buf[len] = '\0';
	if (!copy_from_iter_full(buf, len, from)) {
		kfree(buf);
		return -EFAULT;
	}

	/*
	line = buf;
	if (line[0] == '<') {
		char *endp = NULL;
		unsigned int u;

		u = simple_strtoul(line + 1, &endp, 10);
		if (endp && endp[0] == '>') {
			level = LOG_LEVEL(u);
			if (LOG_FACILITY(u) != 0)
				facility = LOG_FACILITY(u);
			endp++;
			line = endp;
		}
	}

	devkmsg_emit(facility, level, "%s", line);
	kfree(buf);
	return ret;
}

static ssize_t devkmsg_read(struct file *file, char __user *buf,
			    size_t count, loff_t *ppos)
{
	struct devkmsg_user *user = file->private_data;
	struct printk_record *r = &user->record;
	size_t len;
	ssize_t ret;

	if (!user)
		return -EBADF;

	ret = mutex_lock_interruptible(&user->lock);
	if (ret)
		return ret;

	if (!prb_read_valid(prb, atomic64_read(&user->seq), r)) {
		if (file->f_flags & O_NONBLOCK) {
			ret = -EAGAIN;
			goto out;
		}

		/*
		ret = wait_event_interruptible(log_wait,
				prb_read_valid(prb,
					atomic64_read(&user->seq), r)); /* LMM(devkmsg_read:A) */
		if (ret)
			goto out;
	}

	if (r->info->seq != atomic64_read(&user->seq)) {
		/* our last seen message is gone, return error and reset */
		atomic64_set(&user->seq, r->info->seq);
		ret = -EPIPE;
		goto out;
	}

	len = info_print_ext_header(user->buf, sizeof(user->buf), r->info);
	len += msg_print_ext_body(user->buf + len, sizeof(user->buf) - len,
				  &r->text_buf[0], r->info->text_len,
				  &r->info->dev_info);

	atomic64_set(&user->seq, r->info->seq + 1);

	if (len > count) {
		ret = -EINVAL;
		goto out;
	}

	if (copy_to_user(buf, user->buf, len)) {
		ret = -EFAULT;
		goto out;
	}
	ret = len;
out:
	mutex_unlock(&user->lock);
	return ret;
}

static loff_t devkmsg_llseek(struct file *file, loff_t offset, int whence)
{
	struct devkmsg_user *user = file->private_data;
	loff_t ret = 0;

	if (!user)
		return -EBADF;
	if (offset)
		return -ESPIPE;

	switch (whence) {
	case SEEK_SET:
		/* the first record */
		atomic64_set(&user->seq, prb_first_valid_seq(prb));
		break;
	case SEEK_DATA:
		/*
		atomic64_set(&user->seq, latched_seq_read_nolock(&clear_seq));
		break;
	case SEEK_END:
		/* after the last record */
		atomic64_set(&user->seq, prb_next_seq(prb));
		break;
	default:
		ret = -EINVAL;
	}
	return ret;
}

static __poll_t devkmsg_poll(struct file *file, poll_table *wait)
{
	struct devkmsg_user *user = file->private_data;
	struct printk_info info;
	__poll_t ret = 0;

	if (!user)
		return EPOLLERR|EPOLLNVAL;

	poll_wait(file, &log_wait, wait);

	if (prb_read_valid_info(prb, atomic64_read(&user->seq), &info, NULL)) {
		/* return error when data has vanished underneath us */
		if (info.seq != atomic64_read(&user->seq))
			ret = EPOLLIN|EPOLLRDNORM|EPOLLERR|EPOLLPRI;
		else
			ret = EPOLLIN|EPOLLRDNORM;
	}

	return ret;
}

static int devkmsg_open(struct inode *inode, struct file *file)
{
	struct devkmsg_user *user;
	int err;

	if (devkmsg_log & DEVKMSG_LOG_MASK_OFF)
		return -EPERM;

	/* write-only does not need any file context */
	if ((file->f_flags & O_ACCMODE) != O_WRONLY) {
		err = check_syslog_permissions(SYSLOG_ACTION_READ_ALL,
					       SYSLOG_FROM_READER);
		if (err)
			return err;
	}

	user = kvmalloc(sizeof(struct devkmsg_user), GFP_KERNEL);
	if (!user)
		return -ENOMEM;

	ratelimit_default_init(&user->rs);
	ratelimit_set_flags(&user->rs, RATELIMIT_MSG_ON_RELEASE);

	mutex_init(&user->lock);

	prb_rec_init_rd(&user->record, &user->info,
			&user->text_buf[0], sizeof(user->text_buf));

	atomic64_set(&user->seq, prb_first_valid_seq(prb));

	file->private_data = user;
	return 0;
}

static int devkmsg_release(struct inode *inode, struct file *file)
{
	struct devkmsg_user *user = file->private_data;

	if (!user)
		return 0;

	ratelimit_state_exit(&user->rs);

	mutex_destroy(&user->lock);
	kvfree(user);
	return 0;
}

const struct file_operations kmsg_fops = {
	.open = devkmsg_open,
	.read = devkmsg_read,
	.write_iter = devkmsg_write,
	.llseek = devkmsg_llseek,
	.poll = devkmsg_poll,
	.release = devkmsg_release,
};

#ifdef CONFIG_CRASH_CORE
void log_buf_vmcoreinfo_setup(void)
{
	struct dev_printk_info *dev_info = NULL;

	VMCOREINFO_SYMBOL(prb);
	VMCOREINFO_SYMBOL(printk_rb_static);
	VMCOREINFO_SYMBOL(clear_seq);

	/*

	VMCOREINFO_STRUCT_SIZE(printk_ringbuffer);
	VMCOREINFO_OFFSET(printk_ringbuffer, desc_ring);
	VMCOREINFO_OFFSET(printk_ringbuffer, text_data_ring);
	VMCOREINFO_OFFSET(printk_ringbuffer, fail);

	VMCOREINFO_STRUCT_SIZE(prb_desc_ring);
	VMCOREINFO_OFFSET(prb_desc_ring, count_bits);
	VMCOREINFO_OFFSET(prb_desc_ring, descs);
	VMCOREINFO_OFFSET(prb_desc_ring, infos);
	VMCOREINFO_OFFSET(prb_desc_ring, head_id);
	VMCOREINFO_OFFSET(prb_desc_ring, tail_id);

	VMCOREINFO_STRUCT_SIZE(prb_desc);
	VMCOREINFO_OFFSET(prb_desc, state_var);
	VMCOREINFO_OFFSET(prb_desc, text_blk_lpos);

	VMCOREINFO_STRUCT_SIZE(prb_data_blk_lpos);
	VMCOREINFO_OFFSET(prb_data_blk_lpos, begin);
	VMCOREINFO_OFFSET(prb_data_blk_lpos, next);

	VMCOREINFO_STRUCT_SIZE(printk_info);
	VMCOREINFO_OFFSET(printk_info, seq);
	VMCOREINFO_OFFSET(printk_info, ts_nsec);
	VMCOREINFO_OFFSET(printk_info, text_len);
	VMCOREINFO_OFFSET(printk_info, caller_id);
	VMCOREINFO_OFFSET(printk_info, dev_info);

	VMCOREINFO_STRUCT_SIZE(dev_printk_info);
	VMCOREINFO_OFFSET(dev_printk_info, subsystem);
	VMCOREINFO_LENGTH(printk_info_subsystem, sizeof(dev_info->subsystem));
	VMCOREINFO_OFFSET(dev_printk_info, device);
	VMCOREINFO_LENGTH(printk_info_device, sizeof(dev_info->device));

	VMCOREINFO_STRUCT_SIZE(prb_data_ring);
	VMCOREINFO_OFFSET(prb_data_ring, size_bits);
	VMCOREINFO_OFFSET(prb_data_ring, data);
	VMCOREINFO_OFFSET(prb_data_ring, head_lpos);
	VMCOREINFO_OFFSET(prb_data_ring, tail_lpos);

	VMCOREINFO_SIZE(atomic_long_t);
	VMCOREINFO_TYPE_OFFSET(atomic_long_t, counter);

	VMCOREINFO_STRUCT_SIZE(latched_seq);
	VMCOREINFO_OFFSET(latched_seq, val);
}
#endif

static unsigned long __initdata new_log_buf_len;

static void __init log_buf_len_update(u64 size)
{
	if (size > (u64)LOG_BUF_LEN_MAX) {
		size = (u64)LOG_BUF_LEN_MAX;
		pr_err("log_buf over 2G is not supported.\n");
	}

	if (size)
		size = roundup_pow_of_two(size);
	if (size > log_buf_len)
		new_log_buf_len = (unsigned long)size;
}

static int __init log_buf_len_setup(char *str)
{
	u64 size;

	if (!str)
		return -EINVAL;

	size = memparse(str, &str);

	log_buf_len_update(size);

	return 0;
}
early_param("log_buf_len", log_buf_len_setup);

#ifdef CONFIG_SMP
#define __LOG_CPU_MAX_BUF_LEN (1 << CONFIG_LOG_CPU_MAX_BUF_SHIFT)

static void __init log_buf_add_cpu(void)
{
	unsigned int cpu_extra;

	/*
	if (num_possible_cpus() == 1)
		return;

	cpu_extra = (num_possible_cpus() - 1) * __LOG_CPU_MAX_BUF_LEN;

	/* by default this will only continue through for large > 64 CPUs */
	if (cpu_extra <= __LOG_BUF_LEN / 2)
		return;

	pr_info("log_buf_len individual max cpu contribution: %d bytes\n",
		__LOG_CPU_MAX_BUF_LEN);
	pr_info("log_buf_len total cpu_extra contributions: %d bytes\n",
		cpu_extra);
	pr_info("log_buf_len min size: %d bytes\n", __LOG_BUF_LEN);

	log_buf_len_update(cpu_extra + __LOG_BUF_LEN);
}
#else /* !CONFIG_SMP */
static inline void log_buf_add_cpu(void) {}
#endif /* CONFIG_SMP */

static void __init set_percpu_data_ready(void)
{
	__printk_percpu_data_ready = true;
}

static unsigned int __init add_to_rb(struct printk_ringbuffer *rb,
				     struct printk_record *r)
{
	struct prb_reserved_entry e;
	struct printk_record dest_r;

	prb_rec_init_wr(&dest_r, r->info->text_len);

	if (!prb_reserve(&e, rb, &dest_r))
		return 0;

	memcpy(&dest_r.text_buf[0], &r->text_buf[0], r->info->text_len);
	dest_r.info->text_len = r->info->text_len;
	dest_r.info->facility = r->info->facility;
	dest_r.info->level = r->info->level;
	dest_r.info->flags = r->info->flags;
	dest_r.info->ts_nsec = r->info->ts_nsec;
	dest_r.info->caller_id = r->info->caller_id;
	memcpy(&dest_r.info->dev_info, &r->info->dev_info, sizeof(dest_r.info->dev_info));

	prb_final_commit(&e);

	return prb_record_text_space(&e);
}

static char setup_text_buf[LOG_LINE_MAX] __initdata;

void __init setup_log_buf(int early)
{
	struct printk_info *new_infos;
	unsigned int new_descs_count;
	struct prb_desc *new_descs;
	struct printk_info info;
	struct printk_record r;
	unsigned int text_size;
	size_t new_descs_size;
	size_t new_infos_size;
	unsigned long flags;
	char *new_log_buf;
	unsigned int free;
	u64 seq;

	/*
	if (!early)
		set_percpu_data_ready();

	if (log_buf != __log_buf)
		return;

	if (!early && !new_log_buf_len)
		log_buf_add_cpu();

	if (!new_log_buf_len)
		return;

	new_descs_count = new_log_buf_len >> PRB_AVGBITS;
	if (new_descs_count == 0) {
		pr_err("new_log_buf_len: %lu too small\n", new_log_buf_len);
		return;
	}

	new_log_buf = memblock_alloc(new_log_buf_len, LOG_ALIGN);
	if (unlikely(!new_log_buf)) {
		pr_err("log_buf_len: %lu text bytes not available\n",
		       new_log_buf_len);
		return;
	}

	new_descs_size = new_descs_count * sizeof(struct prb_desc);
	new_descs = memblock_alloc(new_descs_size, LOG_ALIGN);
	if (unlikely(!new_descs)) {
		pr_err("log_buf_len: %zu desc bytes not available\n",
		       new_descs_size);
		goto err_free_log_buf;
	}

	new_infos_size = new_descs_count * sizeof(struct printk_info);
	new_infos = memblock_alloc(new_infos_size, LOG_ALIGN);
	if (unlikely(!new_infos)) {
		pr_err("log_buf_len: %zu info bytes not available\n",
		       new_infos_size);
		goto err_free_descs;
	}

	prb_rec_init_rd(&r, &info, &setup_text_buf[0], sizeof(setup_text_buf));

	prb_init(&printk_rb_dynamic,
		 new_log_buf, ilog2(new_log_buf_len),
		 new_descs, ilog2(new_descs_count),
		 new_infos);

	local_irq_save(flags);

	log_buf_len = new_log_buf_len;
	log_buf = new_log_buf;
	new_log_buf_len = 0;

	free = __LOG_BUF_LEN;
	prb_for_each_record(0, &printk_rb_static, seq, &r) {
		text_size = add_to_rb(&printk_rb_dynamic, &r);
		if (text_size > free)
			free = 0;
		else
			free -= text_size;
	}

	prb = &printk_rb_dynamic;

	local_irq_restore(flags);

	/*
	prb_for_each_record(seq, &printk_rb_static, seq, &r) {
		text_size = add_to_rb(&printk_rb_dynamic, &r);
		if (text_size > free)
			free = 0;
		else
			free -= text_size;
	}

	if (seq != prb_next_seq(&printk_rb_static)) {
		pr_err("dropped %llu messages\n",
		       prb_next_seq(&printk_rb_static) - seq);
	}

	pr_info("log_buf_len: %u bytes\n", log_buf_len);
	pr_info("early log buf free: %u(%u%%)\n",
		free, (free * 100) / __LOG_BUF_LEN);
	return;

err_free_descs:
	memblock_free(new_descs, new_descs_size);
err_free_log_buf:
	memblock_free(new_log_buf, new_log_buf_len);
}

static bool __read_mostly ignore_loglevel;

static int __init ignore_loglevel_setup(char *str)
{
	ignore_loglevel = true;
	pr_info("debug: ignoring loglevel setting.\n");

	return 0;
}

early_param("ignore_loglevel", ignore_loglevel_setup);
module_param(ignore_loglevel, bool, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(ignore_loglevel,
		 "ignore loglevel setting (prints all kernel messages to the console)");

static bool suppress_message_printing(int level)
{
	return (level >= console_loglevel && !ignore_loglevel);
}

#ifdef CONFIG_BOOT_PRINTK_DELAY

static int boot_delay; /* msecs delay after each printk during bootup */
static unsigned long long loops_per_msec;	/* based on boot_delay */

static int __init boot_delay_setup(char *str)
{
	unsigned long lpj;

	lpj = preset_lpj ? preset_lpj : 1000000;	/* some guess */
	loops_per_msec = (unsigned long long)lpj / 1000 * HZ;

	get_option(&str, &boot_delay);
	if (boot_delay > 10 * 1000)
		boot_delay = 0;

	pr_debug("boot_delay: %u, preset_lpj: %ld, lpj: %lu, "
		"HZ: %d, loops_per_msec: %llu\n",
		boot_delay, preset_lpj, lpj, HZ, loops_per_msec);
	return 0;
}
early_param("boot_delay", boot_delay_setup);

static void boot_delay_msec(int level)
{
	unsigned long long k;
	unsigned long timeout;

	if ((boot_delay == 0 || system_state >= SYSTEM_RUNNING)
		|| suppress_message_printing(level)) {
		return;
	}

	k = (unsigned long long)loops_per_msec * boot_delay;

	timeout = jiffies + msecs_to_jiffies(boot_delay);
	while (k) {
		k--;
		cpu_relax();
		/*
		if (time_after(jiffies, timeout))
			break;
		touch_nmi_watchdog();
	}
}
#else
static inline void boot_delay_msec(int level)
{
}
#endif

static bool printk_time = IS_ENABLED(CONFIG_PRINTK_TIME);
module_param_named(time, printk_time, bool, S_IRUGO | S_IWUSR);

static size_t print_syslog(unsigned int level, char *buf)
{
	return sprintf(buf, "<%u>", level);
}

static size_t print_time(u64 ts, char *buf)
{
	unsigned long rem_nsec = do_div(ts, 1000000000);

	return sprintf(buf, "[%5lu.%06lu]",
		       (unsigned long)ts, rem_nsec / 1000);
}

#ifdef CONFIG_PRINTK_CALLER
static size_t print_caller(u32 id, char *buf)
{
	char caller[12];

	snprintf(caller, sizeof(caller), "%c%u",
		 id & 0x80000000 ? 'C' : 'T', id & ~0x80000000);
	return sprintf(buf, "[%6s]", caller);
}
#else
#define print_caller(id, buf) 0
#endif

static size_t info_print_prefix(const struct printk_info  *info, bool syslog,
				bool time, char *buf)
{
	size_t len = 0;

	if (syslog)
		len = print_syslog((info->facility << 3) | info->level, buf);

	if (time)
		len += print_time(info->ts_nsec, buf + len);

	len += print_caller(info->caller_id, buf + len);

	if (IS_ENABLED(CONFIG_PRINTK_CALLER) || time) {
		buf[len++] = ' ';
		buf[len] = '\0';
	}

	return len;
}

static size_t record_print_text(struct printk_record *r, bool syslog,
				bool time)
{
	size_t text_len = r->info->text_len;
	size_t buf_size = r->text_buf_size;
	char *text = r->text_buf;
	char prefix[PREFIX_MAX];
	bool truncated = false;
	size_t prefix_len;
	size_t line_len;
	size_t len = 0;
	char *next;

	/*
	if (text_len > buf_size)
		text_len = buf_size;

	prefix_len = info_print_prefix(r->info, syslog, time, prefix);

	/*
	for (;;) {
		next = memchr(text, '\n', text_len);
		if (next) {
			line_len = next - text;
		} else {
			/* Drop truncated line(s). */
			if (truncated)
				break;
			line_len = text_len;
		}

		/*
		if (len + prefix_len + text_len + 1 + 1 > buf_size) {
			/* Drop even the current line if no space. */
			if (len + prefix_len + line_len + 1 + 1 > buf_size)
				break;

			text_len = buf_size - len - prefix_len - 1 - 1;
			truncated = true;
		}

		memmove(text + prefix_len, text, text_len);
		memcpy(text, prefix, prefix_len);

		/*
		len += prefix_len + line_len + 1;
		if (text_len == line_len) {
			/*
			text[prefix_len + line_len] = '\n';
			break;
		}

		/*
		text += prefix_len + line_len + 1;

		/*
		text_len -= line_len + 1;
	}

	/*
	if (buf_size > 0)
		r->text_buf[len] = 0;

	return len;
}

static size_t get_record_print_text_size(struct printk_info *info,
					 unsigned int line_count,
					 bool syslog, bool time)
{
	char prefix[PREFIX_MAX];
	size_t prefix_len;

	prefix_len = info_print_prefix(info, syslog, time, prefix);

	/*
	return ((prefix_len * line_count) + info->text_len + 1);
}

static u64 find_first_fitting_seq(u64 start_seq, u64 max_seq, size_t size,
				  bool syslog, bool time)
{
	struct printk_info info;
	unsigned int line_count;
	size_t len = 0;
	u64 seq;

	/* Determine the size of the records up to @max_seq. */
	prb_for_each_info(start_seq, prb, seq, &info, &line_count) {
		if (info.seq >= max_seq)
			break;
		len += get_record_print_text_size(&info, line_count, syslog, time);
	}

	/*
	if (seq < max_seq)
		max_seq = seq;

	/*
	prb_for_each_info(start_seq, prb, seq, &info, &line_count) {
		if (len <= size || info.seq >= max_seq)
			break;
		len -= get_record_print_text_size(&info, line_count, syslog, time);
	}

	return seq;
}

static int syslog_print(char __user *buf, int size)
{
	struct printk_info info;
	struct printk_record r;
	char *text;
	int len = 0;
	u64 seq;

	text = kmalloc(CONSOLE_LOG_MAX, GFP_KERNEL);
	if (!text)
		return -ENOMEM;

	prb_rec_init_rd(&r, &info, text, CONSOLE_LOG_MAX);

	mutex_lock(&syslog_lock);

	/*
	do {
		seq = syslog_seq;

		mutex_unlock(&syslog_lock);
		/*
		len = wait_event_interruptible(log_wait,
				prb_read_valid(prb, seq, NULL)); /* LMM(syslog_print:A) */
		mutex_lock(&syslog_lock);

		if (len)
			goto out;
	} while (syslog_seq != seq);

	/*
	do {
		size_t n;
		size_t skip;
		int err;

		if (!prb_read_valid(prb, syslog_seq, &r))
			break;

		if (r.info->seq != syslog_seq) {
			/* message is gone, move to next valid one */
			syslog_seq = r.info->seq;
			syslog_partial = 0;
		}

		/*
		if (!syslog_partial)
			syslog_time = printk_time;

		skip = syslog_partial;
		n = record_print_text(&r, true, syslog_time);
		if (n - syslog_partial <= size) {
			/* message fits into buffer, move forward */
			syslog_seq = r.info->seq + 1;
			n -= syslog_partial;
			syslog_partial = 0;
		} else if (!len){
			/* partial read(), remember position */
			n = size;
			syslog_partial += n;
		} else
			n = 0;

		if (!n)
			break;

		mutex_unlock(&syslog_lock);
		err = copy_to_user(buf, text + skip, n);
		mutex_lock(&syslog_lock);

		if (err) {
			if (!len)
				len = -EFAULT;
			break;
		}

		len += n;
		size -= n;
		buf += n;
	} while (size);
out:
	mutex_unlock(&syslog_lock);
	kfree(text);
	return len;
}

static int syslog_print_all(char __user *buf, int size, bool clear)
{
	struct printk_info info;
	struct printk_record r;
	char *text;
	int len = 0;
	u64 seq;
	bool time;

	text = kmalloc(CONSOLE_LOG_MAX, GFP_KERNEL);
	if (!text)
		return -ENOMEM;

	time = printk_time;
	/*
	seq = find_first_fitting_seq(latched_seq_read_nolock(&clear_seq), -1,
				     size, true, time);

	prb_rec_init_rd(&r, &info, text, CONSOLE_LOG_MAX);

	len = 0;
	prb_for_each_record(seq, prb, seq, &r) {
		int textlen;

		textlen = record_print_text(&r, true, time);

		if (len + textlen > size) {
			seq--;
			break;
		}

		if (copy_to_user(buf + len, text, textlen))
			len = -EFAULT;
		else
			len += textlen;

		if (len < 0)
			break;
	}

	if (clear) {
		mutex_lock(&syslog_lock);
		latched_seq_write(&clear_seq, seq);
		mutex_unlock(&syslog_lock);
	}

	kfree(text);
	return len;
}

static void syslog_clear(void)
{
	mutex_lock(&syslog_lock);
	latched_seq_write(&clear_seq, prb_next_seq(prb));
	mutex_unlock(&syslog_lock);
}

int do_syslog(int type, char __user *buf, int len, int source)
{
	struct printk_info info;
	bool clear = false;
	static int saved_console_loglevel = LOGLEVEL_DEFAULT;
	int error;

	error = check_syslog_permissions(type, source);
	if (error)
		return error;

	switch (type) {
	case SYSLOG_ACTION_CLOSE:	/* Close log */
		break;
	case SYSLOG_ACTION_OPEN:	/* Open log */
		break;
	case SYSLOG_ACTION_READ:	/* Read from log */
		if (!buf || len < 0)
			return -EINVAL;
		if (!len)
			return 0;
		if (!access_ok(buf, len))
			return -EFAULT;
		error = syslog_print(buf, len);
		break;
	/* Read/clear last kernel messages */
	case SYSLOG_ACTION_READ_CLEAR:
		clear = true;
		fallthrough;
	/* Read last kernel messages */
	case SYSLOG_ACTION_READ_ALL:
		if (!buf || len < 0)
			return -EINVAL;
		if (!len)
			return 0;
		if (!access_ok(buf, len))
			return -EFAULT;
		error = syslog_print_all(buf, len, clear);
		break;
	/* Clear ring buffer */
	case SYSLOG_ACTION_CLEAR:
		syslog_clear();
		break;
	/* Disable logging to console */
	case SYSLOG_ACTION_CONSOLE_OFF:
		if (saved_console_loglevel == LOGLEVEL_DEFAULT)
			saved_console_loglevel = console_loglevel;
		console_loglevel = minimum_console_loglevel;
		break;
	/* Enable logging to console */
	case SYSLOG_ACTION_CONSOLE_ON:
		if (saved_console_loglevel != LOGLEVEL_DEFAULT) {
			console_loglevel = saved_console_loglevel;
			saved_console_loglevel = LOGLEVEL_DEFAULT;
		}
		break;
	/* Set level of messages printed to console */
	case SYSLOG_ACTION_CONSOLE_LEVEL:
		if (len < 1 || len > 8)
			return -EINVAL;
		if (len < minimum_console_loglevel)
			len = minimum_console_loglevel;
		console_loglevel = len;
		/* Implicitly re-enable logging to console */
		saved_console_loglevel = LOGLEVEL_DEFAULT;
		break;
	/* Number of chars in the log buffer */
	case SYSLOG_ACTION_SIZE_UNREAD:
		mutex_lock(&syslog_lock);
		if (!prb_read_valid_info(prb, syslog_seq, &info, NULL)) {
			/* No unread messages. */
			mutex_unlock(&syslog_lock);
			return 0;
		}
		if (info.seq != syslog_seq) {
			/* messages are gone, move to first one */
			syslog_seq = info.seq;
			syslog_partial = 0;
		}
		if (source == SYSLOG_FROM_PROC) {
			/*
			error = prb_next_seq(prb) - syslog_seq;
		} else {
			bool time = syslog_partial ? syslog_time : printk_time;
			unsigned int line_count;
			u64 seq;

			prb_for_each_info(syslog_seq, prb, seq, &info,
					  &line_count) {
				error += get_record_print_text_size(&info, line_count,
								    true, time);
				time = printk_time;
			}
			error -= syslog_partial;
		}
		mutex_unlock(&syslog_lock);
		break;
	/* Size of the log buffer */
	case SYSLOG_ACTION_SIZE_BUFFER:
		error = log_buf_len;
		break;
	default:
		error = -EINVAL;
		break;
	}

	return error;
}

SYSCALL_DEFINE3(syslog, int, type, char __user *, buf, int, len)
{
	return do_syslog(type, buf, len, SYSLOG_FROM_READER);
}


#ifdef CONFIG_LOCKDEP
static struct lockdep_map console_owner_dep_map = {
	.name = "console_owner"
};
#endif

static DEFINE_RAW_SPINLOCK(console_owner_lock);
static struct task_struct *console_owner;
static bool console_waiter;

static void console_lock_spinning_enable(void)
{
	raw_spin_lock(&console_owner_lock);
	console_owner = current;
	raw_spin_unlock(&console_owner_lock);

	/* The waiter may spin on us after setting console_owner */
	spin_acquire(&console_owner_dep_map, 0, 0, _THIS_IP_);
}

static int console_lock_spinning_disable_and_check(void)
{
	int waiter;

	raw_spin_lock(&console_owner_lock);
	waiter = READ_ONCE(console_waiter);
	console_owner = NULL;
	raw_spin_unlock(&console_owner_lock);

	if (!waiter) {
		spin_release(&console_owner_dep_map, _THIS_IP_);
		return 0;
	}

	/* The waiter is now free to continue */
	WRITE_ONCE(console_waiter, false);

	spin_release(&console_owner_dep_map, _THIS_IP_);

	/*
	mutex_release(&console_lock_dep_map, _THIS_IP_);
	return 1;
}

static int console_trylock_spinning(void)
{
	struct task_struct *owner = NULL;
	bool waiter;
	bool spin = false;
	unsigned long flags;

	if (console_trylock())
		return 1;

	/*
	if (panic_in_progress())
		return 0;

	printk_safe_enter_irqsave(flags);

	raw_spin_lock(&console_owner_lock);
	owner = READ_ONCE(console_owner);
	waiter = READ_ONCE(console_waiter);
	if (!waiter && owner && owner != current) {
		WRITE_ONCE(console_waiter, true);
		spin = true;
	}
	raw_spin_unlock(&console_owner_lock);

	/*
	if (!spin) {
		printk_safe_exit_irqrestore(flags);
		return 0;
	}

	/* We spin waiting for the owner to release us */
	spin_acquire(&console_owner_dep_map, 0, 0, _THIS_IP_);
	/* Owner will clear console_waiter on hand off */
	while (READ_ONCE(console_waiter))
		cpu_relax();
	spin_release(&console_owner_dep_map, _THIS_IP_);

	printk_safe_exit_irqrestore(flags);
	/*
	mutex_acquire(&console_lock_dep_map, 0, 1, _THIS_IP_);

	return 1;
}

static void call_console_driver(struct console *con, const char *text, size_t len,
				char *dropped_text)
{
	size_t dropped_len;

	if (con->dropped && dropped_text) {
		dropped_len = snprintf(dropped_text, DROPPED_TEXT_MAX,
				       "** %lu printk messages dropped **\n",
				       con->dropped);
		con->dropped = 0;
		con->write(con, dropped_text, dropped_len);
	}

	con->write(con, text, len);
}

static DEFINE_PER_CPU(u8, printk_count);
static u8 printk_count_early;
#ifdef CONFIG_HAVE_NMI
static DEFINE_PER_CPU(u8, printk_count_nmi);
static u8 printk_count_nmi_early;
#endif

#define PRINTK_MAX_RECURSION 3

static u8 *__printk_recursion_counter(void)
{
#ifdef CONFIG_HAVE_NMI
	if (in_nmi()) {
		if (printk_percpu_data_ready())
			return this_cpu_ptr(&printk_count_nmi);
		return &printk_count_nmi_early;
	}
#endif
	if (printk_percpu_data_ready())
		return this_cpu_ptr(&printk_count);
	return &printk_count_early;
}

#define printk_enter_irqsave(recursion_ptr, flags)	\
({							\
	bool success = true;				\
							\
	typecheck(u8 *, recursion_ptr);			\
	local_irq_save(flags);				\
	(recursion_ptr) = __printk_recursion_counter();	\
	if (*(recursion_ptr) > PRINTK_MAX_RECURSION) {	\
		local_irq_restore(flags);		\
		success = false;			\
	} else {					\
		(*(recursion_ptr))++;			\
	}						\
	success;					\
})

#define printk_exit_irqrestore(recursion_ptr, flags)	\
	do {						\
		typecheck(u8 *, recursion_ptr);		\
		(*(recursion_ptr))--;			\
		local_irq_restore(flags);		\
	} while (0)

int printk_delay_msec __read_mostly;

static inline void printk_delay(int level)
{
	boot_delay_msec(level);

	if (unlikely(printk_delay_msec)) {
		int m = printk_delay_msec;

		while (m--) {
			mdelay(1);
			touch_nmi_watchdog();
		}
	}
}

static inline u32 printk_caller_id(void)
{
	return in_task() ? task_pid_nr(current) :
		0x80000000 + smp_processor_id();
}

u16 printk_parse_prefix(const char *text, int *level,
			enum printk_info_flags *flags)
{
	u16 prefix_len = 0;
	int kern_level;

	while (*text) {
		kern_level = printk_get_level(text);
		if (!kern_level)
			break;

		switch (kern_level) {
		case '0' ... '7':
			if (level && *level == LOGLEVEL_DEFAULT)
				*level = kern_level - '0';
			break;
		case 'c':	/* KERN_CONT */
			if (flags)
				*flags |= LOG_CONT;
		}

		prefix_len += 2;
		text += 2;
	}

	return prefix_len;
}

__printf(5, 0)
static u16 printk_sprint(char *text, u16 size, int facility,
			 enum printk_info_flags *flags, const char *fmt,
			 va_list args)
{
	u16 text_len;

	text_len = vscnprintf(text, size, fmt, args);

	/* Mark and strip a trailing newline. */
	if (text_len && text[text_len - 1] == '\n') {
		text_len--;
		*flags |= LOG_NEWLINE;
	}

	/* Strip log level and control flags. */
	if (facility == 0) {
		u16 prefix_len;

		prefix_len = printk_parse_prefix(text, NULL, NULL);
		if (prefix_len) {
			text_len -= prefix_len;
			memmove(text, text + prefix_len, text_len);
		}
	}

	trace_console_rcuidle(text, text_len);

	return text_len;
}

__printf(4, 0)
int vprintk_store(int facility, int level,
		  const struct dev_printk_info *dev_info,
		  const char *fmt, va_list args)
{
	struct prb_reserved_entry e;
	enum printk_info_flags flags = 0;
	struct printk_record r;
	unsigned long irqflags;
	u16 trunc_msg_len = 0;
	char prefix_buf[8];
	u8 *recursion_ptr;
	u16 reserve_size;
	va_list args2;
	u32 caller_id;
	u16 text_len;
	int ret = 0;
	u64 ts_nsec;

	if (!printk_enter_irqsave(recursion_ptr, irqflags))
		return 0;

	/*
	ts_nsec = local_clock();

	caller_id = printk_caller_id();

	/*
	va_copy(args2, args);
	reserve_size = vsnprintf(&prefix_buf[0], sizeof(prefix_buf), fmt, args2) + 1;
	va_end(args2);

	if (reserve_size > LOG_LINE_MAX)
		reserve_size = LOG_LINE_MAX;

	/* Extract log level or control flags. */
	if (facility == 0)
		printk_parse_prefix(&prefix_buf[0], &level, &flags);

	if (level == LOGLEVEL_DEFAULT)
		level = default_message_loglevel;

	if (dev_info)
		flags |= LOG_NEWLINE;

	if (flags & LOG_CONT) {
		prb_rec_init_wr(&r, reserve_size);
		if (prb_reserve_in_last(&e, prb, &r, caller_id, LOG_LINE_MAX)) {
			text_len = printk_sprint(&r.text_buf[r.info->text_len], reserve_size,
						 facility, &flags, fmt, args);
			r.info->text_len += text_len;

			if (flags & LOG_NEWLINE) {
				r.info->flags |= LOG_NEWLINE;
				prb_final_commit(&e);
			} else {
				prb_commit(&e);
			}

			ret = text_len;
			goto out;
		}
	}

	/*
	prb_rec_init_wr(&r, reserve_size);
	if (!prb_reserve(&e, prb, &r)) {
		/* truncate the message if it is too long for empty buffer */
		truncate_msg(&reserve_size, &trunc_msg_len);

		prb_rec_init_wr(&r, reserve_size + trunc_msg_len);
		if (!prb_reserve(&e, prb, &r))
			goto out;
	}

	/* fill message */
	text_len = printk_sprint(&r.text_buf[0], reserve_size, facility, &flags, fmt, args);
	if (trunc_msg_len)
		memcpy(&r.text_buf[text_len], trunc_msg, trunc_msg_len);
	r.info->text_len = text_len + trunc_msg_len;
	r.info->facility = facility;
	r.info->level = level & 7;
	r.info->flags = flags & 0x1f;
	r.info->ts_nsec = ts_nsec;
	r.info->caller_id = caller_id;
	if (dev_info)
		memcpy(&r.info->dev_info, dev_info, sizeof(r.info->dev_info));

	/* A message without a trailing newline can be continued. */
	if (!(flags & LOG_NEWLINE))
		prb_commit(&e);
	else
		prb_final_commit(&e);

	ret = text_len + trunc_msg_len;
out:
	printk_exit_irqrestore(recursion_ptr, irqflags);
	return ret;
}

asmlinkage int vprintk_emit(int facility, int level,
			    const struct dev_printk_info *dev_info,
			    const char *fmt, va_list args)
{
	int printed_len;
	bool in_sched = false;

	/* Suppress unimportant messages after panic happens */
	if (unlikely(suppress_printk))
		return 0;

	if (unlikely(suppress_panic_printk) &&
	    atomic_read(&panic_cpu) != raw_smp_processor_id())
		return 0;

	if (level == LOGLEVEL_SCHED) {
		level = LOGLEVEL_DEFAULT;
		in_sched = true;
	}

	printk_delay(level);

	printed_len = vprintk_store(facility, level, dev_info, fmt, args);

	/* If called from the scheduler, we can not call up(). */
	if (!in_sched) {
		/*
		preempt_disable();
		/*
		if (console_trylock_spinning())
			console_unlock();
		preempt_enable();
	}

	wake_up_klogd();
	return printed_len;
}
EXPORT_SYMBOL(vprintk_emit);

int vprintk_default(const char *fmt, va_list args)
{
	return vprintk_emit(0, LOGLEVEL_DEFAULT, NULL, fmt, args);
}
EXPORT_SYMBOL_GPL(vprintk_default);

asmlinkage __visible int _printk(const char *fmt, ...)
{
	va_list args;
	int r;

	va_start(args, fmt);
	r = vprintk(fmt, args);
	va_end(args);

	return r;
}
EXPORT_SYMBOL(_printk);

static bool __pr_flush(struct console *con, int timeout_ms, bool reset_on_progress);

#else /* CONFIG_PRINTK */

#define CONSOLE_LOG_MAX		0
#define DROPPED_TEXT_MAX	0
#define printk_time		false

#define prb_read_valid(rb, seq, r)	false
#define prb_first_valid_seq(rb)		0
#define prb_next_seq(rb)		0

static u64 syslog_seq;

static size_t record_print_text(const struct printk_record *r,
				bool syslog, bool time)
{
	return 0;
}
static ssize_t info_print_ext_header(char *buf, size_t size,
				     struct printk_info *info)
{
	return 0;
}
static ssize_t msg_print_ext_body(char *buf, size_t size,
				  char *text, size_t text_len,
				  struct dev_printk_info *dev_info) { return 0; }
static void console_lock_spinning_enable(void) { }
static int console_lock_spinning_disable_and_check(void) { return 0; }
static void call_console_driver(struct console *con, const char *text, size_t len,
				char *dropped_text)
{
}
static bool suppress_message_printing(int level) { return false; }
static bool __pr_flush(struct console *con, int timeout_ms, bool reset_on_progress) { return true; }

#endif /* CONFIG_PRINTK */

#ifdef CONFIG_EARLY_PRINTK
struct console *early_console;

asmlinkage __visible void early_printk(const char *fmt, ...)
{
	va_list ap;
	char buf[512];
	int n;

	if (!early_console)
		return;

	va_start(ap, fmt);
	n = vscnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	early_console->write(early_console, buf, n);
}
#endif

static void set_user_specified(struct console_cmdline *c, bool user_specified)
{
	if (!user_specified)
		return;

	/*
	c->user_specified = true;
	/* At least one console defined by the user on the command line. */
	console_set_on_cmdline = 1;
}

static int __add_preferred_console(char *name, int idx, char *options,
				   char *brl_options, bool user_specified)
{
	struct console_cmdline *c;
	int i;

	/*
	for (i = 0, c = console_cmdline;
	     i < MAX_CMDLINECONSOLES && c->name[0];
	     i++, c++) {
		if (strcmp(c->name, name) == 0 && c->index == idx) {
			if (!brl_options)
				preferred_console = i;
			set_user_specified(c, user_specified);
			return 0;
		}
	}
	if (i == MAX_CMDLINECONSOLES)
		return -E2BIG;
	if (!brl_options)
		preferred_console = i;
	strlcpy(c->name, name, sizeof(c->name));
	c->options = options;
	set_user_specified(c, user_specified);
	braille_set_options(c, brl_options);

	c->index = idx;
	return 0;
}

static int __init console_msg_format_setup(char *str)
{
	if (!strcmp(str, "syslog"))
		console_msg_format = MSG_FORMAT_SYSLOG;
	if (!strcmp(str, "default"))
		console_msg_format = MSG_FORMAT_DEFAULT;
	return 1;
}
__setup("console_msg_format=", console_msg_format_setup);

static int __init console_setup(char *str)
{
	char buf[sizeof(console_cmdline[0].name) + 4]; /* 4 for "ttyS" */
	char *s, *options, *brl_options = NULL;
	int idx;

	/*
	if (str[0] == 0 || strcmp(str, "null") == 0) {
		__add_preferred_console("ttynull", 0, NULL, NULL, true);
		return 1;
	}

	if (_braille_console_setup(&str, &brl_options))
		return 1;

	/*
	if (str[0] >= '0' && str[0] <= '9') {
		strcpy(buf, "ttyS");
		strncpy(buf + 4, str, sizeof(buf) - 5);
	} else {
		strncpy(buf, str, sizeof(buf) - 1);
	}
	buf[sizeof(buf) - 1] = 0;
	options = strchr(str, ',');
	if (options)
		*(options++) = 0;
#ifdef __sparc__
	if (!strcmp(str, "ttya"))
		strcpy(buf, "ttyS0");
	if (!strcmp(str, "ttyb"))
		strcpy(buf, "ttyS1");
#endif
	for (s = buf; *s; s++)
		if (isdigit(*s) || *s == ',')
			break;
	idx = simple_strtoul(s, NULL, 10);

	__add_preferred_console(buf, idx, options, brl_options, true);
	return 1;
}
__setup("console=", console_setup);

int add_preferred_console(char *name, int idx, char *options)
{
	return __add_preferred_console(name, idx, options, NULL, false);
}

bool console_suspend_enabled = true;
EXPORT_SYMBOL(console_suspend_enabled);

static int __init console_suspend_disable(char *str)
{
	console_suspend_enabled = false;
	return 1;
}
__setup("no_console_suspend", console_suspend_disable);
module_param_named(console_suspend, console_suspend_enabled,
		bool, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(console_suspend, "suspend console during suspend"
	" and hibernate operations");

static bool printk_console_no_auto_verbose;

void console_verbose(void)
{
	if (console_loglevel && !printk_console_no_auto_verbose)
		console_loglevel = CONSOLE_LOGLEVEL_MOTORMOUTH;
}
EXPORT_SYMBOL_GPL(console_verbose);

module_param_named(console_no_auto_verbose, printk_console_no_auto_verbose, bool, 0644);
MODULE_PARM_DESC(console_no_auto_verbose, "Disable console loglevel raise to highest on oops/panic/etc");

void suspend_console(void)
{
	if (!console_suspend_enabled)
		return;
	pr_info("Suspending console(s) (use no_console_suspend to debug)\n");
	pr_flush(1000, true);
	console_lock();
	console_suspended = 1;
	up_console_sem();
}

void resume_console(void)
{
	if (!console_suspend_enabled)
		return;
	down_console_sem();
	console_suspended = 0;
	console_unlock();
	pr_flush(1000, true);
}

static int console_cpu_notify(unsigned int cpu)
{
	if (!cpuhp_tasks_frozen) {
		/* If trylock fails, someone else is doing the printing */
		if (console_trylock())
			console_unlock();
	}
	return 0;
}

void console_lock(void)
{
	might_sleep();

	down_console_sem();
	if (console_suspended)
		return;
	console_locked = 1;
	console_may_schedule = 1;
}
EXPORT_SYMBOL(console_lock);

int console_trylock(void)
{
	if (down_trylock_console_sem())
		return 0;
	if (console_suspended) {
		up_console_sem();
		return 0;
	}
	console_locked = 1;
	console_may_schedule = 0;
	return 1;
}
EXPORT_SYMBOL(console_trylock);

int is_console_locked(void)
{
	return console_locked;
}
EXPORT_SYMBOL(is_console_locked);

static bool abandon_console_lock_in_panic(void)
{
	if (!panic_in_progress())
		return false;

	/*
	return atomic_read(&panic_cpu) != raw_smp_processor_id();
}

static inline bool console_is_usable(struct console *con)
{
	if (!(con->flags & CON_ENABLED))
		return false;

	if (!con->write)
		return false;

	/*
	if (!cpu_online(raw_smp_processor_id()) &&
	    !(con->flags & CON_ANYTIME))
		return false;

	return true;
}

static void __console_unlock(void)
{
	console_locked = 0;
	up_console_sem();
}

static bool console_emit_next_record(struct console *con, char *text, char *ext_text,
				     char *dropped_text, bool *handover)
{
	static int panic_console_dropped;
	struct printk_info info;
	struct printk_record r;
	unsigned long flags;
	char *write_text;
	size_t len;

	prb_rec_init_rd(&r, &info, text, CONSOLE_LOG_MAX);


	if (!prb_read_valid(prb, con->seq, &r))
		return false;

	if (con->seq != r.info->seq) {
		con->dropped += r.info->seq - con->seq;
		con->seq = r.info->seq;
		if (panic_in_progress() && panic_console_dropped++ > 10) {
			suppress_panic_printk = 1;
			pr_warn_once("Too many dropped messages. Suppress messages on non-panic CPUs to prevent livelock.\n");
		}
	}

	/* Skip record that has level above the console loglevel. */
	if (suppress_message_printing(r.info->level)) {
		con->seq++;
		goto skip;
	}

	if (ext_text) {
		write_text = ext_text;
		len = info_print_ext_header(ext_text, CONSOLE_EXT_LOG_MAX, r.info);
		len += msg_print_ext_body(ext_text + len, CONSOLE_EXT_LOG_MAX - len,
					  &r.text_buf[0], r.info->text_len, &r.info->dev_info);
	} else {
		write_text = text;
		len = record_print_text(&r, console_msg_format & MSG_FORMAT_SYSLOG, printk_time);
	}

	/*
	printk_safe_enter_irqsave(flags);
	console_lock_spinning_enable();

	stop_critical_timings();	/* don't trace print latency */
	call_console_driver(con, write_text, len, dropped_text);
	start_critical_timings();

	con->seq++;

	printk_safe_exit_irqrestore(flags);
skip:
	return true;
}

static bool console_flush_all(bool do_cond_resched, u64 *next_seq, bool *handover)
{
	static char dropped_text[DROPPED_TEXT_MAX];
	static char ext_text[CONSOLE_EXT_LOG_MAX];
	static char text[CONSOLE_LOG_MAX];
	bool any_usable = false;
	struct console *con;
	bool any_progress;


	do {
		any_progress = false;

		for_each_console(con) {
			bool progress;

			if (!console_is_usable(con))
				continue;
			any_usable = true;

			if (con->flags & CON_EXTENDED) {
				/* Extended consoles do not print "dropped messages". */
				progress = console_emit_next_record(con, &text[0],
								    &ext_text[0], NULL,
								    handover);
			} else {
				progress = console_emit_next_record(con, &text[0],
								    NULL, &dropped_text[0],
								    handover);
			}
			if (*handover)
				return false;

			/* Track the next of the highest seq flushed. */
			if (con->seq > *next_seq)
				*next_seq = con->seq;

			if (!progress)
				continue;
			any_progress = true;

			/* Allow panic_cpu to take over the consoles safely. */
			if (abandon_console_lock_in_panic())
				return false;

			if (do_cond_resched)
				cond_resched();
		}
	} while (any_progress);

	return any_usable;
}

void console_unlock(void)
{
	bool do_cond_resched;
	bool handover;
	bool flushed;
	u64 next_seq;

	if (console_suspended) {
		up_console_sem();
		return;
	}

	/*
	do_cond_resched = console_may_schedule;

	do {
		console_may_schedule = 0;

		flushed = console_flush_all(do_cond_resched, &next_seq, &handover);
		if (!handover)
			__console_unlock();

		/*
		if (!flushed)
			break;

		/*
	} while (prb_read_valid(prb, next_seq, NULL) && console_trylock());
}
EXPORT_SYMBOL(console_unlock);

void __sched console_conditional_schedule(void)
{
	if (console_may_schedule)
		cond_resched();
}
EXPORT_SYMBOL(console_conditional_schedule);

void console_unblank(void)
{
	struct console *c;

	/*
	if (oops_in_progress) {
		if (down_trylock_console_sem() != 0)
			return;
	} else
		console_lock();

	console_locked = 1;
	console_may_schedule = 0;
	for_each_console(c)
		if ((c->flags & CON_ENABLED) && c->unblank)
			c->unblank();
	console_unlock();

	if (!oops_in_progress)
		pr_flush(1000, true);
}

void console_flush_on_panic(enum con_flush_mode mode)
{
	/*
	console_trylock();
	console_may_schedule = 0;

	if (mode == CONSOLE_REPLAY_ALL) {
		struct console *c;
		u64 seq;

		seq = prb_first_valid_seq(prb);
		for_each_console(c)
			c->seq = seq;
	}
	console_unlock();
}

struct tty_driver *console_device(int *index)
{
	struct console *c;
	struct tty_driver *driver = NULL;

	console_lock();
	for_each_console(c) {
		if (!c->device)
			continue;
		driver = c->device(c, index);
		if (driver)
			break;
	}
	console_unlock();
	return driver;
}

void console_stop(struct console *console)
{
	__pr_flush(console, 1000, true);
	console_lock();
	console->flags &= ~CON_ENABLED;
	console_unlock();
}
EXPORT_SYMBOL(console_stop);

void console_start(struct console *console)
{
	console_lock();
	console->flags |= CON_ENABLED;
	console_unlock();
	__pr_flush(console, 1000, true);
}
EXPORT_SYMBOL(console_start);

static int __read_mostly keep_bootcon;

static int __init keep_bootcon_setup(char *str)
{
	keep_bootcon = 1;
	pr_info("debug: skip boot console de-registration.\n");

	return 0;
}

early_param("keep_bootcon", keep_bootcon_setup);

static int try_enable_preferred_console(struct console *newcon,
					bool user_specified)
{
	struct console_cmdline *c;
	int i, err;

	for (i = 0, c = console_cmdline;
	     i < MAX_CMDLINECONSOLES && c->name[0];
	     i++, c++) {
		if (c->user_specified != user_specified)
			continue;
		if (!newcon->match ||
		    newcon->match(newcon, c->name, c->index, c->options) != 0) {
			/* default matching */
			BUILD_BUG_ON(sizeof(c->name) != sizeof(newcon->name));
			if (strcmp(c->name, newcon->name) != 0)
				continue;
			if (newcon->index >= 0 &&
			    newcon->index != c->index)
				continue;
			if (newcon->index < 0)
				newcon->index = c->index;

			if (_braille_register_console(newcon, c))
				return 0;

			if (newcon->setup &&
			    (err = newcon->setup(newcon, c->options)) != 0)
				return err;
		}
		newcon->flags |= CON_ENABLED;
		if (i == preferred_console)
			newcon->flags |= CON_CONSDEV;
		return 0;
	}

	/*
	if (newcon->flags & CON_ENABLED && c->user_specified ==	user_specified)
		return 0;

	return -ENOENT;
}

static void try_enable_default_console(struct console *newcon)
{
	if (newcon->index < 0)
		newcon->index = 0;

	if (newcon->setup && newcon->setup(newcon, NULL) != 0)
		return;

	newcon->flags |= CON_ENABLED;

	if (newcon->device)
		newcon->flags |= CON_CONSDEV;
}

#define con_printk(lvl, con, fmt, ...)			\
	printk(lvl pr_fmt("%sconsole [%s%d] " fmt),	\
	       (con->flags & CON_BOOT) ? "boot" : "",	\
	       con->name, con->index, ##__VA_ARGS__)

void register_console(struct console *newcon)
{
	struct console *con;
	bool bootcon_enabled = false;
	bool realcon_enabled = false;
	int err;

	for_each_console(con) {
		if (WARN(con == newcon, "console '%s%d' already registered\n",
					 con->name, con->index))
			return;
	}

	for_each_console(con) {
		if (con->flags & CON_BOOT)
			bootcon_enabled = true;
		else
			realcon_enabled = true;
	}

	/* Do not register boot consoles when there already is a real one. */
	if (newcon->flags & CON_BOOT && realcon_enabled) {
		pr_info("Too late to register bootconsole %s%d\n",
			newcon->name, newcon->index);
		return;
	}

	/*
	if (preferred_console < 0) {
		if (!console_drivers || !console_drivers->device ||
		    console_drivers->flags & CON_BOOT) {
			try_enable_default_console(newcon);
		}
	}

	/* See if this console matches one we selected on the command line */
	err = try_enable_preferred_console(newcon, true);

	/* If not, try to match against the platform default(s) */
	if (err == -ENOENT)
		err = try_enable_preferred_console(newcon, false);

	/* printk() messages are not printed to the Braille console. */
	if (err || newcon->flags & CON_BRL)
		return;

	/*
	if (bootcon_enabled &&
	    ((newcon->flags & (CON_CONSDEV | CON_BOOT)) == CON_CONSDEV)) {
		newcon->flags &= ~CON_PRINTBUFFER;
	}

	/*
	console_lock();
	if ((newcon->flags & CON_CONSDEV) || console_drivers == NULL) {
		newcon->next = console_drivers;
		console_drivers = newcon;
		if (newcon->next)
			newcon->next->flags &= ~CON_CONSDEV;
		/* Ensure this flag is always set for the head of the list */
		newcon->flags |= CON_CONSDEV;
	} else {
		newcon->next = console_drivers->next;
		console_drivers->next = newcon;
	}

	if (newcon->flags & CON_EXTENDED)
		nr_ext_console_drivers++;

	newcon->dropped = 0;
	if (newcon->flags & CON_PRINTBUFFER) {
		/* Get a consistent copy of @syslog_seq. */
		mutex_lock(&syslog_lock);
		newcon->seq = syslog_seq;
		mutex_unlock(&syslog_lock);
	} else {
		/* Begin with next message. */
		newcon->seq = prb_next_seq(prb);
	}
	console_unlock();
	console_sysfs_notify();

	/*
	con_printk(KERN_INFO, newcon, "enabled\n");
	if (bootcon_enabled &&
	    ((newcon->flags & (CON_CONSDEV | CON_BOOT)) == CON_CONSDEV) &&
	    !keep_bootcon) {
		/* We need to iterate through all boot consoles, to make
		 * sure we print everything out, before we unregister them.
		 */
		for_each_console(con)
			if (con->flags & CON_BOOT)
				unregister_console(con);
	}
}
EXPORT_SYMBOL(register_console);

int unregister_console(struct console *console)
{
	struct console *con;
	int res;

	con_printk(KERN_INFO, console, "disabled\n");

	res = _braille_unregister_console(console);
	if (res < 0)
		return res;
	if (res > 0)
		return 0;

	res = -ENODEV;
	console_lock();
	if (console_drivers == console) {
		console_drivers=console->next;
		res = 0;
	} else {
		for_each_console(con) {
			if (con->next == console) {
				con->next = console->next;
				res = 0;
				break;
			}
		}
	}

	if (res)
		goto out_disable_unlock;

	if (console->flags & CON_EXTENDED)
		nr_ext_console_drivers--;

	/*
	if (console_drivers != NULL && console->flags & CON_CONSDEV)
		console_drivers->flags |= CON_CONSDEV;

	console->flags &= ~CON_ENABLED;
	console_unlock();
	console_sysfs_notify();

	if (console->exit)
		res = console->exit(console);

	return res;

out_disable_unlock:
	console->flags &= ~CON_ENABLED;
	console_unlock();

	return res;
}
EXPORT_SYMBOL(unregister_console);

void __init console_init(void)
{
	int ret;
	initcall_t call;
	initcall_entry_t *ce;

	/* Setup the default TTY line discipline. */
	n_tty_init();

	/*
	ce = __con_initcall_start;
	trace_initcall_level("console");
	while (ce < __con_initcall_end) {
		call = initcall_from_entry(ce);
		trace_initcall_start(call);
		ret = call();
		trace_initcall_finish(call, ret);
		ce++;
	}
}

static int __init printk_late_init(void)
{
	struct console *con;
	int ret;

	for_each_console(con) {
		if (!(con->flags & CON_BOOT))
			continue;

		/* Check addresses that might be used for enabled consoles. */
		if (init_section_intersects(con, sizeof(*con)) ||
		    init_section_contains(con->write, 0) ||
		    init_section_contains(con->read, 0) ||
		    init_section_contains(con->device, 0) ||
		    init_section_contains(con->unblank, 0) ||
		    init_section_contains(con->data, 0)) {
			/*
			pr_warn("bootconsole [%s%d] uses init memory and must be disabled even before the real one is ready\n",
				con->name, con->index);
			unregister_console(con);
		}
	}
	ret = cpuhp_setup_state_nocalls(CPUHP_PRINTK_DEAD, "printk:dead", NULL,
					console_cpu_notify);
	WARN_ON(ret < 0);
	ret = cpuhp_setup_state_nocalls(CPUHP_AP_ONLINE_DYN, "printk:online",
					console_cpu_notify, NULL);
	WARN_ON(ret < 0);
	printk_sysctl_init();
	return 0;
}
late_initcall(printk_late_init);

#if defined CONFIG_PRINTK
static bool __pr_flush(struct console *con, int timeout_ms, bool reset_on_progress)
{
	int remaining = timeout_ms;
	struct console *c;
	u64 last_diff = 0;
	u64 printk_seq;
	u64 diff;
	u64 seq;

	might_sleep();

	seq = prb_next_seq(prb);

	for (;;) {
		diff = 0;

		console_lock();

		for_each_console(c) {
			if (con && con != c)
				continue;
			if (!console_is_usable(c))
				continue;
			printk_seq = c->seq;
			if (printk_seq < seq)
				diff += seq - printk_seq;
		}

		/*
		if (console_suspended)
			remaining = 0;
		else if (diff != last_diff && reset_on_progress)
			remaining = timeout_ms;

		console_unlock();

		if (diff == 0 || remaining == 0)
			break;

		if (remaining < 0) {
			/* no timeout limit */
			msleep(100);
		} else if (remaining < 100) {
			msleep(remaining);
			remaining = 0;
		} else {
			msleep(100);
			remaining -= 100;
		}

		last_diff = diff;
	}

	return (diff == 0);
}

bool pr_flush(int timeout_ms, bool reset_on_progress)
{
	return __pr_flush(NULL, timeout_ms, reset_on_progress);
}
EXPORT_SYMBOL(pr_flush);

#define PRINTK_PENDING_WAKEUP	0x01
#define PRINTK_PENDING_OUTPUT	0x02

static DEFINE_PER_CPU(int, printk_pending);

static void wake_up_klogd_work_func(struct irq_work *irq_work)
{
	int pending = this_cpu_xchg(printk_pending, 0);

	if (pending & PRINTK_PENDING_OUTPUT) {
		/* If trylock fails, someone else is doing the printing */
		if (console_trylock())
			console_unlock();
	}

	if (pending & PRINTK_PENDING_WAKEUP)
		wake_up_interruptible(&log_wait);
}

static DEFINE_PER_CPU(struct irq_work, wake_up_klogd_work) =
	IRQ_WORK_INIT_LAZY(wake_up_klogd_work_func);

static void __wake_up_klogd(int val)
{
	if (!printk_percpu_data_ready())
		return;

	preempt_disable();
	/*
	if (wq_has_sleeper(&log_wait) || /* LMM(__wake_up_klogd:A) */
	    (val & PRINTK_PENDING_OUTPUT)) {
		this_cpu_or(printk_pending, val);
		irq_work_queue(this_cpu_ptr(&wake_up_klogd_work));
	}
	preempt_enable();
}

void wake_up_klogd(void)
{
	__wake_up_klogd(PRINTK_PENDING_WAKEUP);
}

void defer_console_output(void)
{
	/*
	__wake_up_klogd(PRINTK_PENDING_WAKEUP | PRINTK_PENDING_OUTPUT);
}

void printk_trigger_flush(void)
{
	defer_console_output();
}

int vprintk_deferred(const char *fmt, va_list args)
{
	int r;

	r = vprintk_emit(0, LOGLEVEL_SCHED, NULL, fmt, args);
	defer_console_output();

	return r;
}

int _printk_deferred(const char *fmt, ...)
{
	va_list args;
	int r;

	va_start(args, fmt);
	r = vprintk_deferred(fmt, args);
	va_end(args);

	return r;
}

DEFINE_RATELIMIT_STATE(printk_ratelimit_state, 5 * HZ, 10);

int __printk_ratelimit(const char *func)
{
	return ___ratelimit(&printk_ratelimit_state, func);
}
EXPORT_SYMBOL(__printk_ratelimit);

bool printk_timed_ratelimit(unsigned long *caller_jiffies,
			unsigned int interval_msecs)
{
	unsigned long elapsed = jiffies - *caller_jiffies;

	if (*caller_jiffies && elapsed <= msecs_to_jiffies(interval_msecs))
		return false;

	return true;
}
EXPORT_SYMBOL(printk_timed_ratelimit);

static DEFINE_SPINLOCK(dump_list_lock);
static LIST_HEAD(dump_list);

int kmsg_dump_register(struct kmsg_dumper *dumper)
{
	unsigned long flags;
	int err = -EBUSY;

	/* The dump callback needs to be set */
	if (!dumper->dump)
		return -EINVAL;

	spin_lock_irqsave(&dump_list_lock, flags);
	/* Don't allow registering multiple times */
	if (!dumper->registered) {
		dumper->registered = 1;
		list_add_tail_rcu(&dumper->list, &dump_list);
		err = 0;
	}
	spin_unlock_irqrestore(&dump_list_lock, flags);

	return err;
}
EXPORT_SYMBOL_GPL(kmsg_dump_register);

int kmsg_dump_unregister(struct kmsg_dumper *dumper)
{
	unsigned long flags;
	int err = -EINVAL;

	spin_lock_irqsave(&dump_list_lock, flags);
	if (dumper->registered) {
		dumper->registered = 0;
		list_del_rcu(&dumper->list);
		err = 0;
	}
	spin_unlock_irqrestore(&dump_list_lock, flags);
	synchronize_rcu();

	return err;
}
EXPORT_SYMBOL_GPL(kmsg_dump_unregister);

static bool always_kmsg_dump;
module_param_named(always_kmsg_dump, always_kmsg_dump, bool, S_IRUGO | S_IWUSR);

const char *kmsg_dump_reason_str(enum kmsg_dump_reason reason)
{
	switch (reason) {
	case KMSG_DUMP_PANIC:
		return "Panic";
	case KMSG_DUMP_OOPS:
		return "Oops";
	case KMSG_DUMP_EMERG:
		return "Emergency";
	case KMSG_DUMP_SHUTDOWN:
		return "Shutdown";
	default:
		return "Unknown";
	}
}
EXPORT_SYMBOL_GPL(kmsg_dump_reason_str);

void kmsg_dump(enum kmsg_dump_reason reason)
{
	struct kmsg_dumper *dumper;

	rcu_read_lock();
	list_for_each_entry_rcu(dumper, &dump_list, list) {
		enum kmsg_dump_reason max_reason = dumper->max_reason;

		/*
		if (max_reason == KMSG_DUMP_UNDEF) {
			max_reason = always_kmsg_dump ? KMSG_DUMP_MAX :
							KMSG_DUMP_OOPS;
		}
		if (reason > max_reason)
			continue;

		/* invoke dumper which will iterate over records */
		dumper->dump(dumper, reason);
	}
	rcu_read_unlock();
}

bool kmsg_dump_get_line(struct kmsg_dump_iter *iter, bool syslog,
			char *line, size_t size, size_t *len)
{
	u64 min_seq = latched_seq_read_nolock(&clear_seq);
	struct printk_info info;
	unsigned int line_count;
	struct printk_record r;
	size_t l = 0;
	bool ret = false;

	if (iter->cur_seq < min_seq)
		iter->cur_seq = min_seq;

	prb_rec_init_rd(&r, &info, line, size);

	/* Read text or count text lines? */
	if (line) {
		if (!prb_read_valid(prb, iter->cur_seq, &r))
			goto out;
		l = record_print_text(&r, syslog, printk_time);
	} else {
		if (!prb_read_valid_info(prb, iter->cur_seq,
					 &info, &line_count)) {
			goto out;
		}
		l = get_record_print_text_size(&info, line_count, syslog,
					       printk_time);

	}

	iter->cur_seq = r.info->seq + 1;
	ret = true;
out:
	if (len)
		*len = l;
	return ret;
}
EXPORT_SYMBOL_GPL(kmsg_dump_get_line);

bool kmsg_dump_get_buffer(struct kmsg_dump_iter *iter, bool syslog,
			  char *buf, size_t size, size_t *len_out)
{
	u64 min_seq = latched_seq_read_nolock(&clear_seq);
	struct printk_info info;
	struct printk_record r;
	u64 seq;
	u64 next_seq;
	size_t len = 0;
	bool ret = false;
	bool time = printk_time;

	if (!buf || !size)
		goto out;

	if (iter->cur_seq < min_seq)
		iter->cur_seq = min_seq;

	if (prb_read_valid_info(prb, iter->cur_seq, &info, NULL)) {
		if (info.seq != iter->cur_seq) {
			/* messages are gone, move to first available one */
			iter->cur_seq = info.seq;
		}
	}

	/* last entry */
	if (iter->cur_seq >= iter->next_seq)
		goto out;

	/*
	seq = find_first_fitting_seq(iter->cur_seq, iter->next_seq,
				     size - 1, syslog, time);

	/*
	next_seq = seq;

	prb_rec_init_rd(&r, &info, buf, size);

	len = 0;
	prb_for_each_record(seq, prb, seq, &r) {
		if (r.info->seq >= iter->next_seq)
			break;

		len += record_print_text(&r, syslog, time);

		/* Adjust record to store to remaining buffer space. */
		prb_rec_init_rd(&r, &info, buf + len, size - len);
	}

	iter->next_seq = next_seq;
	ret = true;
out:
	if (len_out)
		*len_out = len;
	return ret;
}
EXPORT_SYMBOL_GPL(kmsg_dump_get_buffer);

void kmsg_dump_rewind(struct kmsg_dump_iter *iter)
{
	iter->cur_seq = latched_seq_read_nolock(&clear_seq);
	iter->next_seq = prb_next_seq(prb);
}
EXPORT_SYMBOL_GPL(kmsg_dump_rewind);

#endif

#ifdef CONFIG_SMP
static atomic_t printk_cpu_sync_owner = ATOMIC_INIT(-1);
static atomic_t printk_cpu_sync_nested = ATOMIC_INIT(0);

void __printk_cpu_sync_wait(void)
{
	do {
		cpu_relax();
	} while (atomic_read(&printk_cpu_sync_owner) != -1);
}
EXPORT_SYMBOL(__printk_cpu_sync_wait);

int __printk_cpu_sync_try_get(void)
{
	int cpu;
	int old;

	cpu = smp_processor_id();

	/*
	old = atomic_cmpxchg_acquire(&printk_cpu_sync_owner, -1,
				     cpu); /* LMM(__printk_cpu_sync_try_get:A) */
	if (old == -1) {
		/*
		return 1;

	} else if (old == cpu) {
		/* This CPU is already the owner. */
		atomic_inc(&printk_cpu_sync_nested);
		return 1;
	}

	return 0;
}
EXPORT_SYMBOL(__printk_cpu_sync_try_get);

void __printk_cpu_sync_put(void)
{
	if (atomic_read(&printk_cpu_sync_nested)) {
		atomic_dec(&printk_cpu_sync_nested);
		return;
	}

	/*

	/*
	atomic_set_release(&printk_cpu_sync_owner,
			   -1); /* LMM(__printk_cpu_sync_put:B) */
}
EXPORT_SYMBOL(__printk_cpu_sync_put);
#endif /* CONFIG_SMP */
