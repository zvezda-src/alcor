
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/slab.h>
#include <linux/sysctl.h>
#include <linux/bitmap.h>
#include <linux/signal.h>
#include <linux/panic.h>
#include <linux/printk.h>
#include <linux/proc_fs.h>
#include <linux/security.h>
#include <linux/ctype.h>
#include <linux/kmemleak.h>
#include <linux/filter.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/net.h>
#include <linux/sysrq.h>
#include <linux/highuid.h>
#include <linux/writeback.h>
#include <linux/ratelimit.h>
#include <linux/compaction.h>
#include <linux/hugetlb.h>
#include <linux/initrd.h>
#include <linux/key.h>
#include <linux/times.h>
#include <linux/limits.h>
#include <linux/dcache.h>
#include <linux/syscalls.h>
#include <linux/vmstat.h>
#include <linux/nfs_fs.h>
#include <linux/acpi.h>
#include <linux/reboot.h>
#include <linux/ftrace.h>
#include <linux/perf_event.h>
#include <linux/oom.h>
#include <linux/kmod.h>
#include <linux/capability.h>
#include <linux/binfmts.h>
#include <linux/sched/sysctl.h>
#include <linux/mount.h>
#include <linux/userfaultfd_k.h>
#include <linux/pid.h>

#include "../lib/kstrtox.h"

#include <linux/uaccess.h>
#include <asm/processor.h>

#ifdef CONFIG_X86
#include <asm/nmi.h>
#include <asm/stacktrace.h>
#include <asm/io.h>
#endif
#ifdef CONFIG_SPARC
#include <asm/setup.h>
#endif
#ifdef CONFIG_RT_MUTEXES
#include <linux/rtmutex.h>
#endif

#if defined(CONFIG_SYSCTL)


#ifdef CONFIG_PERF_EVENTS
static const int six_hundred_forty_kb = 640 * 1024;
#endif


static const int ngroups_max = NGROUPS_MAX;
static const int cap_last_cap = CAP_LAST_CAP;

#ifdef CONFIG_PROC_SYSCTL

enum sysctl_writes_mode {
	SYSCTL_WRITES_LEGACY		= -1,
	SYSCTL_WRITES_WARN		= 0,
	SYSCTL_WRITES_STRICT		= 1,
};

static enum sysctl_writes_mode sysctl_writes_strict = SYSCTL_WRITES_STRICT;
#endif /* CONFIG_PROC_SYSCTL */

#if defined(HAVE_ARCH_PICK_MMAP_LAYOUT) || \
    defined(CONFIG_ARCH_WANT_DEFAULT_TOPDOWN_MMAP_LAYOUT)
int sysctl_legacy_va_layout;
#endif

#ifdef CONFIG_COMPACTION
static const int max_extfrag_threshold = 1000;
#endif

#endif /* CONFIG_SYSCTL */


#ifdef CONFIG_PROC_SYSCTL

static int _proc_do_string(char *data, int maxlen, int write,
		char *buffer, size_t *lenp, loff_t *ppos)
{
	size_t len;
	char c, *p;

	if (!data || !maxlen || !*lenp) {
		*lenp = 0;
		return 0;
	}

	if (write) {
		if (sysctl_writes_strict == SYSCTL_WRITES_STRICT) {
			/* Only continue writes not past the end of buffer. */
			len = strlen(data);
			if (len > maxlen - 1)
				len = maxlen - 1;

			if (*ppos > len)
				return 0;
			len = *ppos;
		} else {
			/* Start writing from beginning of buffer. */
			len = 0;
		}

		*ppos += *lenp;
		p = buffer;
		while ((p - buffer) < *lenp && len < maxlen - 1) {
			c = *(p++);
			if (c == 0 || c == '\n')
				break;
			data[len++] = c;
		}
		data[len] = 0;
	} else {
		len = strlen(data);
		if (len > maxlen)
			len = maxlen;

		if (*ppos > len) {
			*lenp = 0;
			return 0;
		}

		data += *ppos;
		len  -= *ppos;

		if (len > *lenp)
			len = *lenp;
		if (len)
			memcpy(buffer, data, len);
		if (len < *lenp) {
			buffer[len] = '\n';
			len++;
		}
		*lenp = len;
		*ppos += len;
	}
	return 0;
}

static void warn_sysctl_write(struct ctl_table *table)
{
	pr_warn_once("%s wrote to %s when file position was not 0!\n"
		"This will not be supported in the future. To silence this\n"
		"warning, set kernel.sysctl_writes_strict = -1\n",
		current->comm, table->procname);
}

static bool proc_first_pos_non_zero_ignore(loff_t *ppos,
					   struct ctl_table *table)
{
	if (!*ppos)
		return false;

	switch (sysctl_writes_strict) {
	case SYSCTL_WRITES_STRICT:
		return true;
	case SYSCTL_WRITES_WARN:
		warn_sysctl_write(table);
		return false;
	default:
		return false;
	}
}

int proc_dostring(struct ctl_table *table, int write,
		  void *buffer, size_t *lenp, loff_t *ppos)
{
	if (write)
		proc_first_pos_non_zero_ignore(ppos, table);

	return _proc_do_string(table->data, table->maxlen, write, buffer, lenp,
			ppos);
}

static size_t proc_skip_spaces(char **buf)
{
	size_t ret;
	char *tmp = skip_spaces(*buf);
	ret = tmp - *buf;
	return ret;
}

static void proc_skip_char(char **buf, size_t *size, const char v)
{
	while (*size) {
		if (**buf != v)
			break;
		(*size)--;
		(*buf)++;
	}
}

static int strtoul_lenient(const char *cp, char **endp, unsigned int base,
			   unsigned long *res)
{
	unsigned long long result;
	unsigned int rv;

	cp = _parse_integer_fixup_radix(cp, &base);
	rv = _parse_integer(cp, base, &result);
	if ((rv & KSTRTOX_OVERFLOW) || (result != (unsigned long)result))
		return -ERANGE;

	cp += rv;

	if (endp)
		*endp = (char *)cp;

	return 0;
}

#define TMPBUFLEN 22
static int proc_get_long(char **buf, size_t *size,
			  unsigned long *val, bool *neg,
			  const char *perm_tr, unsigned perm_tr_len, char *tr)
{
	int len;
	char *p, tmp[TMPBUFLEN];

	if (!*size)
		return -EINVAL;

	len = *size;
	if (len > TMPBUFLEN - 1)
		len = TMPBUFLEN - 1;

	memcpy(tmp, *buf, len);

	tmp[len] = 0;
	p = tmp;
	if (*p == '-' && *size > 1) {
		*neg = true;
		p++;
	} else
		*neg = false;
	if (!isdigit(*p))
		return -EINVAL;

	if (strtoul_lenient(p, &p, 0, val))
		return -EINVAL;

	len = p - tmp;

	/* We don't know if the next char is whitespace thus we may accept
	 * invalid integers (e.g. 1234...a) or two integers instead of one
	 * (e.g. 123...1). So lets not allow such large numbers. */
	if (len == TMPBUFLEN - 1)
		return -EINVAL;

	if (len < *size && perm_tr_len && !memchr(perm_tr, *p, perm_tr_len))
		return -EINVAL;

	if (tr && (len < *size))
		*tr = *p;


	return 0;
}

static void proc_put_long(void **buf, size_t *size, unsigned long val, bool neg)
{
	int len;
	char tmp[TMPBUFLEN], *p = tmp;

	sprintf(p, "%s%lu", neg ? "-" : "", val);
	len = strlen(tmp);
	if (len > *size)
		len = *size;
	memcpy(*buf, tmp, len);
}
#undef TMPBUFLEN

static void proc_put_char(void **buf, size_t *size, char c)
{
	if (*size) {
		char **buffer = (char **)buf;
		**buffer = c;

		(*size)--;
		(*buffer)++;
		*buf = *buffer;
	}
}

static int do_proc_dobool_conv(bool *negp, unsigned long *lvalp,
				int *valp,
				int write, void *data)
{
	if (write) {
		*(bool *)valp = *lvalp;
	} else {
		int val = *(bool *)valp;

		*lvalp = (unsigned long)val;
		*negp = false;
	}
	return 0;
}

static int do_proc_dointvec_conv(bool *negp, unsigned long *lvalp,
				 int *valp,
				 int write, void *data)
{
	if (write) {
		if (*negp) {
			if (*lvalp > (unsigned long) INT_MAX + 1)
				return -EINVAL;
			WRITE_ONCE(*valp, -*lvalp);
		} else {
			if (*lvalp > (unsigned long) INT_MAX)
				return -EINVAL;
			WRITE_ONCE(*valp, *lvalp);
		}
	} else {
		int val = READ_ONCE(*valp);
		if (val < 0) {
			*negp = true;
			*lvalp = -(unsigned long)val;
		} else {
			*negp = false;
			*lvalp = (unsigned long)val;
		}
	}
	return 0;
}

static int do_proc_douintvec_conv(unsigned long *lvalp,
				  unsigned int *valp,
				  int write, void *data)
{
	if (write) {
		if (*lvalp > UINT_MAX)
			return -EINVAL;
		WRITE_ONCE(*valp, *lvalp);
	} else {
		unsigned int val = READ_ONCE(*valp);
		*lvalp = (unsigned long)val;
	}
	return 0;
}

static const char proc_wspace_sep[] = { ' ', '\t', '\n' };

static int __do_proc_dointvec(void *tbl_data, struct ctl_table *table,
		  int write, void *buffer,
		  size_t *lenp, loff_t *ppos,
		  int (*conv)(bool *negp, unsigned long *lvalp, int *valp,
			      int write, void *data),
		  void *data)
{
	int *i, vleft, first = 1, err = 0;
	size_t left;
	char *p;
	
	if (!tbl_data || !table->maxlen || !*lenp || (*ppos && !write)) {
		*lenp = 0;
		return 0;
	}
	
	i = (int *) tbl_data;
	vleft = table->maxlen / sizeof(*i);
	left = *lenp;

	if (!conv)
		conv = do_proc_dointvec_conv;

	if (write) {
		if (proc_first_pos_non_zero_ignore(ppos, table))
			goto out;

		if (left > PAGE_SIZE - 1)
			left = PAGE_SIZE - 1;
		p = buffer;
	}

	for (; left && vleft--; i++, first=0) {
		unsigned long lval;
		bool neg;

		if (write) {
			left -= proc_skip_spaces(&p);

			if (!left)
				break;
			err = proc_get_long(&p, &left, &lval, &neg,
					     proc_wspace_sep,
					     sizeof(proc_wspace_sep), NULL);
			if (err)
				break;
			if (conv(&neg, &lval, i, 1, data)) {
				err = -EINVAL;
				break;
			}
		} else {
			if (conv(&neg, &lval, i, 0, data)) {
				err = -EINVAL;
				break;
			}
			if (!first)
				proc_put_char(&buffer, &left, '\t');
			proc_put_long(&buffer, &left, lval, neg);
		}
	}

	if (!write && !first && left && !err)
		proc_put_char(&buffer, &left, '\n');
	if (write && !err && left)
		left -= proc_skip_spaces(&p);
	if (write && first)
		return err ? : -EINVAL;
out:
	return err;
}

static int do_proc_dointvec(struct ctl_table *table, int write,
		  void *buffer, size_t *lenp, loff_t *ppos,
		  int (*conv)(bool *negp, unsigned long *lvalp, int *valp,
			      int write, void *data),
		  void *data)
{
	return __do_proc_dointvec(table->data, table, write,
			buffer, lenp, ppos, conv, data);
}

static int do_proc_douintvec_w(unsigned int *tbl_data,
			       struct ctl_table *table,
			       void *buffer,
			       size_t *lenp, loff_t *ppos,
			       int (*conv)(unsigned long *lvalp,
					   unsigned int *valp,
					   int write, void *data),
			       void *data)
{
	unsigned long lval;
	int err = 0;
	size_t left;
	bool neg;
	char *p = buffer;

	left = *lenp;

	if (proc_first_pos_non_zero_ignore(ppos, table))
		goto bail_early;

	if (left > PAGE_SIZE - 1)
		left = PAGE_SIZE - 1;

	left -= proc_skip_spaces(&p);
	if (!left) {
		err = -EINVAL;
		goto out_free;
	}

	err = proc_get_long(&p, &left, &lval, &neg,
			     proc_wspace_sep,
			     sizeof(proc_wspace_sep), NULL);
	if (err || neg) {
		err = -EINVAL;
		goto out_free;
	}

	if (conv(&lval, tbl_data, 1, data)) {
		err = -EINVAL;
		goto out_free;
	}

	if (!err && left)
		left -= proc_skip_spaces(&p);

out_free:
	if (err)
		return -EINVAL;

	return 0;

	/* This is in keeping with old __do_proc_dointvec() */
bail_early:
	return err;
}

static int do_proc_douintvec_r(unsigned int *tbl_data, void *buffer,
			       size_t *lenp, loff_t *ppos,
			       int (*conv)(unsigned long *lvalp,
					   unsigned int *valp,
					   int write, void *data),
			       void *data)
{
	unsigned long lval;
	int err = 0;
	size_t left;

	left = *lenp;

	if (conv(&lval, tbl_data, 0, data)) {
		err = -EINVAL;
		goto out;
	}

	proc_put_long(&buffer, &left, lval, false);
	if (!left)
		goto out;

	proc_put_char(&buffer, &left, '\n');

out:

	return err;
}

static int __do_proc_douintvec(void *tbl_data, struct ctl_table *table,
			       int write, void *buffer,
			       size_t *lenp, loff_t *ppos,
			       int (*conv)(unsigned long *lvalp,
					   unsigned int *valp,
					   int write, void *data),
			       void *data)
{
	unsigned int *i, vleft;

	if (!tbl_data || !table->maxlen || !*lenp || (*ppos && !write)) {
		*lenp = 0;
		return 0;
	}

	i = (unsigned int *) tbl_data;
	vleft = table->maxlen / sizeof(*i);

	/*
	if (vleft != 1) {
		*lenp = 0;
		return -EINVAL;
	}

	if (!conv)
		conv = do_proc_douintvec_conv;

	if (write)
		return do_proc_douintvec_w(i, table, buffer, lenp, ppos,
					   conv, data);
	return do_proc_douintvec_r(i, buffer, lenp, ppos, conv, data);
}

int do_proc_douintvec(struct ctl_table *table, int write,
		      void *buffer, size_t *lenp, loff_t *ppos,
		      int (*conv)(unsigned long *lvalp,
				  unsigned int *valp,
				  int write, void *data),
		      void *data)
{
	return __do_proc_douintvec(table->data, table, write,
				   buffer, lenp, ppos, conv, data);
}

int proc_dobool(struct ctl_table *table, int write, void *buffer,
		size_t *lenp, loff_t *ppos)
{
	return do_proc_dointvec(table, write, buffer, lenp, ppos,
				do_proc_dobool_conv, NULL);
}

int proc_dointvec(struct ctl_table *table, int write, void *buffer,
		  size_t *lenp, loff_t *ppos)
{
	return do_proc_dointvec(table, write, buffer, lenp, ppos, NULL, NULL);
}

#ifdef CONFIG_COMPACTION
static int proc_dointvec_minmax_warn_RT_change(struct ctl_table *table,
		int write, void *buffer, size_t *lenp, loff_t *ppos)
{
	int ret, old;

	if (!IS_ENABLED(CONFIG_PREEMPT_RT) || !write)
		return proc_dointvec_minmax(table, write, buffer, lenp, ppos);

	old = *(int *)table->data;
	ret = proc_dointvec_minmax(table, write, buffer, lenp, ppos);
	if (ret)
		return ret;
	if (old != *(int *)table->data)
		pr_warn_once("sysctl attribute %s changed by %s[%d]\n",
			     table->procname, current->comm,
			     task_pid_nr(current));
	return ret;
}
#endif

int proc_douintvec(struct ctl_table *table, int write, void *buffer,
		size_t *lenp, loff_t *ppos)
{
	return do_proc_douintvec(table, write, buffer, lenp, ppos,
				 do_proc_douintvec_conv, NULL);
}

static int proc_taint(struct ctl_table *table, int write,
			       void *buffer, size_t *lenp, loff_t *ppos)
{
	struct ctl_table t;
	unsigned long tmptaint = get_taint();
	int err;

	if (write && !capable(CAP_SYS_ADMIN))
		return -EPERM;

	t = *table;
	t.data = &tmptaint;
	err = proc_doulongvec_minmax(&t, write, buffer, lenp, ppos);
	if (err < 0)
		return err;

	if (write) {
		int i;

		/*
		if (panic_on_taint_nousertaint && (tmptaint & panic_on_taint))
			return -EINVAL;

		/*
		for (i = 0; i < TAINT_FLAGS_COUNT; i++)
			if ((1UL << i) & tmptaint)
				add_taint(i, LOCKDEP_STILL_OK);
	}

	return err;
}

struct do_proc_dointvec_minmax_conv_param {
	int *min;
	int *max;
};

static int do_proc_dointvec_minmax_conv(bool *negp, unsigned long *lvalp,
					int *valp,
					int write, void *data)
{
	int tmp, ret;
	struct do_proc_dointvec_minmax_conv_param *param = data;
	/*
	int *ip = write ? &tmp : valp;

	ret = do_proc_dointvec_conv(negp, lvalp, ip, write, data);
	if (ret)
		return ret;

	if (write) {
		if ((param->min && *param->min > tmp) ||
		    (param->max && *param->max < tmp))
			return -EINVAL;
		WRITE_ONCE(*valp, tmp);
	}

	return 0;
}

int proc_dointvec_minmax(struct ctl_table *table, int write,
		  void *buffer, size_t *lenp, loff_t *ppos)
{
	struct do_proc_dointvec_minmax_conv_param param = {
		.min = (int *) table->extra1,
		.max = (int *) table->extra2,
	};
	return do_proc_dointvec(table, write, buffer, lenp, ppos,
				do_proc_dointvec_minmax_conv, &param);
}

struct do_proc_douintvec_minmax_conv_param {
	unsigned int *min;
	unsigned int *max;
};

static int do_proc_douintvec_minmax_conv(unsigned long *lvalp,
					 unsigned int *valp,
					 int write, void *data)
{
	int ret;
	unsigned int tmp;
	struct do_proc_douintvec_minmax_conv_param *param = data;
	/* write via temporary local uint for bounds-checking */
	unsigned int *up = write ? &tmp : valp;

	ret = do_proc_douintvec_conv(lvalp, up, write, data);
	if (ret)
		return ret;

	if (write) {
		if ((param->min && *param->min > tmp) ||
		    (param->max && *param->max < tmp))
			return -ERANGE;

		WRITE_ONCE(*valp, tmp);
	}

	return 0;
}

int proc_douintvec_minmax(struct ctl_table *table, int write,
			  void *buffer, size_t *lenp, loff_t *ppos)
{
	struct do_proc_douintvec_minmax_conv_param param = {
		.min = (unsigned int *) table->extra1,
		.max = (unsigned int *) table->extra2,
	};
	return do_proc_douintvec(table, write, buffer, lenp, ppos,
				 do_proc_douintvec_minmax_conv, &param);
}

int proc_dou8vec_minmax(struct ctl_table *table, int write,
			void *buffer, size_t *lenp, loff_t *ppos)
{
	struct ctl_table tmp;
	unsigned int min = 0, max = 255U, val;
	u8 *data = table->data;
	struct do_proc_douintvec_minmax_conv_param param = {
		.min = &min,
		.max = &max,
	};
	int res;

	/* Do not support arrays yet. */
	if (table->maxlen != sizeof(u8))
		return -EINVAL;

	if (table->extra1) {
		min = *(unsigned int *) table->extra1;
		if (min > 255U)
			return -EINVAL;
	}
	if (table->extra2) {
		max = *(unsigned int *) table->extra2;
		if (max > 255U)
			return -EINVAL;
	}

	tmp = *table;

	tmp.maxlen = sizeof(val);
	tmp.data = &val;
	val = READ_ONCE(*data);
	res = do_proc_douintvec(&tmp, write, buffer, lenp, ppos,
				do_proc_douintvec_minmax_conv, &param);
	if (res)
		return res;
	if (write)
		WRITE_ONCE(*data, val);
	return 0;
}
EXPORT_SYMBOL_GPL(proc_dou8vec_minmax);

#ifdef CONFIG_MAGIC_SYSRQ
static int sysrq_sysctl_handler(struct ctl_table *table, int write,
				void *buffer, size_t *lenp, loff_t *ppos)
{
	int tmp, ret;

	tmp = sysrq_mask();

	ret = __do_proc_dointvec(&tmp, table, write, buffer,
			       lenp, ppos, NULL, NULL);
	if (ret || !write)
		return ret;

	if (write)
		sysrq_toggle_support(tmp);

	return 0;
}
#endif

static int __do_proc_doulongvec_minmax(void *data, struct ctl_table *table,
		int write, void *buffer, size_t *lenp, loff_t *ppos,
		unsigned long convmul, unsigned long convdiv)
{
	unsigned long *i, *min, *max;
	int vleft, first = 1, err = 0;
	size_t left;
	char *p;

	if (!data || !table->maxlen || !*lenp || (*ppos && !write)) {
		*lenp = 0;
		return 0;
	}

	i = (unsigned long *) data;
	min = (unsigned long *) table->extra1;
	max = (unsigned long *) table->extra2;
	vleft = table->maxlen / sizeof(unsigned long);
	left = *lenp;

	if (write) {
		if (proc_first_pos_non_zero_ignore(ppos, table))
			goto out;

		if (left > PAGE_SIZE - 1)
			left = PAGE_SIZE - 1;
		p = buffer;
	}

	for (; left && vleft--; i++, first = 0) {
		unsigned long val;

		if (write) {
			bool neg;

			left -= proc_skip_spaces(&p);
			if (!left)
				break;

			err = proc_get_long(&p, &left, &val, &neg,
					     proc_wspace_sep,
					     sizeof(proc_wspace_sep), NULL);
			if (err || neg) {
				err = -EINVAL;
				break;
			}

			val = convmul * val / convdiv;
			if ((min && val < *min) || (max && val > *max)) {
				err = -EINVAL;
				break;
			}
			WRITE_ONCE(*i, val);
		} else {
			val = convdiv * READ_ONCE(*i) / convmul;
			if (!first)
				proc_put_char(&buffer, &left, '\t');
			proc_put_long(&buffer, &left, val, false);
		}
	}

	if (!write && !first && left && !err)
		proc_put_char(&buffer, &left, '\n');
	if (write && !err)
		left -= proc_skip_spaces(&p);
	if (write && first)
		return err ? : -EINVAL;
out:
	return err;
}

static int do_proc_doulongvec_minmax(struct ctl_table *table, int write,
		void *buffer, size_t *lenp, loff_t *ppos, unsigned long convmul,
		unsigned long convdiv)
{
	return __do_proc_doulongvec_minmax(table->data, table, write,
			buffer, lenp, ppos, convmul, convdiv);
}

int proc_doulongvec_minmax(struct ctl_table *table, int write,
			   void *buffer, size_t *lenp, loff_t *ppos)
{
    return do_proc_doulongvec_minmax(table, write, buffer, lenp, ppos, 1l, 1l);
}

int proc_doulongvec_ms_jiffies_minmax(struct ctl_table *table, int write,
				      void *buffer, size_t *lenp, loff_t *ppos)
{
    return do_proc_doulongvec_minmax(table, write, buffer,
				     lenp, ppos, HZ, 1000l);
}


static int do_proc_dointvec_jiffies_conv(bool *negp, unsigned long *lvalp,
					 int *valp,
					 int write, void *data)
{
	if (write) {
		if (*lvalp > INT_MAX / HZ)
			return 1;
		if (*negp)
			WRITE_ONCE(*valp, -*lvalp * HZ);
		else
			WRITE_ONCE(*valp, *lvalp * HZ);
	} else {
		int val = READ_ONCE(*valp);
		unsigned long lval;
		if (val < 0) {
			*negp = true;
			lval = -(unsigned long)val;
		} else {
			*negp = false;
			lval = (unsigned long)val;
		}
		*lvalp = lval / HZ;
	}
	return 0;
}

static int do_proc_dointvec_userhz_jiffies_conv(bool *negp, unsigned long *lvalp,
						int *valp,
						int write, void *data)
{
	if (write) {
		if (USER_HZ < HZ && *lvalp > (LONG_MAX / HZ) * USER_HZ)
			return 1;
		*valp = clock_t_to_jiffies(*negp ? -*lvalp : *lvalp);
	} else {
		int val = *valp;
		unsigned long lval;
		if (val < 0) {
			*negp = true;
			lval = -(unsigned long)val;
		} else {
			*negp = false;
			lval = (unsigned long)val;
		}
		*lvalp = jiffies_to_clock_t(lval);
	}
	return 0;
}

static int do_proc_dointvec_ms_jiffies_conv(bool *negp, unsigned long *lvalp,
					    int *valp,
					    int write, void *data)
{
	if (write) {
		unsigned long jif = msecs_to_jiffies(*negp ? -*lvalp : *lvalp);

		if (jif > INT_MAX)
			return 1;
		WRITE_ONCE(*valp, (int)jif);
	} else {
		int val = READ_ONCE(*valp);
		unsigned long lval;
		if (val < 0) {
			*negp = true;
			lval = -(unsigned long)val;
		} else {
			*negp = false;
			lval = (unsigned long)val;
		}
		*lvalp = jiffies_to_msecs(lval);
	}
	return 0;
}

static int do_proc_dointvec_ms_jiffies_minmax_conv(bool *negp, unsigned long *lvalp,
						int *valp, int write, void *data)
{
	int tmp, ret;
	struct do_proc_dointvec_minmax_conv_param *param = data;
	/*
	int *ip = write ? &tmp : valp;

	ret = do_proc_dointvec_ms_jiffies_conv(negp, lvalp, ip, write, data);
	if (ret)
		return ret;

	if (write) {
		if ((param->min && *param->min > tmp) ||
				(param->max && *param->max < tmp))
			return -EINVAL;
		*valp = tmp;
	}
	return 0;
}

int proc_dointvec_jiffies(struct ctl_table *table, int write,
			  void *buffer, size_t *lenp, loff_t *ppos)
{
    return do_proc_dointvec(table,write,buffer,lenp,ppos,
		    	    do_proc_dointvec_jiffies_conv,NULL);
}

int proc_dointvec_ms_jiffies_minmax(struct ctl_table *table, int write,
			  void *buffer, size_t *lenp, loff_t *ppos)
{
	struct do_proc_dointvec_minmax_conv_param param = {
		.min = (int *) table->extra1,
		.max = (int *) table->extra2,
	};
	return do_proc_dointvec(table, write, buffer, lenp, ppos,
			do_proc_dointvec_ms_jiffies_minmax_conv, &param);
}

int proc_dointvec_userhz_jiffies(struct ctl_table *table, int write,
				 void *buffer, size_t *lenp, loff_t *ppos)
{
    return do_proc_dointvec(table,write,buffer,lenp,ppos,
		    	    do_proc_dointvec_userhz_jiffies_conv,NULL);
}

int proc_dointvec_ms_jiffies(struct ctl_table *table, int write, void *buffer,
		size_t *lenp, loff_t *ppos)
{
	return do_proc_dointvec(table, write, buffer, lenp, ppos,
				do_proc_dointvec_ms_jiffies_conv, NULL);
}

static int proc_do_cad_pid(struct ctl_table *table, int write, void *buffer,
		size_t *lenp, loff_t *ppos)
{
	struct pid *new_pid;
	pid_t tmp;
	int r;

	tmp = pid_vnr(cad_pid);

	r = __do_proc_dointvec(&tmp, table, write, buffer,
			       lenp, ppos, NULL, NULL);
	if (r || !write)
		return r;

	new_pid = find_get_pid(tmp);
	if (!new_pid)
		return -ESRCH;

	put_pid(xchg(&cad_pid, new_pid));
	return 0;
}

int proc_do_large_bitmap(struct ctl_table *table, int write,
			 void *buffer, size_t *lenp, loff_t *ppos)
{
	int err = 0;
	size_t left = *lenp;
	unsigned long bitmap_len = table->maxlen;
	unsigned long *bitmap = *(unsigned long **) table->data;
	unsigned long *tmp_bitmap = NULL;
	char tr_a[] = { '-', ',', '\n' }, tr_b[] = { ',', '\n', 0 }, c;

	if (!bitmap || !bitmap_len || !left || (*ppos && !write)) {
		*lenp = 0;
		return 0;
	}

	if (write) {
		char *p = buffer;
		size_t skipped = 0;

		if (left > PAGE_SIZE - 1) {
			left = PAGE_SIZE - 1;
			/* How much of the buffer we'll skip this pass */
			skipped = *lenp - left;
		}

		tmp_bitmap = bitmap_zalloc(bitmap_len, GFP_KERNEL);
		if (!tmp_bitmap)
			return -ENOMEM;
		proc_skip_char(&p, &left, '\n');
		while (!err && left) {
			unsigned long val_a, val_b;
			bool neg;
			size_t saved_left;

			/* In case we stop parsing mid-number, we can reset */
			saved_left = left;
			err = proc_get_long(&p, &left, &val_a, &neg, tr_a,
					     sizeof(tr_a), &c);
			/*
			if ((left <= 1) && skipped) {
				left = saved_left;
				break;
			}

			if (err)
				break;
			if (val_a >= bitmap_len || neg) {
				err = -EINVAL;
				break;
			}

			val_b = val_a;
			if (left) {
				p++;
				left--;
			}

			if (c == '-') {
				err = proc_get_long(&p, &left, &val_b,
						     &neg, tr_b, sizeof(tr_b),
						     &c);
				/*
				if (!left && skipped) {
					left = saved_left;
					break;
				}

				if (err)
					break;
				if (val_b >= bitmap_len || neg ||
				    val_a > val_b) {
					err = -EINVAL;
					break;
				}
				if (left) {
					p++;
					left--;
				}
			}

			bitmap_set(tmp_bitmap, val_a, val_b - val_a + 1);
			proc_skip_char(&p, &left, '\n');
		}
		left += skipped;
	} else {
		unsigned long bit_a, bit_b = 0;
		bool first = 1;

		while (left) {
			bit_a = find_next_bit(bitmap, bitmap_len, bit_b);
			if (bit_a >= bitmap_len)
				break;
			bit_b = find_next_zero_bit(bitmap, bitmap_len,
						   bit_a + 1) - 1;

			if (!first)
				proc_put_char(&buffer, &left, ',');
			proc_put_long(&buffer, &left, bit_a, false);
			if (bit_a != bit_b) {
				proc_put_char(&buffer, &left, '-');
				proc_put_long(&buffer, &left, bit_b, false);
			}

			first = 0; bit_b++;
		}
		proc_put_char(&buffer, &left, '\n');
	}

	if (!err) {
		if (write) {
			if (*ppos)
				bitmap_or(bitmap, bitmap, tmp_bitmap, bitmap_len);
			else
				bitmap_copy(bitmap, tmp_bitmap, bitmap_len);
		}
		*lenp -= left;
		*ppos += *lenp;
	}

	bitmap_free(tmp_bitmap);
	return err;
}

#else /* CONFIG_PROC_SYSCTL */

int proc_dostring(struct ctl_table *table, int write,
		  void *buffer, size_t *lenp, loff_t *ppos)
{
	return -ENOSYS;
}

int proc_dobool(struct ctl_table *table, int write,
		void *buffer, size_t *lenp, loff_t *ppos)
{
	return -ENOSYS;
}

int proc_dointvec(struct ctl_table *table, int write,
		  void *buffer, size_t *lenp, loff_t *ppos)
{
	return -ENOSYS;
}

int proc_douintvec(struct ctl_table *table, int write,
		  void *buffer, size_t *lenp, loff_t *ppos)
{
	return -ENOSYS;
}

int proc_dointvec_minmax(struct ctl_table *table, int write,
		    void *buffer, size_t *lenp, loff_t *ppos)
{
	return -ENOSYS;
}

int proc_douintvec_minmax(struct ctl_table *table, int write,
			  void *buffer, size_t *lenp, loff_t *ppos)
{
	return -ENOSYS;
}

int proc_dou8vec_minmax(struct ctl_table *table, int write,
			void *buffer, size_t *lenp, loff_t *ppos)
{
	return -ENOSYS;
}

int proc_dointvec_jiffies(struct ctl_table *table, int write,
		    void *buffer, size_t *lenp, loff_t *ppos)
{
	return -ENOSYS;
}

int proc_dointvec_ms_jiffies_minmax(struct ctl_table *table, int write,
				    void *buffer, size_t *lenp, loff_t *ppos)
{
	return -ENOSYS;
}

int proc_dointvec_userhz_jiffies(struct ctl_table *table, int write,
		    void *buffer, size_t *lenp, loff_t *ppos)
{
	return -ENOSYS;
}

int proc_dointvec_ms_jiffies(struct ctl_table *table, int write,
			     void *buffer, size_t *lenp, loff_t *ppos)
{
	return -ENOSYS;
}

int proc_doulongvec_minmax(struct ctl_table *table, int write,
		    void *buffer, size_t *lenp, loff_t *ppos)
{
	return -ENOSYS;
}

int proc_doulongvec_ms_jiffies_minmax(struct ctl_table *table, int write,
				      void *buffer, size_t *lenp, loff_t *ppos)
{
	return -ENOSYS;
}

int proc_do_large_bitmap(struct ctl_table *table, int write,
			 void *buffer, size_t *lenp, loff_t *ppos)
{
	return -ENOSYS;
}

#endif /* CONFIG_PROC_SYSCTL */

#if defined(CONFIG_SYSCTL)
int proc_do_static_key(struct ctl_table *table, int write,
		       void *buffer, size_t *lenp, loff_t *ppos)
{
	struct static_key *key = (struct static_key *)table->data;
	static DEFINE_MUTEX(static_key_mutex);
	int val, ret;
	struct ctl_table tmp = {
		.data   = &val,
		.maxlen = sizeof(val),
		.mode   = table->mode,
		.extra1 = SYSCTL_ZERO,
		.extra2 = SYSCTL_ONE,
	};

	if (write && !capable(CAP_SYS_ADMIN))
		return -EPERM;

	mutex_lock(&static_key_mutex);
	val = static_key_enabled(key);
	ret = proc_dointvec_minmax(&tmp, write, buffer, lenp, ppos);
	if (write && !ret) {
		if (val)
			static_key_enable(key);
		else
			static_key_disable(key);
	}
	mutex_unlock(&static_key_mutex);
	return ret;
}

static struct ctl_table kern_table[] = {
#ifdef CONFIG_NUMA_BALANCING
	{
		.procname	= "numa_balancing",
		.data		= NULL, /* filled in by handler */
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= sysctl_numa_balancing,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_FOUR,
	},
#endif /* CONFIG_NUMA_BALANCING */
	{
		.procname	= "panic",
		.data		= &panic_timeout,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
#ifdef CONFIG_PROC_SYSCTL
	{
		.procname	= "tainted",
		.maxlen 	= sizeof(long),
		.mode		= 0644,
		.proc_handler	= proc_taint,
	},
	{
		.procname	= "sysctl_writes_strict",
		.data		= &sysctl_writes_strict,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_NEG_ONE,
		.extra2		= SYSCTL_ONE,
	},
#endif
	{
		.procname	= "print-fatal-signals",
		.data		= &print_fatal_signals,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
#ifdef CONFIG_SPARC
	{
		.procname	= "reboot-cmd",
		.data		= reboot_command,
		.maxlen		= 256,
		.mode		= 0644,
		.proc_handler	= proc_dostring,
	},
	{
		.procname	= "stop-a",
		.data		= &stop_a_enabled,
		.maxlen		= sizeof (int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "scons-poweroff",
		.data		= &scons_pwroff,
		.maxlen		= sizeof (int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
#endif
#ifdef CONFIG_SPARC64
	{
		.procname	= "tsb-ratio",
		.data		= &sysctl_tsb_ratio,
		.maxlen		= sizeof (int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
#endif
#ifdef CONFIG_PARISC
	{
		.procname	= "soft-power",
		.data		= &pwrsw_enabled,
		.maxlen		= sizeof (int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
#endif
#ifdef CONFIG_SYSCTL_ARCH_UNALIGN_ALLOW
	{
		.procname	= "unaligned-trap",
		.data		= &unaligned_enabled,
		.maxlen		= sizeof (int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
#endif
#ifdef CONFIG_STACK_TRACER
	{
		.procname	= "stack_tracer_enabled",
		.data		= &stack_tracer_enabled,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= stack_trace_sysctl,
	},
#endif
#ifdef CONFIG_TRACING
	{
		.procname	= "ftrace_dump_on_oops",
		.data		= &ftrace_dump_on_oops,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "traceoff_on_warning",
		.data		= &__disable_trace_on_warning,
		.maxlen		= sizeof(__disable_trace_on_warning),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "tracepoint_printk",
		.data		= &tracepoint_printk,
		.maxlen		= sizeof(tracepoint_printk),
		.mode		= 0644,
		.proc_handler	= tracepoint_printk_sysctl,
	},
#endif
#ifdef CONFIG_MODULES
	{
		.procname	= "modprobe",
		.data		= &modprobe_path,
		.maxlen		= KMOD_PATH_LEN,
		.mode		= 0644,
		.proc_handler	= proc_dostring,
	},
	{
		.procname	= "modules_disabled",
		.data		= &modules_disabled,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		/* only handle a transition from default "0" to "1" */
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ONE,
		.extra2		= SYSCTL_ONE,
	},
#endif
#ifdef CONFIG_UEVENT_HELPER
	{
		.procname	= "hotplug",
		.data		= &uevent_helper,
		.maxlen		= UEVENT_HELPER_PATH_LEN,
		.mode		= 0644,
		.proc_handler	= proc_dostring,
	},
#endif
#ifdef CONFIG_MAGIC_SYSRQ
	{
		.procname	= "sysrq",
		.data		= NULL,
		.maxlen		= sizeof (int),
		.mode		= 0644,
		.proc_handler	= sysrq_sysctl_handler,
	},
#endif
#ifdef CONFIG_PROC_SYSCTL
	{
		.procname	= "cad_pid",
		.data		= NULL,
		.maxlen		= sizeof (int),
		.mode		= 0600,
		.proc_handler	= proc_do_cad_pid,
	},
#endif
	{
		.procname	= "threads-max",
		.data		= NULL,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= sysctl_max_threads,
	},
	{
		.procname	= "usermodehelper",
		.mode		= 0555,
		.child		= usermodehelper_table,
	},
	{
		.procname	= "overflowuid",
		.data		= &overflowuid,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_MAXOLDUID,
	},
	{
		.procname	= "overflowgid",
		.data		= &overflowgid,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_MAXOLDUID,
	},
#ifdef CONFIG_S390
	{
		.procname	= "userprocess_debug",
		.data		= &show_unhandled_signals,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
#endif
	{
		.procname	= "pid_max",
		.data		= &pid_max,
		.maxlen		= sizeof (int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &pid_max_min,
		.extra2		= &pid_max_max,
	},
	{
		.procname	= "panic_on_oops",
		.data		= &panic_on_oops,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "panic_print",
		.data		= &panic_print,
		.maxlen		= sizeof(unsigned long),
		.mode		= 0644,
		.proc_handler	= proc_doulongvec_minmax,
	},
	{
		.procname	= "ngroups_max",
		.data		= (void *)&ngroups_max,
		.maxlen		= sizeof (int),
		.mode		= 0444,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "cap_last_cap",
		.data		= (void *)&cap_last_cap,
		.maxlen		= sizeof(int),
		.mode		= 0444,
		.proc_handler	= proc_dointvec,
	},
#if defined(CONFIG_X86_LOCAL_APIC) && defined(CONFIG_X86)
	{
		.procname       = "unknown_nmi_panic",
		.data           = &unknown_nmi_panic,
		.maxlen         = sizeof (int),
		.mode           = 0644,
		.proc_handler   = proc_dointvec,
	},
#endif

#if (defined(CONFIG_X86_32) || defined(CONFIG_PARISC)) && \
	defined(CONFIG_DEBUG_STACKOVERFLOW)
	{
		.procname	= "panic_on_stackoverflow",
		.data		= &sysctl_panic_on_stackoverflow,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
#endif
#if defined(CONFIG_X86)
	{
		.procname	= "panic_on_unrecovered_nmi",
		.data		= &panic_on_unrecovered_nmi,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "panic_on_io_nmi",
		.data		= &panic_on_io_nmi,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "bootloader_type",
		.data		= &bootloader_type,
		.maxlen		= sizeof (int),
		.mode		= 0444,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "bootloader_version",
		.data		= &bootloader_version,
		.maxlen		= sizeof (int),
		.mode		= 0444,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "io_delay_type",
		.data		= &io_delay_type,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
#endif
#if defined(CONFIG_MMU)
	{
		.procname	= "randomize_va_space",
		.data		= &randomize_va_space,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
#endif
#if defined(CONFIG_S390) && defined(CONFIG_SMP)
	{
		.procname	= "spin_retry",
		.data		= &spin_retry,
		.maxlen		= sizeof (int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
#endif
#if	defined(CONFIG_ACPI_SLEEP) && defined(CONFIG_X86)
	{
		.procname	= "acpi_video_flags",
		.data		= &acpi_realmode_flags,
		.maxlen		= sizeof (unsigned long),
		.mode		= 0644,
		.proc_handler	= proc_doulongvec_minmax,
	},
#endif
#ifdef CONFIG_SYSCTL_ARCH_UNALIGN_NO_WARN
	{
		.procname	= "ignore-unaligned-usertrap",
		.data		= &no_unaligned_warning,
		.maxlen		= sizeof (int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
#endif
#ifdef CONFIG_IA64
	{
		.procname	= "unaligned-dump-stack",
		.data		= &unaligned_dump_stack,
		.maxlen		= sizeof (int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
#endif
#ifdef CONFIG_RT_MUTEXES
	{
		.procname	= "max_lock_depth",
		.data		= &max_lock_depth,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
#endif
#ifdef CONFIG_KEYS
	{
		.procname	= "keys",
		.mode		= 0555,
		.child		= key_sysctls,
	},
#endif
#ifdef CONFIG_PERF_EVENTS
	/*
	{
		.procname	= "perf_event_paranoid",
		.data		= &sysctl_perf_event_paranoid,
		.maxlen		= sizeof(sysctl_perf_event_paranoid),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "perf_event_mlock_kb",
		.data		= &sysctl_perf_event_mlock,
		.maxlen		= sizeof(sysctl_perf_event_mlock),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "perf_event_max_sample_rate",
		.data		= &sysctl_perf_event_sample_rate,
		.maxlen		= sizeof(sysctl_perf_event_sample_rate),
		.mode		= 0644,
		.proc_handler	= perf_proc_update_handler,
		.extra1		= SYSCTL_ONE,
	},
	{
		.procname	= "perf_cpu_time_max_percent",
		.data		= &sysctl_perf_cpu_time_max_percent,
		.maxlen		= sizeof(sysctl_perf_cpu_time_max_percent),
		.mode		= 0644,
		.proc_handler	= perf_cpu_time_max_percent_handler,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE_HUNDRED,
	},
	{
		.procname	= "perf_event_max_stack",
		.data		= &sysctl_perf_event_max_stack,
		.maxlen		= sizeof(sysctl_perf_event_max_stack),
		.mode		= 0644,
		.proc_handler	= perf_event_max_stack_handler,
		.extra1		= SYSCTL_ZERO,
		.extra2		= (void *)&six_hundred_forty_kb,
	},
	{
		.procname	= "perf_event_max_contexts_per_stack",
		.data		= &sysctl_perf_event_max_contexts_per_stack,
		.maxlen		= sizeof(sysctl_perf_event_max_contexts_per_stack),
		.mode		= 0644,
		.proc_handler	= perf_event_max_stack_handler,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE_THOUSAND,
	},
#endif
	{
		.procname	= "panic_on_warn",
		.data		= &panic_on_warn,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
#if defined(CONFIG_TREE_RCU)
	{
		.procname	= "panic_on_rcu_stall",
		.data		= &sysctl_panic_on_rcu_stall,
		.maxlen		= sizeof(sysctl_panic_on_rcu_stall),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
#endif
#if defined(CONFIG_TREE_RCU)
	{
		.procname	= "max_rcu_stall_to_panic",
		.data		= &sysctl_max_rcu_stall_to_panic,
		.maxlen		= sizeof(sysctl_max_rcu_stall_to_panic),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ONE,
		.extra2		= SYSCTL_INT_MAX,
	},
#endif
	{ }
};

static struct ctl_table vm_table[] = {
	{
		.procname	= "overcommit_memory",
		.data		= &sysctl_overcommit_memory,
		.maxlen		= sizeof(sysctl_overcommit_memory),
		.mode		= 0644,
		.proc_handler	= overcommit_policy_handler,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_TWO,
	},
	{
		.procname	= "overcommit_ratio",
		.data		= &sysctl_overcommit_ratio,
		.maxlen		= sizeof(sysctl_overcommit_ratio),
		.mode		= 0644,
		.proc_handler	= overcommit_ratio_handler,
	},
	{
		.procname	= "overcommit_kbytes",
		.data		= &sysctl_overcommit_kbytes,
		.maxlen		= sizeof(sysctl_overcommit_kbytes),
		.mode		= 0644,
		.proc_handler	= overcommit_kbytes_handler,
	},
	{
		.procname	= "page-cluster",
		.data		= &page_cluster,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
	},
	{
		.procname	= "dirtytime_expire_seconds",
		.data		= &dirtytime_expire_interval,
		.maxlen		= sizeof(dirtytime_expire_interval),
		.mode		= 0644,
		.proc_handler	= dirtytime_interval_handler,
		.extra1		= SYSCTL_ZERO,
	},
	{
		.procname	= "swappiness",
		.data		= &vm_swappiness,
		.maxlen		= sizeof(vm_swappiness),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_TWO_HUNDRED,
	},
#ifdef CONFIG_NUMA
	{
		.procname	= "numa_stat",
		.data		= &sysctl_vm_numa_stat,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= sysctl_vm_numa_stat_handler,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
#endif
#ifdef CONFIG_HUGETLB_PAGE
	{
		.procname	= "nr_hugepages",
		.data		= NULL,
		.maxlen		= sizeof(unsigned long),
		.mode		= 0644,
		.proc_handler	= hugetlb_sysctl_handler,
	},
#ifdef CONFIG_NUMA
	{
		.procname       = "nr_hugepages_mempolicy",
		.data           = NULL,
		.maxlen         = sizeof(unsigned long),
		.mode           = 0644,
		.proc_handler   = &hugetlb_mempolicy_sysctl_handler,
	},
#endif
	 {
		.procname	= "hugetlb_shm_group",
		.data		= &sysctl_hugetlb_shm_group,
		.maxlen		= sizeof(gid_t),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	 },
	{
		.procname	= "nr_overcommit_hugepages",
		.data		= NULL,
		.maxlen		= sizeof(unsigned long),
		.mode		= 0644,
		.proc_handler	= hugetlb_overcommit_handler,
	},
#endif
	{
		.procname	= "lowmem_reserve_ratio",
		.data		= &sysctl_lowmem_reserve_ratio,
		.maxlen		= sizeof(sysctl_lowmem_reserve_ratio),
		.mode		= 0644,
		.proc_handler	= lowmem_reserve_ratio_sysctl_handler,
	},
	{
		.procname	= "drop_caches",
		.data		= &sysctl_drop_caches,
		.maxlen		= sizeof(int),
		.mode		= 0200,
		.proc_handler	= drop_caches_sysctl_handler,
		.extra1		= SYSCTL_ONE,
		.extra2		= SYSCTL_FOUR,
	},
#ifdef CONFIG_COMPACTION
	{
		.procname	= "compact_memory",
		.data		= NULL,
		.maxlen		= sizeof(int),
		.mode		= 0200,
		.proc_handler	= sysctl_compaction_handler,
	},
	{
		.procname	= "compaction_proactiveness",
		.data		= &sysctl_compaction_proactiveness,
		.maxlen		= sizeof(sysctl_compaction_proactiveness),
		.mode		= 0644,
		.proc_handler	= compaction_proactiveness_sysctl_handler,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE_HUNDRED,
	},
	{
		.procname	= "extfrag_threshold",
		.data		= &sysctl_extfrag_threshold,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= (void *)&max_extfrag_threshold,
	},
	{
		.procname	= "compact_unevictable_allowed",
		.data		= &sysctl_compact_unevictable_allowed,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax_warn_RT_change,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},

#endif /* CONFIG_COMPACTION */
	{
		.procname	= "min_free_kbytes",
		.data		= &min_free_kbytes,
		.maxlen		= sizeof(min_free_kbytes),
		.mode		= 0644,
		.proc_handler	= min_free_kbytes_sysctl_handler,
		.extra1		= SYSCTL_ZERO,
	},
	{
		.procname	= "watermark_boost_factor",
		.data		= &watermark_boost_factor,
		.maxlen		= sizeof(watermark_boost_factor),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
	},
	{
		.procname	= "watermark_scale_factor",
		.data		= &watermark_scale_factor,
		.maxlen		= sizeof(watermark_scale_factor),
		.mode		= 0644,
		.proc_handler	= watermark_scale_factor_sysctl_handler,
		.extra1		= SYSCTL_ONE,
		.extra2		= SYSCTL_THREE_THOUSAND,
	},
	{
		.procname	= "percpu_pagelist_high_fraction",
		.data		= &percpu_pagelist_high_fraction,
		.maxlen		= sizeof(percpu_pagelist_high_fraction),
		.mode		= 0644,
		.proc_handler	= percpu_pagelist_high_fraction_sysctl_handler,
		.extra1		= SYSCTL_ZERO,
	},
	{
		.procname	= "page_lock_unfairness",
		.data		= &sysctl_page_lock_unfairness,
		.maxlen		= sizeof(sysctl_page_lock_unfairness),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
	},
#ifdef CONFIG_MMU
	{
		.procname	= "max_map_count",
		.data		= &sysctl_max_map_count,
		.maxlen		= sizeof(sysctl_max_map_count),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
	},
#else
	{
		.procname	= "nr_trim_pages",
		.data		= &sysctl_nr_trim_pages,
		.maxlen		= sizeof(sysctl_nr_trim_pages),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
	},
#endif
	{
		.procname	= "vfs_cache_pressure",
		.data		= &sysctl_vfs_cache_pressure,
		.maxlen		= sizeof(sysctl_vfs_cache_pressure),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
	},
#if defined(HAVE_ARCH_PICK_MMAP_LAYOUT) || \
    defined(CONFIG_ARCH_WANT_DEFAULT_TOPDOWN_MMAP_LAYOUT)
	{
		.procname	= "legacy_va_layout",
		.data		= &sysctl_legacy_va_layout,
		.maxlen		= sizeof(sysctl_legacy_va_layout),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
	},
#endif
#ifdef CONFIG_NUMA
	{
		.procname	= "zone_reclaim_mode",
		.data		= &node_reclaim_mode,
		.maxlen		= sizeof(node_reclaim_mode),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
	},
	{
		.procname	= "min_unmapped_ratio",
		.data		= &sysctl_min_unmapped_ratio,
		.maxlen		= sizeof(sysctl_min_unmapped_ratio),
		.mode		= 0644,
		.proc_handler	= sysctl_min_unmapped_ratio_sysctl_handler,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE_HUNDRED,
	},
	{
		.procname	= "min_slab_ratio",
		.data		= &sysctl_min_slab_ratio,
		.maxlen		= sizeof(sysctl_min_slab_ratio),
		.mode		= 0644,
		.proc_handler	= sysctl_min_slab_ratio_sysctl_handler,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE_HUNDRED,
	},
#endif
#ifdef CONFIG_SMP
	{
		.procname	= "stat_interval",
		.data		= &sysctl_stat_interval,
		.maxlen		= sizeof(sysctl_stat_interval),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_jiffies,
	},
	{
		.procname	= "stat_refresh",
		.data		= NULL,
		.maxlen		= 0,
		.mode		= 0600,
		.proc_handler	= vmstat_refresh,
	},
#endif
#ifdef CONFIG_MMU
	{
		.procname	= "mmap_min_addr",
		.data		= &dac_mmap_min_addr,
		.maxlen		= sizeof(unsigned long),
		.mode		= 0644,
		.proc_handler	= mmap_min_addr_handler,
	},
#endif
#ifdef CONFIG_NUMA
	{
		.procname	= "numa_zonelist_order",
		.data		= &numa_zonelist_order,
		.maxlen		= NUMA_ZONELIST_ORDER_LEN,
		.mode		= 0644,
		.proc_handler	= numa_zonelist_order_handler,
	},
#endif
#if (defined(CONFIG_X86_32) && !defined(CONFIG_UML))|| \
   (defined(CONFIG_SUPERH) && defined(CONFIG_VSYSCALL))
	{
		.procname	= "vdso_enabled",
#ifdef CONFIG_X86_32
		.data		= &vdso32_enabled,
		.maxlen		= sizeof(vdso32_enabled),
#else
		.data		= &vdso_enabled,
		.maxlen		= sizeof(vdso_enabled),
#endif
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
		.extra1		= SYSCTL_ZERO,
	},
#endif
#ifdef CONFIG_MEMORY_FAILURE
	{
		.procname	= "memory_failure_early_kill",
		.data		= &sysctl_memory_failure_early_kill,
		.maxlen		= sizeof(sysctl_memory_failure_early_kill),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
	{
		.procname	= "memory_failure_recovery",
		.data		= &sysctl_memory_failure_recovery,
		.maxlen		= sizeof(sysctl_memory_failure_recovery),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
#endif
	{
		.procname	= "user_reserve_kbytes",
		.data		= &sysctl_user_reserve_kbytes,
		.maxlen		= sizeof(sysctl_user_reserve_kbytes),
		.mode		= 0644,
		.proc_handler	= proc_doulongvec_minmax,
	},
	{
		.procname	= "admin_reserve_kbytes",
		.data		= &sysctl_admin_reserve_kbytes,
		.maxlen		= sizeof(sysctl_admin_reserve_kbytes),
		.mode		= 0644,
		.proc_handler	= proc_doulongvec_minmax,
	},
#ifdef CONFIG_HAVE_ARCH_MMAP_RND_BITS
	{
		.procname	= "mmap_rnd_bits",
		.data		= &mmap_rnd_bits,
		.maxlen		= sizeof(mmap_rnd_bits),
		.mode		= 0600,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= (void *)&mmap_rnd_bits_min,
		.extra2		= (void *)&mmap_rnd_bits_max,
	},
#endif
#ifdef CONFIG_HAVE_ARCH_MMAP_RND_COMPAT_BITS
	{
		.procname	= "mmap_rnd_compat_bits",
		.data		= &mmap_rnd_compat_bits,
		.maxlen		= sizeof(mmap_rnd_compat_bits),
		.mode		= 0600,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= (void *)&mmap_rnd_compat_bits_min,
		.extra2		= (void *)&mmap_rnd_compat_bits_max,
	},
#endif
#ifdef CONFIG_USERFAULTFD
	{
		.procname	= "unprivileged_userfaultfd",
		.data		= &sysctl_unprivileged_userfaultfd,
		.maxlen		= sizeof(sysctl_unprivileged_userfaultfd),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
#endif
	{ }
};

static struct ctl_table debug_table[] = {
#ifdef CONFIG_SYSCTL_EXCEPTION_TRACE
	{
		.procname	= "exception-trace",
		.data		= &show_unhandled_signals,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec
	},
#endif
	{ }
};

static struct ctl_table dev_table[] = {
	{ }
};

DECLARE_SYSCTL_BASE(kernel, kern_table);
DECLARE_SYSCTL_BASE(vm, vm_table);
DECLARE_SYSCTL_BASE(debug, debug_table);
DECLARE_SYSCTL_BASE(dev, dev_table);

int __init sysctl_init_bases(void)
{
	register_sysctl_base(kernel);
	register_sysctl_base(vm);
	register_sysctl_base(debug);
	register_sysctl_base(dev);

	return 0;
}
#endif /* CONFIG_SYSCTL */
EXPORT_SYMBOL(proc_dobool);
EXPORT_SYMBOL(proc_dointvec);
EXPORT_SYMBOL(proc_douintvec);
EXPORT_SYMBOL(proc_dointvec_jiffies);
EXPORT_SYMBOL(proc_dointvec_minmax);
EXPORT_SYMBOL_GPL(proc_douintvec_minmax);
EXPORT_SYMBOL(proc_dointvec_userhz_jiffies);
EXPORT_SYMBOL(proc_dointvec_ms_jiffies);
EXPORT_SYMBOL(proc_dostring);
EXPORT_SYMBOL(proc_doulongvec_minmax);
EXPORT_SYMBOL(proc_doulongvec_ms_jiffies_minmax);
EXPORT_SYMBOL(proc_do_large_bitmap);
