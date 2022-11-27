
#include <linux/types.h>
#include <linux/ctype.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kdev_t.h>
#include <linux/console.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/smp.h>
#include <linux/nmi.h>
#include <linux/delay.h>
#include <linux/kgdb.h>
#include <linux/kdb.h>
#include <linux/kallsyms.h>
#include "kdb_private.h"

#define CMD_BUFLEN 256
char kdb_prompt_str[CMD_BUFLEN];

int kdb_trap_printk;
int kdb_printf_cpu = -1;

static int kgdb_transition_check(char *buffer)
{
	if (buffer[0] != '+' && buffer[0] != '$') {
		KDB_STATE_SET(KGDB_TRANS);
		kdb_printf("%s", buffer);
	} else {
		int slen = strlen(buffer);
		if (slen > 3 && buffer[slen - 3] == '#') {
			kdb_gdb_state_pass(buffer);
			strcpy(buffer, "kgdb");
			KDB_STATE_SET(DOING_KGDB);
			return 1;
		}
	}
	return 0;
}

static int kdb_handle_escape(char *buf, size_t sz)
{
	char *lastkey = buf + sz - 1;

	switch (sz) {
	case 1:
		if (*lastkey == '\e')
			return 0;
		break;

	case 2: /* \e<something> */
		if (*lastkey == '[')
			return 0;
		break;

	case 3:
		switch (*lastkey) {
		case 'A': /* \e[A, up arrow */
			return 16;
		case 'B': /* \e[B, down arrow */
			return 14;
		case 'C': /* \e[C, right arrow */
			return 6;
		case 'D': /* \e[D, left arrow */
			return 2;
		case '1': /* \e[<1,3,4>], may be home, del, end */
		case '3':
		case '4':
			return 0;
		}
		break;

	case 4:
		if (*lastkey == '~') {
			switch (buf[2]) {
			case '1': /* \e[1~, home */
				return 1;
			case '3': /* \e[3~, del */
				return 4;
			case '4': /* \e[4~, end */
				return 5;
			}
		}
		break;
	}

	return -1;
}

char kdb_getchar(void)
{
#define ESCAPE_UDELAY 1000
#define ESCAPE_DELAY (2*1000000/ESCAPE_UDELAY) /* 2 seconds worth of udelays */
	char buf[4];	/* longest vt100 escape sequence is 4 bytes */
	char *pbuf = buf;
	int escape_delay = 0;
	get_char_func *f, *f_prev = NULL;
	int key;

	for (f = &kdb_poll_funcs[0]; ; ++f) {
		if (*f == NULL) {
			/* Reset NMI watchdog once per poll loop */
			touch_nmi_watchdog();
			f = &kdb_poll_funcs[0];
		}

		key = (*f)();
		if (key == -1) {
			if (escape_delay) {
				udelay(ESCAPE_UDELAY);
				if (--escape_delay == 0)
					return '\e';
			}
			continue;
		}

		/*
		if (f_prev != f) {
			f_prev = f;
			pbuf = buf;
			escape_delay = ESCAPE_DELAY;
		}

		*pbuf++ = key;
		key = kdb_handle_escape(buf, pbuf - buf);
		if (key < 0) /* no escape sequence; return best character */
			return buf[pbuf - buf == 2 ? 1 : 0];
		if (key > 0)
			return key;
	}

	unreachable();
}


static char *kdb_read(char *buffer, size_t bufsize)
{
	char *cp = buffer;
	char *bufend = buffer+bufsize-2;	/* Reserve space for newline
						 * and null byte */
	char *lastchar;
	char *p_tmp;
	char tmp;
	static char tmpbuffer[CMD_BUFLEN];
	int len = strlen(buffer);
	int len_tmp;
	int tab = 0;
	int count;
	int i;
	int diag, dtab_count;
	int key, buf_size, ret;


	diag = kdbgetintenv("DTABCOUNT", &dtab_count);
	if (diag)
		dtab_count = 30;

	if (len > 0) {
		cp += len;
		if (*(buffer+len-1) == '\n')
			cp--;
	}

	lastchar = cp;
	kdb_printf("%s", buffer);
poll_again:
	key = kdb_getchar();
	if (key != 9)
		tab = 0;
	switch (key) {
	case 8: /* backspace */
		if (cp > buffer) {
			if (cp < lastchar) {
				memcpy(tmpbuffer, cp, lastchar - cp);
				memcpy(cp-1, tmpbuffer, lastchar - cp);
			}
			*(--lastchar) = '\0';
			--cp;
			kdb_printf("\b%s \r", cp);
			tmp = *cp;
			*cp = '\0';
			kdb_printf(kdb_prompt_str);
			kdb_printf("%s", buffer);
			*cp = tmp;
		}
		break;
	case 13: /* enter */
		*lastchar++ = '\n';
		*lastchar++ = '\0';
		if (!KDB_STATE(KGDB_TRANS)) {
			KDB_STATE_SET(KGDB_TRANS);
			kdb_printf("%s", buffer);
		}
		kdb_printf("\n");
		return buffer;
	case 4: /* Del */
		if (cp < lastchar) {
			memcpy(tmpbuffer, cp+1, lastchar - cp - 1);
			memcpy(cp, tmpbuffer, lastchar - cp - 1);
			*(--lastchar) = '\0';
			kdb_printf("%s \r", cp);
			tmp = *cp;
			*cp = '\0';
			kdb_printf(kdb_prompt_str);
			kdb_printf("%s", buffer);
			*cp = tmp;
		}
		break;
	case 1: /* Home */
		if (cp > buffer) {
			kdb_printf("\r");
			kdb_printf(kdb_prompt_str);
			cp = buffer;
		}
		break;
	case 5: /* End */
		if (cp < lastchar) {
			kdb_printf("%s", cp);
			cp = lastchar;
		}
		break;
	case 2: /* Left */
		if (cp > buffer) {
			kdb_printf("\b");
			--cp;
		}
		break;
	case 14: /* Down */
		memset(tmpbuffer, ' ',
		       strlen(kdb_prompt_str) + (lastchar-buffer));
		*(tmpbuffer+strlen(kdb_prompt_str) +
		  (lastchar-buffer)) = '\0';
		kdb_printf("\r%s\r", tmpbuffer);
		*lastchar = (char)key;
		*(lastchar+1) = '\0';
		return lastchar;
	case 6: /* Right */
		if (cp < lastchar) {
			kdb_printf("%c", *cp);
			++cp;
		}
		break;
	case 16: /* Up */
		memset(tmpbuffer, ' ',
		       strlen(kdb_prompt_str) + (lastchar-buffer));
		*(tmpbuffer+strlen(kdb_prompt_str) +
		  (lastchar-buffer)) = '\0';
		kdb_printf("\r%s\r", tmpbuffer);
		*lastchar = (char)key;
		*(lastchar+1) = '\0';
		return lastchar;
	case 9: /* Tab */
		if (tab < 2)
			++tab;
		p_tmp = buffer;
		while (*p_tmp == ' ')
			p_tmp++;
		if (p_tmp > cp)
			break;
		memcpy(tmpbuffer, p_tmp, cp-p_tmp);
		*(tmpbuffer + (cp-p_tmp)) = '\0';
		p_tmp = strrchr(tmpbuffer, ' ');
		if (p_tmp)
			++p_tmp;
		else
			p_tmp = tmpbuffer;
		len = strlen(p_tmp);
		buf_size = sizeof(tmpbuffer) - (p_tmp - tmpbuffer);
		count = kallsyms_symbol_complete(p_tmp, buf_size);
		if (tab == 2 && count > 0) {
			kdb_printf("\n%d symbols are found.", count);
			if (count > dtab_count) {
				count = dtab_count;
				kdb_printf(" But only first %d symbols will"
					   " be printed.\nYou can change the"
					   " environment variable DTABCOUNT.",
					   count);
			}
			kdb_printf("\n");
			for (i = 0; i < count; i++) {
				ret = kallsyms_symbol_next(p_tmp, i, buf_size);
				if (WARN_ON(!ret))
					break;
				if (ret != -E2BIG)
					kdb_printf("%s ", p_tmp);
				else
					kdb_printf("%s... ", p_tmp);
				*(p_tmp + len) = '\0';
			}
			if (i >= dtab_count)
				kdb_printf("...");
			kdb_printf("\n");
			kdb_printf(kdb_prompt_str);
			kdb_printf("%s", buffer);
		} else if (tab != 2 && count > 0) {
			len_tmp = strlen(p_tmp);
			strncpy(p_tmp+len_tmp, cp, lastchar-cp+1);
			len_tmp = strlen(p_tmp);
			strncpy(cp, p_tmp+len, len_tmp-len + 1);
			len = len_tmp - len;
			kdb_printf("%s", cp);
			cp += len;
			lastchar += len;
		}
		kdb_nextline = 1; /* reset output line number */
		break;
	default:
		if (key >= 32 && lastchar < bufend) {
			if (cp < lastchar) {
				memcpy(tmpbuffer, cp, lastchar - cp);
				memcpy(cp+1, tmpbuffer, lastchar - cp);
				*++lastchar = '\0';
				*cp = key;
				kdb_printf("%s\r", cp);
				++cp;
				tmp = *cp;
				*cp = '\0';
				kdb_printf(kdb_prompt_str);
				kdb_printf("%s", buffer);
				*cp = tmp;
			} else {
				*++lastchar = '\0';
				*cp++ = key;
				/* The kgdb transition check will hide
				 * printed characters if we think that
				 * kgdb is connecting, until the check
				 * fails */
				if (!KDB_STATE(KGDB_TRANS)) {
					if (kgdb_transition_check(buffer))
						return buffer;
				} else {
					kdb_printf("%c", key);
				}
			}
			/* Special escape to kgdb */
			if (lastchar - buffer >= 5 &&
			    strcmp(lastchar - 5, "$?#3f") == 0) {
				kdb_gdb_state_pass(lastchar - 5);
				strcpy(buffer, "kgdb");
				KDB_STATE_SET(DOING_KGDB);
				return buffer;
			}
			if (lastchar - buffer >= 11 &&
			    strcmp(lastchar - 11, "$qSupported") == 0) {
				kdb_gdb_state_pass(lastchar - 11);
				strcpy(buffer, "kgdb");
				KDB_STATE_SET(DOING_KGDB);
				return buffer;
			}
		}
		break;
	}
	goto poll_again;
}


char *kdb_getstr(char *buffer, size_t bufsize, const char *prompt)
{
	if (prompt && kdb_prompt_str != prompt)
		strscpy(kdb_prompt_str, prompt, CMD_BUFLEN);
	kdb_printf(kdb_prompt_str);
	kdb_nextline = 1;	/* Prompt and input resets line number */
	return kdb_read(buffer, bufsize);
}


static void kdb_input_flush(void)
{
	get_char_func *f;
	int res;
	int flush_delay = 1;
	while (flush_delay) {
		flush_delay--;
empty:
		touch_nmi_watchdog();
		for (f = &kdb_poll_funcs[0]; *f; ++f) {
			res = (*f)();
			if (res != -1) {
				flush_delay = 1;
				goto empty;
			}
		}
		if (flush_delay)
			mdelay(1);
	}
}


static char kdb_buffer[256];	/* A bit too big to go on stack */
static char *next_avail = kdb_buffer;
static int  size_avail;
static int  suspend_grep;

static int kdb_search_string(char *searched, char *searchfor)
{
	char firstchar, *cp;
	int len1, len2;

	/* not counting the newline at the end of "searched" */
	len1 = strlen(searched)-1;
	len2 = strlen(searchfor);
	if (len1 < len2)
		return 0;
	if (kdb_grep_leading && kdb_grep_trailing && len1 != len2)
		return 0;
	if (kdb_grep_leading) {
		if (!strncmp(searched, searchfor, len2))
			return 1;
	} else if (kdb_grep_trailing) {
		if (!strncmp(searched+len1-len2, searchfor, len2))
			return 1;
	} else {
		firstchar = *searchfor;
		cp = searched;
		while ((cp = strchr(cp, firstchar))) {
			if (!strncmp(cp, searchfor, len2))
				return 1;
			cp++;
		}
	}
	return 0;
}

static void kdb_msg_write(const char *msg, int msg_len)
{
	struct console *c;
	const char *cp;
	int len;

	if (msg_len == 0)
		return;

	cp = msg;
	len = msg_len;

	while (len--) {
		dbg_io_ops->write_char(*cp);
		cp++;
	}

	for_each_console(c) {
		if (!(c->flags & CON_ENABLED))
			continue;
		if (c == dbg_io_ops->cons)
			continue;
		/*
		++oops_in_progress;
		c->write(c, msg, msg_len);
		--oops_in_progress;
		touch_nmi_watchdog();
	}
}

int vkdb_printf(enum kdb_msgsrc src, const char *fmt, va_list ap)
{
	int diag;
	int linecount;
	int colcount;
	int logging, saved_loglevel = 0;
	int retlen = 0;
	int fnd, len;
	int this_cpu, old_cpu;
	char *cp, *cp2, *cphold = NULL, replaced_byte = ' ';
	char *moreprompt = "more> ";
	unsigned long flags;

	/* Serialize kdb_printf if multiple cpus try to write at once.
	 * But if any cpu goes recursive in kdb, just print the output,
	 * even if it is interleaved with any other text.
	 */
	local_irq_save(flags);
	this_cpu = smp_processor_id();
	for (;;) {
		old_cpu = cmpxchg(&kdb_printf_cpu, -1, this_cpu);
		if (old_cpu == -1 || old_cpu == this_cpu)
			break;

		cpu_relax();
	}

	diag = kdbgetintenv("LINES", &linecount);
	if (diag || linecount <= 1)
		linecount = 24;

	diag = kdbgetintenv("COLUMNS", &colcount);
	if (diag || colcount <= 1)
		colcount = 80;

	diag = kdbgetintenv("LOGGING", &logging);
	if (diag)
		logging = 0;

	if (!kdb_grepping_flag || suspend_grep) {
		/* normally, every vsnprintf starts a new buffer */
		next_avail = kdb_buffer;
		size_avail = sizeof(kdb_buffer);
	}
	vsnprintf(next_avail, size_avail, fmt, ap);

	/*

	/* skip the search if prints are temporarily unconditional */
	if (!suspend_grep && kdb_grepping_flag) {
		cp = strchr(kdb_buffer, '\n');
		if (!cp) {
			/*
			if (next_avail == kdb_buffer) {
				/*
				cp2 = kdb_buffer;
				len = strlen(kdb_prompt_str);
				if (!strncmp(cp2, kdb_prompt_str, len)) {
					/*
					kdb_grepping_flag = 0;
					goto kdb_printit;
				}
			}
			/* no newline; don't search/write the buffer
			   until one is there */
			len = strlen(kdb_buffer);
			next_avail = kdb_buffer + len;
			size_avail = sizeof(kdb_buffer) - len;
			goto kdb_print_out;
		}

		/*
		cp++;	 	     /* to byte after the newline */
		replaced_byte = *cp; /* remember what/where it was */
		cphold = cp;
		*cp = '\0';	     /* end the string for our search */

		/*
		fnd = kdb_search_string(kdb_buffer, kdb_grep_string);
		if (!fnd) {
			/*
			*cphold = replaced_byte;
			strcpy(kdb_buffer, cphold);
			len = strlen(kdb_buffer);
			next_avail = kdb_buffer + len;
			size_avail = sizeof(kdb_buffer) - len;
			goto kdb_print_out;
		}
		if (kdb_grepping_flag >= KDB_GREPPING_FLAG_SEARCH) {
			/*
			*cphold = replaced_byte;
			kdb_grepping_flag = 0;
		}
		/*
	}
kdb_printit:

	/*
	retlen = strlen(kdb_buffer);
	cp = (char *) printk_skip_headers(kdb_buffer);
	if (!dbg_kdb_mode && kgdb_connected)
		gdbstub_msg_write(cp, retlen - (cp - kdb_buffer));
	else
		kdb_msg_write(cp, retlen - (cp - kdb_buffer));

	if (logging) {
		saved_loglevel = console_loglevel;
		console_loglevel = CONSOLE_LOGLEVEL_SILENT;
		if (printk_get_level(kdb_buffer) || src == KDB_MSGSRC_PRINTK)
			printk("%s", kdb_buffer);
		else
			pr_info("%s", kdb_buffer);
	}

	if (KDB_STATE(PAGER)) {
		/*
		int got = 0;
		len = retlen;
		while (len--) {
			if (kdb_buffer[len] == '\n') {
				kdb_nextline++;
				got = 0;
			} else if (kdb_buffer[len] == '\r') {
				got = 0;
			} else {
				got++;
			}
		}
		kdb_nextline += got / (colcount + 1);
	}

	/* check for having reached the LINES number of printed lines */
	if (kdb_nextline >= linecount) {
		char ch;

		/* Watch out for recursion here.  Any routine that calls
		 * kdb_printf will come back through here.  And kdb_read
		 * uses kdb_printf to echo on serial consoles ...
		 */
		kdb_nextline = 1;	/* In case of recursion */

		/*
		moreprompt = kdbgetenv("MOREPROMPT");
		if (moreprompt == NULL)
			moreprompt = "more> ";

		kdb_input_flush();
		kdb_msg_write(moreprompt, strlen(moreprompt));

		if (logging)
			printk("%s", moreprompt);

		ch = kdb_getchar();
		kdb_nextline = 1;	/* Really set output line 1 */

		/* empty and reset the buffer: */
		kdb_buffer[0] = '\0';
		next_avail = kdb_buffer;
		size_avail = sizeof(kdb_buffer);
		if ((ch == 'q') || (ch == 'Q')) {
			/* user hit q or Q */
			KDB_FLAG_SET(CMD_INTERRUPT); /* command interrupted */
			KDB_STATE_CLEAR(PAGER);
			/* end of command output; back to normal mode */
			kdb_grepping_flag = 0;
			kdb_printf("\n");
		} else if (ch == ' ') {
			kdb_printf("\r");
			suspend_grep = 1; /* for this recursion */
		} else if (ch == '\n' || ch == '\r') {
			kdb_nextline = linecount - 1;
			kdb_printf("\r");
			suspend_grep = 1; /* for this recursion */
		} else if (ch == '/' && !kdb_grepping_flag) {
			kdb_printf("\r");
			kdb_getstr(kdb_grep_string, KDB_GREP_STRLEN,
				   kdbgetenv("SEARCHPROMPT") ?: "search> ");
			*strchrnul(kdb_grep_string, '\n') = '\0';
			kdb_grepping_flag += KDB_GREPPING_FLAG_SEARCH;
			suspend_grep = 1; /* for this recursion */
		} else if (ch) {
			/* user hit something unexpected */
			suspend_grep = 1; /* for this recursion */
			if (ch != '/')
				kdb_printf(
				    "\nOnly 'q', 'Q' or '/' are processed at "
				    "more prompt, input ignored\n");
			else
				kdb_printf("\n'/' cannot be used during | "
					   "grep filtering, input ignored\n");
		} else if (kdb_grepping_flag) {
			/* user hit enter */
			suspend_grep = 1; /* for this recursion */
			kdb_printf("\n");
		}
		kdb_input_flush();
	}

	/*
	if (kdb_grepping_flag && !suspend_grep) {
		*cphold = replaced_byte;
		strcpy(kdb_buffer, cphold);
		len = strlen(kdb_buffer);
		next_avail = kdb_buffer + len;
		size_avail = sizeof(kdb_buffer) - len;
	}

kdb_print_out:
	suspend_grep = 0; /* end of what may have been a recursive call */
	if (logging)
		console_loglevel = saved_loglevel;
	/* kdb_printf_cpu locked the code above. */
	smp_store_release(&kdb_printf_cpu, old_cpu);
	local_irq_restore(flags);
	return retlen;
}

int kdb_printf(const char *fmt, ...)
{
	va_list ap;
	int r;

	va_start(ap, fmt);
	r = vkdb_printf(KDB_MSGSRC_INTERNAL, fmt, ap);
	va_end(ap);

	return r;
}
EXPORT_SYMBOL_GPL(kdb_printf);
