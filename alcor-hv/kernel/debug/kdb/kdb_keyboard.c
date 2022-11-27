
#include <linux/kdb.h>
#include <linux/keyboard.h>
#include <linux/ctype.h>
#include <linux/io.h>


#define KBD_STATUS_REG		0x64	/* Status register (R) */
#define KBD_DATA_REG		0x60	/* Keyboard data register (R/W) */


#define KBD_STAT_OBF 		0x01	/* Keyboard output buffer full */
#define KBD_STAT_MOUSE_OBF	0x20	/* Mouse output buffer full */

static int kbd_exists;
static int kbd_last_ret;

int kdb_get_kbd_char(void)
{
	int scancode, scanstatus;
	static int shift_lock;	/* CAPS LOCK state (0-off, 1-on) */
	static int shift_key;	/* Shift next keypress */
	static int ctrl_key;
	u_short keychar;

	if (KDB_FLAG(NO_I8042) || KDB_FLAG(NO_VT_CONSOLE) ||
	    (inb(KBD_STATUS_REG) == 0xff && inb(KBD_DATA_REG) == 0xff)) {
		kbd_exists = 0;
		return -1;
	}
	kbd_exists = 1;

	if ((inb(KBD_STATUS_REG) & KBD_STAT_OBF) == 0)
		return -1;

	/*
	scancode = inb(KBD_DATA_REG);
	scanstatus = inb(KBD_STATUS_REG);

	/*
	if (scanstatus & KBD_STAT_MOUSE_OBF)
		return -1;

	/*

	if (((scancode&0x7f) == 0x2a) || ((scancode&0x7f) == 0x36)) {
		/*
		if ((scancode & 0x80) == 0)
			shift_key = 1;
		else
			shift_key = 0;
		return -1;
	}

	if ((scancode&0x7f) == 0x1d) {
		/*
		if ((scancode & 0x80) == 0)
			ctrl_key = 1;
		else
			ctrl_key = 0;
		return -1;
	}

	if ((scancode & 0x80) != 0) {
		if (scancode == 0x9c)
			kbd_last_ret = 0;
		return -1;
	}

	scancode &= 0x7f;

	/*

	if (scancode == 0x3a) {
		/*
		shift_lock ^= 1;

#ifdef	KDB_BLINK_LED
		kdb_toggleled(0x4);
#endif
		return -1;
	}

	if (scancode == 0x0e) {
		/*
		return 8;
	}

	/* Special Key */
	switch (scancode) {
	case 0xF: /* Tab */
		return 9;
	case 0x53: /* Del */
		return 4;
	case 0x47: /* Home */
		return 1;
	case 0x4F: /* End */
		return 5;
	case 0x4B: /* Left */
		return 2;
	case 0x48: /* Up */
		return 16;
	case 0x50: /* Down */
		return 14;
	case 0x4D: /* Right */
		return 6;
	}

	if (scancode == 0xe0)
		return -1;

	/*
	if (scancode == 0x73)
		scancode = 0x59;
	else if (scancode == 0x7d)
		scancode = 0x7c;

	if (!shift_lock && !shift_key && !ctrl_key) {
		keychar = plain_map[scancode];
	} else if ((shift_lock || shift_key) && key_maps[1]) {
		keychar = key_maps[1][scancode];
	} else if (ctrl_key && key_maps[4]) {
		keychar = key_maps[4][scancode];
	} else {
		keychar = 0x0020;
		kdb_printf("Unknown state/scancode (%d)\n", scancode);
	}
	keychar &= 0x0fff;
	if (keychar == '\t')
		keychar = ' ';
	switch (KTYP(keychar)) {
	case KT_LETTER:
	case KT_LATIN:
		if (isprint(keychar))
			break;		/* printable characters */
		fallthrough;
	case KT_SPEC:
		if (keychar == K_ENTER)
			break;
		fallthrough;
	default:
		return -1;	/* ignore unprintables */
	}

	if (scancode == 0x1c) {
		kbd_last_ret = 1;
		return 13;
	}

	return keychar & 0xff;
}
EXPORT_SYMBOL_GPL(kdb_get_kbd_char);

void kdb_kbd_cleanup_state(void)
{
	int scancode, scanstatus;

	/*
	if (!kbd_last_ret)
		return;

	kbd_last_ret = 0;
	/*

	while (1) {
		while ((inb(KBD_STATUS_REG) & KBD_STAT_OBF) == 0)
			cpu_relax();

		/*
		scancode = inb(KBD_DATA_REG);
		scanstatus = inb(KBD_STATUS_REG);

		/*
		if (scanstatus & KBD_STAT_MOUSE_OBF)
			continue;

		/*
		if (scancode != 0x9c)
			continue;

		return;
	}
}
