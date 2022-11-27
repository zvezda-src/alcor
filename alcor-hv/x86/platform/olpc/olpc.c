
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/export.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/string.h>
#include <linux/platform_device.h>
#include <linux/of.h>
#include <linux/syscore_ops.h>
#include <linux/mutex.h>
#include <linux/olpc-ec.h>

#include <asm/geode.h>
#include <asm/setup.h>
#include <asm/olpc.h>
#include <asm/olpc_ofw.h>

struct olpc_platform_t olpc_platform_info;
EXPORT_SYMBOL_GPL(olpc_platform_info);

#define EC_BASE_TIMEOUT 20

static int ec_timeout = EC_BASE_TIMEOUT;

static int __init olpc_ec_timeout_set(char *str)
{
	if (get_option(&str, &ec_timeout) != 1) {
		ec_timeout = EC_BASE_TIMEOUT;
		printk(KERN_ERR "olpc-ec:  invalid argument to "
				"'olpc_ec_timeout=', ignoring!\n");
	}
	printk(KERN_DEBUG "olpc-ec:  using %d ms delay for EC commands.\n",
			ec_timeout);
	return 1;
}
__setup("olpc_ec_timeout=", olpc_ec_timeout_set);


static inline unsigned int ibf_status(unsigned int port)
{
	return !!(inb(port) & 0x02);
}

static inline unsigned int obf_status(unsigned int port)
{
	return inb(port) & 0x01;
}

#define wait_on_ibf(p, d) __wait_on_ibf(__LINE__, (p), (d))
static int __wait_on_ibf(unsigned int line, unsigned int port, int desired)
{
	unsigned int timeo;
	int state = ibf_status(port);

	for (timeo = ec_timeout; state != desired && timeo; timeo--) {
		mdelay(1);
		state = ibf_status(port);
	}

	if ((state == desired) && (ec_timeout > EC_BASE_TIMEOUT) &&
			timeo < (ec_timeout - EC_BASE_TIMEOUT)) {
		printk(KERN_WARNING "olpc-ec:  %d: waited %u ms for IBF!\n",
				line, ec_timeout - timeo);
	}

	return !(state == desired);
}

#define wait_on_obf(p, d) __wait_on_obf(__LINE__, (p), (d))
static int __wait_on_obf(unsigned int line, unsigned int port, int desired)
{
	unsigned int timeo;
	int state = obf_status(port);

	for (timeo = ec_timeout; state != desired && timeo; timeo--) {
		mdelay(1);
		state = obf_status(port);
	}

	if ((state == desired) && (ec_timeout > EC_BASE_TIMEOUT) &&
			timeo < (ec_timeout - EC_BASE_TIMEOUT)) {
		printk(KERN_WARNING "olpc-ec:  %d: waited %u ms for OBF!\n",
				line, ec_timeout - timeo);
	}

	return !(state == desired);
}

static int olpc_xo1_ec_cmd(u8 cmd, u8 *inbuf, size_t inlen, u8 *outbuf,
		size_t outlen, void *arg)
{
	int ret = -EIO;
	int i;
	int restarts = 0;

	/* Clear OBF */
	for (i = 0; i < 10 && (obf_status(0x6c) == 1); i++)
		inb(0x68);
	if (i == 10) {
		printk(KERN_ERR "olpc-ec:  timeout while attempting to "
				"clear OBF flag!\n");
		goto err;
	}

	if (wait_on_ibf(0x6c, 0)) {
		printk(KERN_ERR "olpc-ec:  timeout waiting for EC to "
				"quiesce!\n");
		goto err;
	}

restart:
	/*
	pr_devel("olpc-ec:  running cmd 0x%x\n", cmd);
	outb(cmd, 0x6c);

	if (wait_on_ibf(0x6c, 0)) {
		printk(KERN_ERR "olpc-ec:  timeout waiting for EC to read "
				"command!\n");
		goto err;
	}

	if (inbuf && inlen) {
		/* write data to EC */
		for (i = 0; i < inlen; i++) {
			pr_devel("olpc-ec:  sending cmd arg 0x%x\n", inbuf[i]);
			outb(inbuf[i], 0x68);
			if (wait_on_ibf(0x6c, 0)) {
				printk(KERN_ERR "olpc-ec:  timeout waiting for"
						" EC accept data!\n");
				goto err;
			}
		}
	}
	if (outbuf && outlen) {
		/* read data from EC */
		for (i = 0; i < outlen; i++) {
			if (wait_on_obf(0x6c, 1)) {
				printk(KERN_ERR "olpc-ec:  timeout waiting for"
						" EC to provide data!\n");
				if (restarts++ < 10)
					goto restart;
				goto err;
			}
			outbuf[i] = inb(0x68);
			pr_devel("olpc-ec:  received 0x%x\n", outbuf[i]);
		}
	}

	ret = 0;
err:
	return ret;
}

static bool __init check_ofw_architecture(struct device_node *root)
{
	const char *olpc_arch;
	int propsize;

	olpc_arch = of_get_property(root, "architecture", &propsize);
	return propsize == 5 && strncmp("OLPC", olpc_arch, 5) == 0;
}

static u32 __init get_board_revision(struct device_node *root)
{
	int propsize;
	const __be32 *rev;

	rev = of_get_property(root, "board-revision-int", &propsize);
	if (propsize != 4)
		return 0;

	return be32_to_cpu(*rev);
}

static bool __init platform_detect(void)
{
	struct device_node *root = of_find_node_by_path("/");
	bool success;

	if (!root)
		return false;

	success = check_ofw_architecture(root);
	if (success) {
		olpc_platform_info.boardrev = get_board_revision(root);
		olpc_platform_info.flags |= OLPC_F_PRESENT;

		pr_info("OLPC board revision %s%X\n",
			((olpc_platform_info.boardrev & 0xf) < 8) ? "pre" : "",
			olpc_platform_info.boardrev >> 4);
	}

	of_node_put(root);
	return success;
}

static int __init add_xo1_platform_devices(void)
{
	struct platform_device *pdev;

	pdev = platform_device_register_simple("xo1-rfkill", -1, NULL, 0);
	if (IS_ERR(pdev))
		return PTR_ERR(pdev);

	pdev = platform_device_register_simple("olpc-xo1", -1, NULL, 0);

	return PTR_ERR_OR_ZERO(pdev);
}

static int olpc_xo1_ec_suspend(struct platform_device *pdev)
{
	/*
	return olpc_ec_cmd(EC_SET_SCI_INHIBIT, NULL, 0, NULL, 0);
}

static int olpc_xo1_ec_resume(struct platform_device *pdev)
{
	/* Tell the EC to stop inhibiting SCIs */
	olpc_ec_cmd(EC_SET_SCI_INHIBIT_RELEASE, NULL, 0, NULL, 0);

	/*
	olpc_ec_cmd(EC_WAKE_UP_WLAN, NULL, 0, NULL, 0);
	olpc_ec_cmd(EC_WAKE_UP_WLAN, NULL, 0, NULL, 0);

	return 0;
}

static struct olpc_ec_driver ec_xo1_driver = {
	.suspend = olpc_xo1_ec_suspend,
	.resume = olpc_xo1_ec_resume,
	.ec_cmd = olpc_xo1_ec_cmd,
#ifdef CONFIG_OLPC_XO1_SCI
	/*
	.wakeup_available = true,
#endif
};

static struct olpc_ec_driver ec_xo1_5_driver = {
	.ec_cmd = olpc_xo1_ec_cmd,
#ifdef CONFIG_OLPC_XO15_SCI
	/*
	.wakeup_available = true,
#endif
};

static int __init olpc_init(void)
{
	int r = 0;

	if (!olpc_ofw_present() || !platform_detect())
		return 0;

	/* register the XO-1 and 1.5-specific EC handler */
	if (olpc_platform_info.boardrev < olpc_board_pre(0xd0))	/* XO-1 */
		olpc_ec_driver_register(&ec_xo1_driver, NULL);
	else
		olpc_ec_driver_register(&ec_xo1_5_driver, NULL);
	platform_device_register_simple("olpc-ec", -1, NULL, 0);

	/* assume B1 and above models always have a DCON */
	if (olpc_board_at_least(olpc_board(0xb1)))
		olpc_platform_info.flags |= OLPC_F_DCON;

#ifdef CONFIG_PCI_OLPC
	/* If the VSA exists let it emulate PCI, if not emulate in kernel.
	 * XO-1 only. */
	if (olpc_platform_info.boardrev < olpc_board_pre(0xd0) &&
			!cs5535_has_vsa2())
		x86_init.pci.arch_init = pci_olpc_init;
#endif

	if (olpc_platform_info.boardrev < olpc_board_pre(0xd0)) { /* XO-1 */
		r = add_xo1_platform_devices();
		if (r)
			return r;
	}

	return 0;
}

postcore_initcall(olpc_init);
