
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/delay.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/mutex.h>
#include <linux/pci.h>

#include <asm/intel-mid.h>

#define PM_STS			0x00
#define PM_CMD			0x04
#define PM_ICS			0x08
#define PM_WKC(x)		(0x10 + (x) * 4)
#define PM_WKS(x)		(0x18 + (x) * 4)
#define PM_SSC(x)		(0x20 + (x) * 4)
#define PM_SSS(x)		(0x30 + (x) * 4)

#define PM_STS_BUSY		(1 << 8)

#define PM_CMD_CMD(x)		((x) << 0)
#define PM_CMD_IOC		(1 << 8)
#define PM_CMD_CM_NOP		(0 << 9)
#define PM_CMD_CM_IMMEDIATE	(1 << 9)
#define PM_CMD_CM_DELAY		(2 << 9)
#define PM_CMD_CM_TRIGGER	(3 << 9)

#define PM_CMD_SYS_STATE_S5	(5 << 16)

#define PM_CMD_CFG_TRIGGER_NC	(3 << 19)

#define TRIGGER_NC_MSG_2	(2 << 22)

#define CMD_SET_CFG		0x01

#define PM_ICS_INT_STATUS(x)	((x) & 0xff)
#define PM_ICS_IE		(1 << 8)
#define PM_ICS_IP		(1 << 9)
#define PM_ICS_SW_INT_STS	(1 << 10)

#define INT_INVALID		0
#define INT_CMD_COMPLETE	1
#define INT_CMD_ERR		2
#define INT_WAKE_EVENT		3
#define INT_LSS_POWER_ERR	4
#define INT_S0iX_MSG_ERR	5
#define INT_NO_C6		6
#define INT_TRIGGER_ERR		7
#define INT_INACTIVITY		8

#define LSS_MAX_SHARED_DEVS	4
#define LSS_MAX_DEVS		64

#define LSS_WS_BITS		1	/* wake state width */
#define LSS_PWS_BITS		2	/* power state width */

#define PCI_DEVICE_ID_PENWELL	0x0828
#define PCI_DEVICE_ID_TANGIER	0x11a1

struct mid_pwr_dev {
	struct pci_dev *pdev;
	pci_power_t state;
};

struct mid_pwr {
	struct device *dev;
	void __iomem *regs;
	int irq;
	bool available;

	struct mutex lock;
	struct mid_pwr_dev lss[LSS_MAX_DEVS][LSS_MAX_SHARED_DEVS];
};

static struct mid_pwr *midpwr;

static u32 mid_pwr_get_state(struct mid_pwr *pwr, int reg)
{
	return readl(pwr->regs + PM_SSS(reg));
}

static void mid_pwr_set_state(struct mid_pwr *pwr, int reg, u32 value)
{
	writel(value, pwr->regs + PM_SSC(reg));
}

static void mid_pwr_set_wake(struct mid_pwr *pwr, int reg, u32 value)
{
	writel(value, pwr->regs + PM_WKC(reg));
}

static void mid_pwr_interrupt_disable(struct mid_pwr *pwr)
{
	writel(~PM_ICS_IE, pwr->regs + PM_ICS);
}

static bool mid_pwr_is_busy(struct mid_pwr *pwr)
{
	return !!(readl(pwr->regs + PM_STS) & PM_STS_BUSY);
}

static int mid_pwr_wait(struct mid_pwr *pwr)
{
	unsigned int count = 500000;
	bool busy;

	do {
		busy = mid_pwr_is_busy(pwr);
		if (!busy)
			return 0;
		udelay(1);
	} while (--count);

	return -EBUSY;
}

static int mid_pwr_wait_for_cmd(struct mid_pwr *pwr, u8 cmd)
{
	writel(PM_CMD_CMD(cmd) | PM_CMD_CM_IMMEDIATE, pwr->regs + PM_CMD);
	return mid_pwr_wait(pwr);
}

static int __update_power_state(struct mid_pwr *pwr, int reg, int bit, int new)
{
	int curstate;
	u32 power;
	int ret;

	/* Check if the device is already in desired state */
	power = mid_pwr_get_state(pwr, reg);
	curstate = (power >> bit) & 3;
	if (curstate == new)
		return 0;

	/* Update the power state */
	mid_pwr_set_state(pwr, reg, (power & ~(3 << bit)) | (new << bit));

	/* Send command to SCU */
	ret = mid_pwr_wait_for_cmd(pwr, CMD_SET_CFG);
	if (ret)
		return ret;

	/* Check if the device is already in desired state */
	power = mid_pwr_get_state(pwr, reg);
	curstate = (power >> bit) & 3;
	if (curstate != new)
		return -EAGAIN;

	return 0;
}

static pci_power_t __find_weakest_power_state(struct mid_pwr_dev *lss,
					      struct pci_dev *pdev,
					      pci_power_t state)
{
	pci_power_t weakest = PCI_D3hot;
	unsigned int j;

	/* Find device in cache or first free cell */
	for (j = 0; j < LSS_MAX_SHARED_DEVS; j++) {
		if (lss[j].pdev == pdev || !lss[j].pdev)
			break;
	}

	/* Store the desired state in cache */
	if (j < LSS_MAX_SHARED_DEVS) {
		lss[j].pdev = pdev;
		lss[j].state = state;
	} else {
		dev_WARN(&pdev->dev, "No room for device in PWRMU LSS cache\n");
		weakest = state;
	}

	/* Find the power state we may use */
	for (j = 0; j < LSS_MAX_SHARED_DEVS; j++) {
		if (lss[j].state < weakest)
			weakest = lss[j].state;
	}

	return weakest;
}

static int __set_power_state(struct mid_pwr *pwr, struct pci_dev *pdev,
			     pci_power_t state, int id, int reg, int bit)
{
	const char *name;
	int ret;

	state = __find_weakest_power_state(pwr->lss[id], pdev, state);
	name = pci_power_name(state);

	ret = __update_power_state(pwr, reg, bit, (__force int)state);
	if (ret) {
		dev_warn(&pdev->dev, "Can't set power state %s: %d\n", name, ret);
		return ret;
	}

	dev_vdbg(&pdev->dev, "Set power state %s\n", name);
	return 0;
}

static int mid_pwr_set_power_state(struct mid_pwr *pwr, struct pci_dev *pdev,
				   pci_power_t state)
{
	int id, reg, bit;
	int ret;

	id = intel_mid_pwr_get_lss_id(pdev);
	if (id < 0)
		return id;

	reg = (id * LSS_PWS_BITS) / 32;
	bit = (id * LSS_PWS_BITS) % 32;

	/* We support states between PCI_D0 and PCI_D3hot */
	if (state < PCI_D0)
		state = PCI_D0;
	if (state > PCI_D3hot)
		state = PCI_D3hot;

	mutex_lock(&pwr->lock);
	ret = __set_power_state(pwr, pdev, state, id, reg, bit);
	mutex_unlock(&pwr->lock);
	return ret;
}

int intel_mid_pci_set_power_state(struct pci_dev *pdev, pci_power_t state)
{
	struct mid_pwr *pwr = midpwr;
	int ret = 0;

	might_sleep();

	if (pwr && pwr->available)
		ret = mid_pwr_set_power_state(pwr, pdev, state);
	dev_vdbg(&pdev->dev, "set_power_state() returns %d\n", ret);

	return 0;
}

pci_power_t intel_mid_pci_get_power_state(struct pci_dev *pdev)
{
	struct mid_pwr *pwr = midpwr;
	int id, reg, bit;
	u32 power;

	if (!pwr || !pwr->available)
		return PCI_UNKNOWN;

	id = intel_mid_pwr_get_lss_id(pdev);
	if (id < 0)
		return PCI_UNKNOWN;

	reg = (id * LSS_PWS_BITS) / 32;
	bit = (id * LSS_PWS_BITS) % 32;
	power = mid_pwr_get_state(pwr, reg);
	return (__force pci_power_t)((power >> bit) & 3);
}

void intel_mid_pwr_power_off(void)
{
	struct mid_pwr *pwr = midpwr;
	u32 cmd = PM_CMD_SYS_STATE_S5 |
		  PM_CMD_CMD(CMD_SET_CFG) |
		  PM_CMD_CM_TRIGGER |
		  PM_CMD_CFG_TRIGGER_NC |
		  TRIGGER_NC_MSG_2;

	/* Send command to SCU */
	writel(cmd, pwr->regs + PM_CMD);
	mid_pwr_wait(pwr);
}

int intel_mid_pwr_get_lss_id(struct pci_dev *pdev)
{
	int vndr;
	u8 id;

	/*
	vndr = pci_find_capability(pdev, PCI_CAP_ID_VNDR);
	if (!vndr)
		return -EINVAL;

	/* Read the Logical SubSystem ID byte */
	pci_read_config_byte(pdev, vndr + INTEL_MID_PWR_LSS_OFFSET, &id);
	if (!(id & INTEL_MID_PWR_LSS_TYPE))
		return -ENODEV;

	id &= ~INTEL_MID_PWR_LSS_TYPE;
	if (id >= LSS_MAX_DEVS)
		return -ERANGE;

	return id;
}

static irqreturn_t mid_pwr_irq_handler(int irq, void *dev_id)
{
	struct mid_pwr *pwr = dev_id;
	u32 ics;

	ics = readl(pwr->regs + PM_ICS);
	if (!(ics & PM_ICS_IP))
		return IRQ_NONE;

	writel(ics | PM_ICS_IP, pwr->regs + PM_ICS);

	dev_warn(pwr->dev, "Unexpected IRQ: %#x\n", PM_ICS_INT_STATUS(ics));
	return IRQ_HANDLED;
}

struct mid_pwr_device_info {
	int (*set_initial_state)(struct mid_pwr *pwr);
};

static int mid_pwr_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct mid_pwr_device_info *info = (void *)id->driver_data;
	struct device *dev = &pdev->dev;
	struct mid_pwr *pwr;
	int ret;

	ret = pcim_enable_device(pdev);
	if (ret < 0) {
		dev_err(&pdev->dev, "error: could not enable device\n");
		return ret;
	}

	ret = pcim_iomap_regions(pdev, 1 << 0, pci_name(pdev));
	if (ret) {
		dev_err(&pdev->dev, "I/O memory remapping failed\n");
		return ret;
	}

	pwr = devm_kzalloc(dev, sizeof(*pwr), GFP_KERNEL);
	if (!pwr)
		return -ENOMEM;

	pwr->dev = dev;
	pwr->regs = pcim_iomap_table(pdev)[0];
	pwr->irq = pdev->irq;

	mutex_init(&pwr->lock);

	/* Disable interrupts */
	mid_pwr_interrupt_disable(pwr);

	if (info && info->set_initial_state) {
		ret = info->set_initial_state(pwr);
		if (ret)
			dev_warn(dev, "Can't set initial state: %d\n", ret);
	}

	ret = devm_request_irq(dev, pdev->irq, mid_pwr_irq_handler,
			       IRQF_NO_SUSPEND, pci_name(pdev), pwr);
	if (ret)
		return ret;

	pwr->available = true;
	midpwr = pwr;

	pci_set_drvdata(pdev, pwr);
	return 0;
}

static int mid_set_initial_state(struct mid_pwr *pwr, const u32 *states)
{
	unsigned int i, j;
	int ret;

	/*
	mid_pwr_set_wake(pwr, 0, 0xffffffff);
	mid_pwr_set_wake(pwr, 1, 0xffffffff);

	/*
	mid_pwr_set_state(pwr, 0, states[0]);
	mid_pwr_set_state(pwr, 1, states[1]);
	mid_pwr_set_state(pwr, 2, states[2]);
	mid_pwr_set_state(pwr, 3, states[3]);

	/* Send command to SCU */
	ret = mid_pwr_wait_for_cmd(pwr, CMD_SET_CFG);
	if (ret)
		return ret;

	for (i = 0; i < LSS_MAX_DEVS; i++) {
		for (j = 0; j < LSS_MAX_SHARED_DEVS; j++)
			pwr->lss[i][j].state = PCI_D3hot;
	}

	return 0;
}

static int pnw_set_initial_state(struct mid_pwr *pwr)
{
	/* On Penwell SRAM must stay powered on */
	static const u32 states[] = {
		0xf00fffff,		/* PM_SSC(0) */
		0xffffffff,		/* PM_SSC(1) */
		0xffffffff,		/* PM_SSC(2) */
		0xffffffff,		/* PM_SSC(3) */
	};
	return mid_set_initial_state(pwr, states);
}

static int tng_set_initial_state(struct mid_pwr *pwr)
{
	static const u32 states[] = {
		0xffffffff,		/* PM_SSC(0) */
		0xffffffff,		/* PM_SSC(1) */
		0xffffffff,		/* PM_SSC(2) */
		0xffffffff,		/* PM_SSC(3) */
	};
	return mid_set_initial_state(pwr, states);
}

static const struct mid_pwr_device_info pnw_info = {
	.set_initial_state = pnw_set_initial_state,
};

static const struct mid_pwr_device_info tng_info = {
	.set_initial_state = tng_set_initial_state,
};

static const struct pci_device_id mid_pwr_pci_ids[] = {
	{ PCI_VDEVICE(INTEL, PCI_DEVICE_ID_PENWELL), (kernel_ulong_t)&pnw_info },
	{ PCI_VDEVICE(INTEL, PCI_DEVICE_ID_TANGIER), (kernel_ulong_t)&tng_info },
	{}
};

static struct pci_driver mid_pwr_pci_driver = {
	.name		= "intel_mid_pwr",
	.probe		= mid_pwr_probe,
	.id_table	= mid_pwr_pci_ids,
};

builtin_pci_driver(mid_pwr_pci_driver);
