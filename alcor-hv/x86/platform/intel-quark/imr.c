
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <asm-generic/sections.h>
#include <asm/cpu_device_id.h>
#include <asm/imr.h>
#include <asm/iosf_mbi.h>
#include <asm/io.h>

#include <linux/debugfs.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/types.h>

struct imr_device {
	bool		init;
	struct mutex	lock;
	int		max_imr;
	int		reg_base;
};

static struct imr_device imr_dev;

#define IMR_LOCK	BIT(31)

struct imr_regs {
	u32 addr_lo;
	u32 addr_hi;
	u32 rmask;
	u32 wmask;
};

#define IMR_NUM_REGS	(sizeof(struct imr_regs)/sizeof(u32))
#define IMR_SHIFT	8
#define imr_to_phys(x)	((x) << IMR_SHIFT)
#define phys_to_imr(x)	((x) >> IMR_SHIFT)

static inline int imr_is_enabled(struct imr_regs *imr)
{
	return !(imr->rmask == IMR_READ_ACCESS_ALL &&
		 imr->wmask == IMR_WRITE_ACCESS_ALL &&
		 imr_to_phys(imr->addr_lo) == 0 &&
		 imr_to_phys(imr->addr_hi) == 0);
}

static int imr_read(struct imr_device *idev, u32 imr_id, struct imr_regs *imr)
{
	u32 reg = imr_id * IMR_NUM_REGS + idev->reg_base;
	int ret;

	ret = iosf_mbi_read(QRK_MBI_UNIT_MM, MBI_REG_READ, reg++, &imr->addr_lo);
	if (ret)
		return ret;

	ret = iosf_mbi_read(QRK_MBI_UNIT_MM, MBI_REG_READ, reg++, &imr->addr_hi);
	if (ret)
		return ret;

	ret = iosf_mbi_read(QRK_MBI_UNIT_MM, MBI_REG_READ, reg++, &imr->rmask);
	if (ret)
		return ret;

	return iosf_mbi_read(QRK_MBI_UNIT_MM, MBI_REG_READ, reg++, &imr->wmask);
}

static int imr_write(struct imr_device *idev, u32 imr_id, struct imr_regs *imr)
{
	unsigned long flags;
	u32 reg = imr_id * IMR_NUM_REGS + idev->reg_base;
	int ret;

	local_irq_save(flags);

	ret = iosf_mbi_write(QRK_MBI_UNIT_MM, MBI_REG_WRITE, reg++, imr->addr_lo);
	if (ret)
		goto failed;

	ret = iosf_mbi_write(QRK_MBI_UNIT_MM, MBI_REG_WRITE, reg++, imr->addr_hi);
	if (ret)
		goto failed;

	ret = iosf_mbi_write(QRK_MBI_UNIT_MM, MBI_REG_WRITE, reg++, imr->rmask);
	if (ret)
		goto failed;

	ret = iosf_mbi_write(QRK_MBI_UNIT_MM, MBI_REG_WRITE, reg++, imr->wmask);
	if (ret)
		goto failed;

	local_irq_restore(flags);
	return 0;
failed:
	/*
	local_irq_restore(flags);
	WARN(ret, "IOSF-MBI write fail range 0x%08x-0x%08x unreliable\n",
	     imr_to_phys(imr->addr_lo), imr_to_phys(imr->addr_hi) + IMR_MASK);

	return ret;
}

static int imr_dbgfs_state_show(struct seq_file *s, void *unused)
{
	phys_addr_t base;
	phys_addr_t end;
	int i;
	struct imr_device *idev = s->private;
	struct imr_regs imr;
	size_t size;
	int ret = -ENODEV;

	mutex_lock(&idev->lock);

	for (i = 0; i < idev->max_imr; i++) {

		ret = imr_read(idev, i, &imr);
		if (ret)
			break;

		/*
		if (imr_is_enabled(&imr)) {
			base = imr_to_phys(imr.addr_lo);
			end = imr_to_phys(imr.addr_hi) + IMR_MASK;
			size = end - base + 1;
		} else {
			base = 0;
			end = 0;
			size = 0;
		}
		seq_printf(s, "imr%02i: base=%pa, end=%pa, size=0x%08zx "
			   "rmask=0x%08x, wmask=0x%08x, %s, %s\n", i,
			   &base, &end, size, imr.rmask, imr.wmask,
			   imr_is_enabled(&imr) ? "enabled " : "disabled",
			   imr.addr_lo & IMR_LOCK ? "locked" : "unlocked");
	}

	mutex_unlock(&idev->lock);
	return ret;
}
DEFINE_SHOW_ATTRIBUTE(imr_dbgfs_state);

static void imr_debugfs_register(struct imr_device *idev)
{
	debugfs_create_file("imr_state", 0444, NULL, idev,
			    &imr_dbgfs_state_fops);
}

static int imr_check_params(phys_addr_t base, size_t size)
{
	if ((base & IMR_MASK) || (size & IMR_MASK)) {
		pr_err("base %pa size 0x%08zx must align to 1KiB\n",
			&base, size);
		return -EINVAL;
	}
	if (size == 0)
		return -EINVAL;

	return 0;
}

static inline size_t imr_raw_size(size_t size)
{
	return size - IMR_ALIGN;
}

static inline int imr_address_overlap(phys_addr_t addr, struct imr_regs *imr)
{
	return addr >= imr_to_phys(imr->addr_lo) && addr <= imr_to_phys(imr->addr_hi);
}

int imr_add_range(phys_addr_t base, size_t size,
		  unsigned int rmask, unsigned int wmask)
{
	phys_addr_t end;
	unsigned int i;
	struct imr_device *idev = &imr_dev;
	struct imr_regs imr;
	size_t raw_size;
	int reg;
	int ret;

	if (WARN_ONCE(idev->init == false, "driver not initialized"))
		return -ENODEV;

	ret = imr_check_params(base, size);
	if (ret)
		return ret;

	/* Tweak the size value. */
	raw_size = imr_raw_size(size);
	end = base + raw_size;

	/*
	imr.addr_lo = phys_to_imr(base);
	imr.addr_hi = phys_to_imr(end);
	imr.rmask = rmask;
	imr.wmask = wmask;
	if (!imr_is_enabled(&imr))
		return -ENOTSUPP;

	mutex_lock(&idev->lock);

	/*
	reg = -1;
	for (i = 0; i < idev->max_imr; i++) {
		ret = imr_read(idev, i, &imr);
		if (ret)
			goto failed;

		/* Find overlap @ base or end of requested range. */
		ret = -EINVAL;
		if (imr_is_enabled(&imr)) {
			if (imr_address_overlap(base, &imr))
				goto failed;
			if (imr_address_overlap(end, &imr))
				goto failed;
		} else {
			reg = i;
		}
	}

	/* Error out if we have no free IMR entries. */
	if (reg == -1) {
		ret = -ENOMEM;
		goto failed;
	}

	pr_debug("add %d phys %pa-%pa size %zx mask 0x%08x wmask 0x%08x\n",
		 reg, &base, &end, raw_size, rmask, wmask);

	/* Enable IMR at specified range and access mask. */
	imr.addr_lo = phys_to_imr(base);
	imr.addr_hi = phys_to_imr(end);
	imr.rmask = rmask;
	imr.wmask = wmask;

	ret = imr_write(idev, reg, &imr);
	if (ret < 0) {
		/*
		imr.addr_lo = 0;
		imr.addr_hi = 0;
		imr.rmask = IMR_READ_ACCESS_ALL;
		imr.wmask = IMR_WRITE_ACCESS_ALL;
		imr_write(idev, reg, &imr);
	}
failed:
	mutex_unlock(&idev->lock);
	return ret;
}
EXPORT_SYMBOL_GPL(imr_add_range);

static int __imr_remove_range(int reg, phys_addr_t base, size_t size)
{
	phys_addr_t end;
	bool found = false;
	unsigned int i;
	struct imr_device *idev = &imr_dev;
	struct imr_regs imr;
	size_t raw_size;
	int ret = 0;

	if (WARN_ONCE(idev->init == false, "driver not initialized"))
		return -ENODEV;

	/*
	if (reg == -1) {
		ret = imr_check_params(base, size);
		if (ret)
			return ret;
	}

	/* Tweak the size value. */
	raw_size = imr_raw_size(size);
	end = base + raw_size;

	mutex_lock(&idev->lock);

	if (reg >= 0) {
		/* If a specific IMR is given try to use it. */
		ret = imr_read(idev, reg, &imr);
		if (ret)
			goto failed;

		if (!imr_is_enabled(&imr) || imr.addr_lo & IMR_LOCK) {
			ret = -ENODEV;
			goto failed;
		}
		found = true;
	} else {
		/* Search for match based on address range. */
		for (i = 0; i < idev->max_imr; i++) {
			ret = imr_read(idev, i, &imr);
			if (ret)
				goto failed;

			if (!imr_is_enabled(&imr) || imr.addr_lo & IMR_LOCK)
				continue;

			if ((imr_to_phys(imr.addr_lo) == base) &&
			    (imr_to_phys(imr.addr_hi) == end)) {
				found = true;
				reg = i;
				break;
			}
		}
	}

	if (!found) {
		ret = -ENODEV;
		goto failed;
	}

	pr_debug("remove %d phys %pa-%pa size %zx\n", reg, &base, &end, raw_size);

	/* Tear down the IMR. */
	imr.addr_lo = 0;
	imr.addr_hi = 0;
	imr.rmask = IMR_READ_ACCESS_ALL;
	imr.wmask = IMR_WRITE_ACCESS_ALL;

	ret = imr_write(idev, reg, &imr);

failed:
	mutex_unlock(&idev->lock);
	return ret;
}

int imr_remove_range(phys_addr_t base, size_t size)
{
	return __imr_remove_range(-1, base, size);
}
EXPORT_SYMBOL_GPL(imr_remove_range);

static inline int imr_clear(int reg)
{
	return __imr_remove_range(reg, 0, 0);
}

static void __init imr_fixup_memmap(struct imr_device *idev)
{
	phys_addr_t base = virt_to_phys(&_text);
	size_t size = virt_to_phys(&__end_rodata) - base;
	unsigned long start, end;
	int i;
	int ret;

	/* Tear down all existing unlocked IMRs. */
	for (i = 0; i < idev->max_imr; i++)
		imr_clear(i);

	start = (unsigned long)_text;
	end = (unsigned long)__end_rodata - 1;

	/*
	ret = imr_add_range(base, size, IMR_CPU, IMR_CPU);
	if (ret < 0) {
		pr_err("unable to setup IMR for kernel: %zu KiB (%lx - %lx)\n",
			size / 1024, start, end);
	} else {
		pr_info("protecting kernel .text - .rodata: %zu KiB (%lx - %lx)\n",
			size / 1024, start, end);
	}

}

static const struct x86_cpu_id imr_ids[] __initconst = {
	X86_MATCH_VENDOR_FAM_MODEL(INTEL, 5, INTEL_FAM5_QUARK_X1000, NULL),
	{}
};

static int __init imr_init(void)
{
	struct imr_device *idev = &imr_dev;

	if (!x86_match_cpu(imr_ids) || !iosf_mbi_available())
		return -ENODEV;

	idev->max_imr = QUARK_X1000_IMR_MAX;
	idev->reg_base = QUARK_X1000_IMR_REGBASE;
	idev->init = true;

	mutex_init(&idev->lock);
	imr_debugfs_register(idev);
	imr_fixup_memmap(idev);
	return 0;
}
device_initcall(imr_init);
