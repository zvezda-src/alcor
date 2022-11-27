#include <linux/export.h>
#include <linux/slab.h>
#include <linux/regset.h>

static int __regset_get(struct task_struct *target,
			const struct user_regset *regset,
			unsigned int size,
			void **data)
{
	void *p = *data, *to_free = NULL;
	int res;

	if (!regset->regset_get)
		return -EOPNOTSUPP;
	if (size > regset->n * regset->size)
		size = regset->n * regset->size;
	if (!p) {
		to_free = p = kzalloc(size, GFP_KERNEL);
		if (!p)
			return -ENOMEM;
	}
	res = regset->regset_get(target, regset,
			   (struct membuf){.p = p, .left = size});
	if (res < 0) {
		kfree(to_free);
		return res;
	}
	return size - res;
}

int regset_get(struct task_struct *target,
	       const struct user_regset *regset,
	       unsigned int size,
	       void *data)
{
	return __regset_get(target, regset, size, &data);
}
EXPORT_SYMBOL(regset_get);

int regset_get_alloc(struct task_struct *target,
		     const struct user_regset *regset,
		     unsigned int size,
		     void **data)
{
	return __regset_get(target, regset, size, data);
}
EXPORT_SYMBOL(regset_get_alloc);

int copy_regset_to_user(struct task_struct *target,
			const struct user_regset_view *view,
			unsigned int setno,
			unsigned int offset, unsigned int size,
			void __user *data)
{
	const struct user_regset *regset = &view->regsets[setno];
	void *buf;
	int ret;

	ret = regset_get_alloc(target, regset, size, &buf);
	if (ret > 0)
		ret = copy_to_user(data, buf, ret) ? -EFAULT : 0;
	kfree(buf);
	return ret;
}
