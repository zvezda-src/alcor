
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/mm.h>
#include <linux/export.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <linux/pid_namespace.h>
#include <linux/user_namespace.h>
#include <linux/uaccess.h>


const kernel_cap_t __cap_empty_set = CAP_EMPTY_SET;
EXPORT_SYMBOL(__cap_empty_set);

int file_caps_enabled = 1;

static int __init file_caps_disable(char *str)
{
	file_caps_enabled = 0;
	return 1;
}
__setup("no_file_caps", file_caps_disable);

#ifdef CONFIG_MULTIUSER

static void warn_legacy_capability_use(void)
{
	char name[sizeof(current->comm)];

	pr_info_once("warning: `%s' uses 32-bit capabilities (legacy support in use)\n",
		     get_task_comm(name, current));
}


static void warn_deprecated_v2(void)
{
	char name[sizeof(current->comm)];

	pr_info_once("warning: `%s' uses deprecated v2 capabilities in a way that may be insecure\n",
		     get_task_comm(name, current));
}

static int cap_validate_magic(cap_user_header_t header, unsigned *tocopy)
{
	__u32 version;

	if (get_user(version, &header->version))
		return -EFAULT;

	switch (version) {
	case _LINUX_CAPABILITY_VERSION_1:
		warn_legacy_capability_use();
		*tocopy = _LINUX_CAPABILITY_U32S_1;
		break;
	case _LINUX_CAPABILITY_VERSION_2:
		warn_deprecated_v2();
		fallthrough;	/* v3 is otherwise equivalent to v2 */
	case _LINUX_CAPABILITY_VERSION_3:
		*tocopy = _LINUX_CAPABILITY_U32S_3;
		break;
	default:
		if (put_user((u32)_KERNEL_CAPABILITY_VERSION, &header->version))
			return -EFAULT;
		return -EINVAL;
	}

	return 0;
}

static inline int cap_get_target_pid(pid_t pid, kernel_cap_t *pEp,
				     kernel_cap_t *pIp, kernel_cap_t *pPp)
{
	int ret;

	if (pid && (pid != task_pid_vnr(current))) {
		struct task_struct *target;

		rcu_read_lock();

		target = find_task_by_vpid(pid);
		if (!target)
			ret = -ESRCH;
		else
			ret = security_capget(target, pEp, pIp, pPp);

		rcu_read_unlock();
	} else
		ret = security_capget(current, pEp, pIp, pPp);

	return ret;
}

SYSCALL_DEFINE2(capget, cap_user_header_t, header, cap_user_data_t, dataptr)
{
	int ret = 0;
	pid_t pid;
	unsigned tocopy;
	kernel_cap_t pE, pI, pP;

	ret = cap_validate_magic(header, &tocopy);
	if ((dataptr == NULL) || (ret != 0))
		return ((dataptr == NULL) && (ret == -EINVAL)) ? 0 : ret;

	if (get_user(pid, &header->pid))
		return -EFAULT;

	if (pid < 0)
		return -EINVAL;

	ret = cap_get_target_pid(pid, &pE, &pI, &pP);
	if (!ret) {
		struct __user_cap_data_struct kdata[_KERNEL_CAPABILITY_U32S];
		unsigned i;

		for (i = 0; i < tocopy; i++) {
			kdata[i].effective = pE.cap[i];
			kdata[i].permitted = pP.cap[i];
			kdata[i].inheritable = pI.cap[i];
		}

		/*
		if (copy_to_user(dataptr, kdata, tocopy
				 * sizeof(struct __user_cap_data_struct))) {
			return -EFAULT;
		}
	}

	return ret;
}

SYSCALL_DEFINE2(capset, cap_user_header_t, header, const cap_user_data_t, data)
{
	struct __user_cap_data_struct kdata[_KERNEL_CAPABILITY_U32S];
	unsigned i, tocopy, copybytes;
	kernel_cap_t inheritable, permitted, effective;
	struct cred *new;
	int ret;
	pid_t pid;

	ret = cap_validate_magic(header, &tocopy);
	if (ret != 0)
		return ret;

	if (get_user(pid, &header->pid))
		return -EFAULT;

	/* may only affect current now */
	if (pid != 0 && pid != task_pid_vnr(current))
		return -EPERM;

	copybytes = tocopy * sizeof(struct __user_cap_data_struct);
	if (copybytes > sizeof(kdata))
		return -EFAULT;

	if (copy_from_user(&kdata, data, copybytes))
		return -EFAULT;

	for (i = 0; i < tocopy; i++) {
		effective.cap[i] = kdata[i].effective;
		permitted.cap[i] = kdata[i].permitted;
		inheritable.cap[i] = kdata[i].inheritable;
	}
	while (i < _KERNEL_CAPABILITY_U32S) {
		effective.cap[i] = 0;
		permitted.cap[i] = 0;
		inheritable.cap[i] = 0;
		i++;
	}

	effective.cap[CAP_LAST_U32] &= CAP_LAST_U32_VALID_MASK;
	permitted.cap[CAP_LAST_U32] &= CAP_LAST_U32_VALID_MASK;
	inheritable.cap[CAP_LAST_U32] &= CAP_LAST_U32_VALID_MASK;

	new = prepare_creds();
	if (!new)
		return -ENOMEM;

	ret = security_capset(new, current_cred(),
			      &effective, &inheritable, &permitted);
	if (ret < 0)
		goto error;

	audit_log_capset(new, current_cred());

	return commit_creds(new);

error:
	abort_creds(new);
	return ret;
}

bool has_ns_capability(struct task_struct *t,
		       struct user_namespace *ns, int cap)
{
	int ret;

	rcu_read_lock();
	ret = security_capable(__task_cred(t), ns, cap, CAP_OPT_NONE);
	rcu_read_unlock();

	return (ret == 0);
}

bool has_capability(struct task_struct *t, int cap)
{
	return has_ns_capability(t, &init_user_ns, cap);
}
EXPORT_SYMBOL(has_capability);

bool has_ns_capability_noaudit(struct task_struct *t,
			       struct user_namespace *ns, int cap)
{
	int ret;

	rcu_read_lock();
	ret = security_capable(__task_cred(t), ns, cap, CAP_OPT_NOAUDIT);
	rcu_read_unlock();

	return (ret == 0);
}

bool has_capability_noaudit(struct task_struct *t, int cap)
{
	return has_ns_capability_noaudit(t, &init_user_ns, cap);
}
EXPORT_SYMBOL(has_capability_noaudit);

static bool ns_capable_common(struct user_namespace *ns,
			      int cap,
			      unsigned int opts)
{
	int capable;

	if (unlikely(!cap_valid(cap))) {
		pr_crit("capable() called with invalid cap=%u\n", cap);
		BUG();
	}

	capable = security_capable(current_cred(), ns, cap, opts);
	if (capable == 0) {
		current->flags |= PF_SUPERPRIV;
		return true;
	}
	return false;
}

bool ns_capable(struct user_namespace *ns, int cap)
{
	return ns_capable_common(ns, cap, CAP_OPT_NONE);
}
EXPORT_SYMBOL(ns_capable);

bool ns_capable_noaudit(struct user_namespace *ns, int cap)
{
	return ns_capable_common(ns, cap, CAP_OPT_NOAUDIT);
}
EXPORT_SYMBOL(ns_capable_noaudit);

bool ns_capable_setid(struct user_namespace *ns, int cap)
{
	return ns_capable_common(ns, cap, CAP_OPT_INSETID);
}
EXPORT_SYMBOL(ns_capable_setid);

bool capable(int cap)
{
	return ns_capable(&init_user_ns, cap);
}
EXPORT_SYMBOL(capable);
#endif /* CONFIG_MULTIUSER */

bool file_ns_capable(const struct file *file, struct user_namespace *ns,
		     int cap)
{

	if (WARN_ON_ONCE(!cap_valid(cap)))
		return false;

	if (security_capable(file->f_cred, ns, cap, CAP_OPT_NONE) == 0)
		return true;

	return false;
}
EXPORT_SYMBOL(file_ns_capable);

bool privileged_wrt_inode_uidgid(struct user_namespace *ns,
				 struct user_namespace *mnt_userns,
				 const struct inode *inode)
{
	return kuid_has_mapping(ns, i_uid_into_mnt(mnt_userns, inode)) &&
	       kgid_has_mapping(ns, i_gid_into_mnt(mnt_userns, inode));
}

bool capable_wrt_inode_uidgid(struct user_namespace *mnt_userns,
			      const struct inode *inode, int cap)
{
	struct user_namespace *ns = current_user_ns();

	return ns_capable(ns, cap) &&
	       privileged_wrt_inode_uidgid(ns, mnt_userns, inode);
}
EXPORT_SYMBOL(capable_wrt_inode_uidgid);

bool ptracer_capable(struct task_struct *tsk, struct user_namespace *ns)
{
	int ret = 0;  /* An absent tracer adds no restrictions */
	const struct cred *cred;

	rcu_read_lock();
	cred = rcu_dereference(tsk->ptracer_cred);
	if (cred)
		ret = security_capable(cred, ns, CAP_SYS_PTRACE,
				       CAP_OPT_NOAUDIT);
	rcu_read_unlock();
	return (ret == 0);
}
