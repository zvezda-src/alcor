
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/module_signature.h>
#include <linux/string.h>
#include <linux/verification.h>
#include <linux/security.h>
#include <crypto/public_key.h>
#include <uapi/linux/module.h>
#include "internal.h"

#undef MODULE_PARAM_PREFIX
#define MODULE_PARAM_PREFIX "module."

static bool sig_enforce = IS_ENABLED(CONFIG_MODULE_SIG_FORCE);
module_param(sig_enforce, bool_enable_only, 0644);

bool is_module_sig_enforced(void)
{
	return sig_enforce;
}
EXPORT_SYMBOL(is_module_sig_enforced);

void set_module_sig_enforced(void)
{
	sig_enforce = true;
}

int mod_verify_sig(const void *mod, struct load_info *info)
{
	struct module_signature ms;
	size_t sig_len, modlen = info->len;
	int ret;

	pr_devel("==>%s(,%zu)\n", __func__, modlen);

	if (modlen <= sizeof(ms))
		return -EBADMSG;

	memcpy(&ms, mod + (modlen - sizeof(ms)), sizeof(ms));

	ret = mod_check_sig(&ms, modlen, "module");
	if (ret)
		return ret;

	sig_len = be32_to_cpu(ms.sig_len);
	modlen -= sig_len + sizeof(ms);
	info->len = modlen;

	return verify_pkcs7_signature(mod, modlen, mod + modlen, sig_len,
				      VERIFY_USE_SECONDARY_KEYRING,
				      VERIFYING_MODULE_SIGNATURE,
				      NULL, NULL);
}

int module_sig_check(struct load_info *info, int flags)
{
	int err = -ENODATA;
	const unsigned long markerlen = sizeof(MODULE_SIG_STRING) - 1;
	const char *reason;
	const void *mod = info->hdr;
	bool mangled_module = flags & (MODULE_INIT_IGNORE_MODVERSIONS |
				       MODULE_INIT_IGNORE_VERMAGIC);
	/*
	if (!mangled_module &&
	    info->len > markerlen &&
	    memcmp(mod + info->len - markerlen, MODULE_SIG_STRING, markerlen) == 0) {
		/* We truncate the module to discard the signature */
		info->len -= markerlen;
		err = mod_verify_sig(mod, info);
		if (!err) {
			info->sig_ok = true;
			return 0;
		}
	}

	/*
	switch (err) {
	case -ENODATA:
		reason = "unsigned module";
		break;
	case -ENOPKG:
		reason = "module with unsupported crypto";
		break;
	case -ENOKEY:
		reason = "module with unavailable key";
		break;

	default:
		/*
		return err;
	}

	if (is_module_sig_enforced()) {
		pr_notice("Loading of %s is rejected\n", reason);
		return -EKEYREJECTED;
	}

	return security_locked_down(LOCKDOWN_MODULE_SIGNATURE);
}
