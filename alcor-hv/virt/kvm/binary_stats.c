
#include <linux/kvm_host.h>
#include <linux/kvm.h>
#include <linux/errno.h>
#include <linux/uaccess.h>

ssize_t kvm_stats_read(char *id, const struct kvm_stats_header *header,
		       const struct _kvm_stats_desc *desc,
		       void *stats, size_t size_stats,
		       char __user *user_buffer, size_t size, loff_t *offset)
{
	ssize_t len;
	ssize_t copylen;
	ssize_t remain = size;
	size_t size_desc;
	size_t size_header;
	void *src;
	loff_t pos = *offset;
	char __user *dest = user_buffer;

	size_header = sizeof(*header);
	size_desc = header->num_desc * sizeof(*desc);

	len = KVM_STATS_NAME_SIZE + size_header + size_desc + size_stats - pos;
	len = min(len, remain);
	if (len <= 0)
		return 0;
	remain = len;

	/*
	copylen = size_header - pos;
	copylen = min(copylen, remain);
	if (copylen > 0) {
		src = (void *)header + pos;
		if (copy_to_user(dest, src, copylen))
			return -EFAULT;
		remain -= copylen;
		pos += copylen;
		dest += copylen;
	}

	/*
	copylen = header->id_offset + KVM_STATS_NAME_SIZE - pos;
	copylen = min(copylen, remain);
	if (copylen > 0) {
		src = id + pos - header->id_offset;
		if (copy_to_user(dest, src, copylen))
			return -EFAULT;
		remain -= copylen;
		pos += copylen;
		dest += copylen;
	}

	/*
	copylen = header->desc_offset + size_desc - pos;
	copylen = min(copylen, remain);
	if (copylen > 0) {
		src = (void *)desc + pos - header->desc_offset;
		if (copy_to_user(dest, src, copylen))
			return -EFAULT;
		remain -= copylen;
		pos += copylen;
		dest += copylen;
	}

	/* Copy kvm stats values */
	copylen = header->data_offset + size_stats - pos;
	copylen = min(copylen, remain);
	if (copylen > 0) {
		src = stats + pos - header->data_offset;
		if (copy_to_user(dest, src, copylen))
			return -EFAULT;
		pos += copylen;
	}

	return len;
}
