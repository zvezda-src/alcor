
#include <linux/bug.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <crypto/sha2.h>
#include <asm/purgatory.h>

#include "../boot/string.h"

u8 purgatory_sha256_digest[SHA256_DIGEST_SIZE] __section(".kexec-purgatory");

struct kexec_sha_region purgatory_sha_regions[KEXEC_SEGMENT_MAX] __section(".kexec-purgatory");

static int verify_sha256_digest(void)
{
	struct kexec_sha_region *ptr, *end;
	u8 digest[SHA256_DIGEST_SIZE];
	struct sha256_state sctx;

	sha256_init(&sctx);
	end = purgatory_sha_regions + ARRAY_SIZE(purgatory_sha_regions);

	for (ptr = purgatory_sha_regions; ptr < end; ptr++)
		sha256_update(&sctx, (uint8_t *)(ptr->start), ptr->len);

	sha256_final(&sctx, digest);

	if (memcmp(digest, purgatory_sha256_digest, sizeof(digest)))
		return 1;

	return 0;
}

void purgatory(void)
{
	int ret;

	ret = verify_sha256_digest();
	if (ret) {
		/* loop forever */
		for (;;)
			;
	}
}

void warn(const char *msg) {}
