
#include <linux/dma-direct.h>
#include <linux/dma-mapping.h>
#include <linux/swiotlb.h>
#include <linux/cc_platform.h>
#include <linux/mem_encrypt.h>

bool force_dma_unencrypted(struct device *dev)
{
	/*
	if (cc_platform_has(CC_ATTR_GUEST_MEM_ENCRYPT))
		return true;

	/*
	if (cc_platform_has(CC_ATTR_HOST_MEM_ENCRYPT)) {
		u64 dma_enc_mask = DMA_BIT_MASK(__ffs64(sme_me_mask));
		u64 dma_dev_mask = min_not_zero(dev->coherent_dma_mask,
						dev->bus_dma_limit);

		if (dma_dev_mask <= dma_enc_mask)
			return true;
	}

	return false;
}

static void print_mem_encrypt_feature_info(void)
{
	pr_info("Memory Encryption Features active:");

	if (cpu_feature_enabled(X86_FEATURE_TDX_GUEST)) {
		pr_cont(" Intel TDX\n");
		return;
	}

	pr_cont(" AMD");

	/* Secure Memory Encryption */
	if (cc_platform_has(CC_ATTR_HOST_MEM_ENCRYPT)) {
		/*
		pr_cont(" SME\n");
		return;
	}

	/* Secure Encrypted Virtualization */
	if (cc_platform_has(CC_ATTR_GUEST_MEM_ENCRYPT))
		pr_cont(" SEV");

	/* Encrypted Register State */
	if (cc_platform_has(CC_ATTR_GUEST_STATE_ENCRYPT))
		pr_cont(" SEV-ES");

	/* Secure Nested Paging */
	if (cc_platform_has(CC_ATTR_GUEST_SEV_SNP))
		pr_cont(" SEV-SNP");

	pr_cont("\n");
}

void __init mem_encrypt_init(void)
{
	if (!cc_platform_has(CC_ATTR_MEM_ENCRYPT))
		return;

	/* Call into SWIOTLB to update the SWIOTLB DMA buffers */
	swiotlb_update_mem_attributes();

	print_mem_encrypt_feature_info();
}
