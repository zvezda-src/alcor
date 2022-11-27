
#include <crypto/twofish.h>
#include <linux/crypto.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/types.h>

asmlinkage void twofish_enc_blk(struct twofish_ctx *ctx, u8 *dst,
				const u8 *src);
EXPORT_SYMBOL_GPL(twofish_enc_blk);
asmlinkage void twofish_dec_blk(struct twofish_ctx *ctx, u8 *dst,
				const u8 *src);
EXPORT_SYMBOL_GPL(twofish_dec_blk);

static void twofish_encrypt(struct crypto_tfm *tfm, u8 *dst, const u8 *src)
{
	twofish_enc_blk(crypto_tfm_ctx(tfm), dst, src);
}

static void twofish_decrypt(struct crypto_tfm *tfm, u8 *dst, const u8 *src)
{
	twofish_dec_blk(crypto_tfm_ctx(tfm), dst, src);
}

static struct crypto_alg alg = {
	.cra_name		=	"twofish",
	.cra_driver_name	=	"twofish-asm",
	.cra_priority		=	200,
	.cra_flags		=	CRYPTO_ALG_TYPE_CIPHER,
	.cra_blocksize		=	TF_BLOCK_SIZE,
	.cra_ctxsize		=	sizeof(struct twofish_ctx),
	.cra_alignmask		=	0,
	.cra_module		=	THIS_MODULE,
	.cra_u			=	{
		.cipher = {
			.cia_min_keysize	=	TF_MIN_KEY_SIZE,
			.cia_max_keysize	=	TF_MAX_KEY_SIZE,
			.cia_setkey		=	twofish_setkey,
			.cia_encrypt		=	twofish_encrypt,
			.cia_decrypt		=	twofish_decrypt
		}
	}
};

static int __init twofish_glue_init(void)
{
	return crypto_register_alg(&alg);
}

static void __exit twofish_glue_fini(void)
{
	crypto_unregister_alg(&alg);
}

module_init(twofish_glue_init);
module_exit(twofish_glue_fini);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION ("Twofish Cipher Algorithm, asm optimized");
MODULE_ALIAS_CRYPTO("twofish");
MODULE_ALIAS_CRYPTO("twofish-asm");
