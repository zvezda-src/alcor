#ifndef ASM_X86_TWOFISH_H
#define ASM_X86_TWOFISH_H

#include <linux/crypto.h>
#include <crypto/twofish.h>
#include <crypto/b128ops.h>

asmlinkage void twofish_enc_blk(const void *ctx, u8 *dst, const u8 *src);
asmlinkage void twofish_dec_blk(const void *ctx, u8 *dst, const u8 *src);

asmlinkage void __twofish_enc_blk_3way(const void *ctx, u8 *dst, const u8 *src,
				       bool xor);
asmlinkage void twofish_dec_blk_3way(const void *ctx, u8 *dst, const u8 *src);

extern void twofish_dec_blk_cbc_3way(const void *ctx, u8 *dst, const u8 *src);

#endif /* ASM_X86_TWOFISH_H */
