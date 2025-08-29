// SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
/* Copyright(c) 2014 - 2021 Intel Corporation */
#ifdef QAT_SKCIPHER_SUPPORTED
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/crypto.h>
#include <crypto/internal/aead.h>
#include <crypto/internal/skcipher.h>
#include <crypto/aes.h>
#ifndef QAT_SINGLE_SHA_HEADER
#include <crypto/sha1.h>
#include <crypto/sha2.h>
#else
#include <crypto/sha.h>
#endif
#include <crypto/gcm.h>
#include <crypto/hash.h>
#include <crypto/ghash.h>
#include <crypto/algapi.h>
#include <crypto/authenc.h>
#include <crypto/scatterwalk.h>
#include <linux/dma-mapping.h>
#include "adf_accel_devices.h"
#include "adf_transport_internal.h"
#include "adf_common_drv.h"
#include "qat_algs_send.h"
#include "icp_qat_hw.h"
#include "icp_qat_fw.h"
#include "icp_qat_fw_la.h"
#if KERNEL_VERSION(5, 12, 0) <= LINUX_VERSION_CODE
#include <crypto/internal/cipher.h>
#endif
#if KERNEL_VERSION(5, 12, 0) <= LINUX_VERSION_CODE
MODULE_IMPORT_NS(CRYPTO_INTERNAL);
#endif

#define QAT_AES_HW_CONFIG_ENC(alg, mode) \
	ICP_QAT_HW_CIPHER_CONFIG_BUILD(mode, alg, \
				       ICP_QAT_HW_CIPHER_NO_CONVERT, \
				       ICP_QAT_HW_CIPHER_ENCRYPT)

#define QAT_AES_HW_CONFIG_DEC(alg, mode) \
	ICP_QAT_HW_CIPHER_CONFIG_BUILD(mode, alg, \
				       ICP_QAT_HW_CIPHER_KEY_CONVERT, \
				       ICP_QAT_HW_CIPHER_DECRYPT)

static DEFINE_MUTEX(algs_lock);
static unsigned int active_devs;

/* Common content descriptor */
struct qat_alg_cd {
	union {
		struct qat_enc { /* Encrypt content desc */
			struct icp_qat_hw_cipher_algo_blk cipher;
			struct icp_qat_hw_auth_algo_blk hash;
		} qat_enc_cd;
		struct qat_dec { /* Decrytp content desc */
			struct icp_qat_hw_auth_algo_blk hash;
			struct icp_qat_hw_cipher_algo_blk cipher;
		} qat_dec_cd;
	};
} __aligned(8);

struct qat_alg_aead_ctx {
	struct qat_alg_cd *enc_cd;
	struct qat_alg_cd *dec_cd;
	dma_addr_t enc_cd_paddr;
	dma_addr_t dec_cd_paddr;
	struct icp_qat_fw_la_bulk_req enc_fw_req;
	struct icp_qat_fw_la_bulk_req dec_fw_req;
	union {
		struct crypto_shash *shash_tfm;
		struct crypto_ahash *ahash_tfm;
	} tfm;
	enum icp_qat_hw_auth_algo qat_hash_alg;
	struct qat_crypto_instance *inst;
};

struct qat_alg_skcipher_ctx {
	struct icp_qat_hw_cipher_algo_blk *enc_cd;
	struct icp_qat_hw_cipher_algo_blk *dec_cd;
	dma_addr_t enc_cd_paddr;
	dma_addr_t dec_cd_paddr;
	struct icp_qat_fw_la_bulk_req enc_fw_req;
	struct icp_qat_fw_la_bulk_req dec_fw_req;
	struct qat_crypto_instance *inst;
	struct crypto_skcipher *tfm;
	int mode;
};

static size_t copy_sgl_to_buf(struct scatterlist *src,
			      size_t src_offset,
			      u8 *dst_buffer,
			      size_t dst_offset,
			      size_t len)
{
	int i, nents;
	struct scatterlist *sg_entry;
	u8 *buffer = dst_buffer + dst_offset;
	size_t sg_remaining_len, copy_len = 0;

	if (!src || !dst_buffer)
		return 0;

	if (len == 0)
		return 0;

	nents = sg_nents(src);

	for_each_sg(src, sg_entry, nents, i) {
		if (sg_entry->length > 0) {
			if (src_offset >= sg_entry->length) {
				src_offset -= sg_entry->length;
				continue;
			}

			sg_remaining_len = sg_entry->length - src_offset;

			if (sg_remaining_len >= len) {
				memcpy(buffer + copy_len, sg_virt(sg_entry) + src_offset, len);
				copy_len += len;
				break;
			}

			memcpy(buffer + copy_len, sg_virt(sg_entry) + src_offset, sg_remaining_len);
			copy_len += sg_remaining_len;
			len -= sg_remaining_len;
			src_offset = 0;
		}
	}

	return copy_len;
}

static int qat_get_inter_state_size(enum icp_qat_hw_auth_algo qat_hash_alg)
{
	switch (qat_hash_alg) {
	case ICP_QAT_HW_AUTH_ALGO_SHA1:
		return ICP_QAT_HW_SHA1_STATE1_SZ;
	case ICP_QAT_HW_AUTH_ALGO_SHA256:
		return ICP_QAT_HW_SHA256_STATE1_SZ;
	case ICP_QAT_HW_AUTH_ALGO_SHA512:
		return ICP_QAT_HW_SHA512_STATE1_SZ;
	default:
		return -EFAULT;
	};
	return -EFAULT;
}

static int qat_alg_do_precomputes(struct icp_qat_hw_auth_algo_blk *hash,
				  struct qat_alg_aead_ctx *ctx,
				  const uint8_t *auth_key,
				  unsigned int auth_keylen)
{
	SHASH_DESC_ON_STACK(shash, ctx->tfm.shash_tfm);
	struct sha1_state sha1;
	struct sha256_state sha256;
	struct sha512_state sha512;
	int block_size = crypto_shash_blocksize(ctx->tfm.shash_tfm);
	int digest_size = crypto_shash_digestsize(ctx->tfm.shash_tfm);
	__be32 *hash_state_out;
	__be64 *hash512_state_out;
	char *ipad = NULL;
	char *opad = NULL;
	gfp_t flags;
	int i, offset;

	flags = CRYPTO_TFM_REQ_MAY_SLEEP ? GFP_KERNEL : GFP_ATOMIC;
	ipad = kzalloc(block_size, flags);
	if (unlikely(!ipad))
		return -ENOMEM;

	opad = kzalloc(block_size, flags);
	if (unlikely(!opad)) {
		kfree(ipad);
		return -ENOMEM;
	}

	memset(shash, 0, sizeof(struct shash_desc));
	shash->tfm = ctx->tfm.shash_tfm;

	if (auth_keylen > block_size) {
		int ret = crypto_shash_digest(shash, auth_key,
					      auth_keylen, ipad);
		if (ret) {
			kfree(ipad);
			kfree(opad);
			return ret;
		}

		memcpy(opad, ipad, digest_size);
	} else {
		memcpy(ipad, auth_key, auth_keylen);
		memcpy(opad, auth_key, auth_keylen);
	}

	for (i = 0; i < block_size; i++) {
		char *ipad_ptr = ipad + i;
		char *opad_ptr = opad + i;
		*ipad_ptr ^= 0x36;
		*opad_ptr ^= 0x5C;
	}

	if (crypto_shash_init(shash))
		goto error;

	if (crypto_shash_update(shash, ipad, block_size))
		goto error;

	hash_state_out = (__be32 *)hash->auth.sha.state1;
	hash512_state_out = (__be64 *)hash_state_out;

	switch (ctx->qat_hash_alg) {
	case ICP_QAT_HW_AUTH_ALGO_SHA1:
		if (crypto_shash_export(shash, &sha1))
			goto error;
		for (i = 0; i < digest_size >> 2; i++, hash_state_out++)
			*hash_state_out = cpu_to_be32(*(sha1.state + i));
		break;
	case ICP_QAT_HW_AUTH_ALGO_SHA256:
		if (crypto_shash_export(shash, &sha256))
			goto error;
		for (i = 0; i < digest_size >> 2; i++, hash_state_out++)
			*hash_state_out = cpu_to_be32(*(sha256.state + i));
		break;
	case ICP_QAT_HW_AUTH_ALGO_SHA512:
		if (crypto_shash_export(shash, &sha512))
			goto error;
		for (i = 0; i < digest_size >> 3; i++, hash512_state_out++)
			*hash512_state_out = cpu_to_be64(*(sha512.state + i));
		break;
	default:
		goto error;
	}

	if (crypto_shash_init(shash))
		goto error;

	if (crypto_shash_update(shash, opad, block_size))
		goto error;

	offset = round_up(qat_get_inter_state_size(ctx->qat_hash_alg), 8);
	if (offset < 0)
		goto error;

	hash_state_out = (__be32 *)(hash->auth.sha.state1 + offset);
	hash512_state_out = (__be64 *)hash_state_out;

	switch (ctx->qat_hash_alg) {
	case ICP_QAT_HW_AUTH_ALGO_SHA1:
		if (crypto_shash_export(shash, &sha1))
			goto error;
		for (i = 0; i < digest_size >> 2; i++, hash_state_out++)
			*hash_state_out = cpu_to_be32(*(sha1.state + i));
		break;
	case ICP_QAT_HW_AUTH_ALGO_SHA256:
		if (crypto_shash_export(shash, &sha256))
			goto error;
		for (i = 0; i < digest_size >> 2; i++, hash_state_out++)
			*hash_state_out = cpu_to_be32(*(sha256.state + i));
		break;
	case ICP_QAT_HW_AUTH_ALGO_SHA512:
		if (crypto_shash_export(shash, &sha512))
			goto error;
		for (i = 0; i < digest_size >> 3; i++, hash512_state_out++)
			*hash512_state_out = cpu_to_be64(*(sha512.state + i));
		break;
	default:
		goto error;
	}
	memzero_explicit(ipad, block_size);
	memzero_explicit(opad, block_size);
	kfree(ipad);
	kfree(opad);
	return 0;
error:
	memzero_explicit(ipad, block_size);
	memzero_explicit(opad, block_size);
	kfree(ipad);
	kfree(opad);
	return -EFAULT;
}

static int qat_alg_do_gcm_precomputes(const u8 *key,
				      unsigned int keylen,
				      uint8_t *p_state2)
{
	static struct crypto_cipher *cipher_tfm;
	gfp_t flags;
	u8 *h_multiplier = NULL;

	flags = CRYPTO_TFM_REQ_MAY_SLEEP ? GFP_KERNEL : GFP_ATOMIC;
	h_multiplier = kzalloc(ICP_QAT_HW_GALOIS_H_SZ, flags);

	if (unlikely(!h_multiplier))
		return -ENOMEM;

	cipher_tfm = crypto_alloc_cipher("aes", 0, 0);

	if (IS_ERR(cipher_tfm)) {
		kfree(h_multiplier);
		return -EFAULT;
	}

	crypto_cipher_setkey(cipher_tfm, key, keylen);
	crypto_cipher_encrypt_one(cipher_tfm, p_state2, h_multiplier);

	if (!IS_ERR(cipher_tfm))
		crypto_free_cipher(cipher_tfm);

	memset((p_state2 + (ICP_QAT_HW_GALOIS_LEN_A_SZ +
		ICP_QAT_HW_GALOIS_E_CTR0_SZ)), 0, ICP_QAT_HW_GALOIS_H_SZ);

	kfree(h_multiplier);
	return 0;
}

static void qat_alg_init_common_hdr(struct icp_qat_fw_comn_req_hdr *header)
{
	header->hdr_flags =
		ICP_QAT_FW_COMN_HDR_FLAGS_BUILD(ICP_QAT_FW_COMN_REQ_FLAG_SET);
	header->service_type = ICP_QAT_FW_COMN_REQ_CPM_FW_LA;
	header->comn_req_flags =
		ICP_QAT_FW_COMN_FLAGS_BUILD(QAT_COMN_CD_FLD_TYPE_64BIT_ADR,
					    QAT_COMN_PTR_TYPE_SGL);
	ICP_QAT_FW_LA_PARTIAL_SET(header->serv_specif_flags,
				  ICP_QAT_FW_LA_PARTIAL_NONE);
	ICP_QAT_FW_LA_CIPH_IV_FLD_FLAG_SET(header->serv_specif_flags,
					   ICP_QAT_FW_CIPH_IV_16BYTE_DATA);
	ICP_QAT_FW_LA_PROTO_SET(header->serv_specif_flags,
				ICP_QAT_FW_LA_NO_PROTO);
	ICP_QAT_FW_LA_UPDATE_STATE_SET(header->serv_specif_flags,
				       ICP_QAT_FW_LA_NO_UPDATE_STATE);
}

static int qat_alg_aead_init_enc_session(struct crypto_aead *aead_tfm,
					 int alg,
					 struct crypto_authenc_keys *keys,
					 int mode)
{
	struct qat_alg_aead_ctx *ctx = crypto_aead_ctx(aead_tfm);
	unsigned int digestsize = crypto_aead_authsize(aead_tfm);
	struct qat_enc *enc_ctx = &ctx->enc_cd->qat_enc_cd;
	struct icp_qat_hw_cipher_algo_blk *cipher = &enc_ctx->cipher;
	struct icp_qat_hw_auth_algo_blk *hash =
		(struct icp_qat_hw_auth_algo_blk *)((char *)enc_ctx +
		sizeof(struct icp_qat_hw_auth_setup) + keys->enckeylen);
	struct icp_qat_fw_la_bulk_req *req_tmpl = &ctx->enc_fw_req;
	struct icp_qat_fw_comn_req_hdr_cd_pars *cd_pars = &req_tmpl->cd_pars;
	struct icp_qat_fw_comn_req_hdr *header = &req_tmpl->comn_hdr;
	void *ptr = &req_tmpl->cd_ctrl;
	struct icp_qat_fw_cipher_cd_ctrl_hdr *cipher_cd_ctrl = ptr;
	struct icp_qat_fw_auth_cd_ctrl_hdr *hash_cd_ctrl = ptr;

	/* CD setup */
	cipher->aes.cipher_config.val = QAT_AES_HW_CONFIG_ENC(alg, mode);
	memcpy(cipher->aes.key, keys->enckey, keys->enckeylen);
	hash->auth.sha.inner_setup.auth_config.config =
		ICP_QAT_HW_AUTH_CONFIG_BUILD(ICP_QAT_HW_AUTH_MODE1,
					     ctx->qat_hash_alg, digestsize);
	hash->auth.sha.inner_setup.auth_counter.counter =
		cpu_to_be32(crypto_shash_blocksize(ctx->tfm.shash_tfm));

	if (qat_alg_do_precomputes(hash, ctx, keys->authkey, keys->authkeylen))
		return -EFAULT;

	/* Request setup */
	qat_alg_init_common_hdr(header);
	header->service_cmd_id = ICP_QAT_FW_LA_CMD_CIPHER_HASH;
	ICP_QAT_FW_LA_DIGEST_IN_BUFFER_SET(header->serv_specif_flags,
					   ICP_QAT_FW_LA_DIGEST_IN_BUFFER);
	ICP_QAT_FW_LA_RET_AUTH_SET(header->serv_specif_flags,
				   ICP_QAT_FW_LA_RET_AUTH_RES);
	ICP_QAT_FW_LA_CMP_AUTH_SET(header->serv_specif_flags,
				   ICP_QAT_FW_LA_NO_CMP_AUTH_RES);
	cd_pars->u.s.content_desc_addr = ctx->enc_cd_paddr;
	cd_pars->u.s.content_desc_params_sz = sizeof(struct qat_alg_cd) >> 3;

	/* Cipher CD config setup */
	cipher_cd_ctrl->cipher_key_sz = keys->enckeylen >> 3;
	cipher_cd_ctrl->cipher_state_sz = AES_BLOCK_SIZE >> 3;
	cipher_cd_ctrl->cipher_cfg_offset = 0;
	ICP_QAT_FW_COMN_CURR_ID_SET(cipher_cd_ctrl, ICP_QAT_FW_SLICE_CIPHER);
	ICP_QAT_FW_COMN_NEXT_ID_SET(cipher_cd_ctrl, ICP_QAT_FW_SLICE_AUTH);
	/* Auth CD config setup */
	hash_cd_ctrl->hash_cfg_offset = ((char *)hash - (char *)cipher) >> 3;
	hash_cd_ctrl->hash_flags = ICP_QAT_FW_AUTH_HDR_FLAG_NO_NESTED;
	hash_cd_ctrl->inner_res_sz = digestsize;
	hash_cd_ctrl->final_sz = digestsize;

	switch (ctx->qat_hash_alg) {
	case ICP_QAT_HW_AUTH_ALGO_SHA1:
		hash_cd_ctrl->inner_state1_sz =
			round_up(ICP_QAT_HW_SHA1_STATE1_SZ, 8);
		hash_cd_ctrl->inner_state2_sz =
			round_up(ICP_QAT_HW_SHA1_STATE2_SZ, 8);
		break;
	case ICP_QAT_HW_AUTH_ALGO_SHA256:
		hash_cd_ctrl->inner_state1_sz = ICP_QAT_HW_SHA256_STATE1_SZ;
		hash_cd_ctrl->inner_state2_sz = ICP_QAT_HW_SHA256_STATE2_SZ;
		break;
	case ICP_QAT_HW_AUTH_ALGO_SHA512:
		hash_cd_ctrl->inner_state1_sz = ICP_QAT_HW_SHA512_STATE1_SZ;
		hash_cd_ctrl->inner_state2_sz = ICP_QAT_HW_SHA512_STATE2_SZ;
		break;
	default:
		break;
	}
	hash_cd_ctrl->inner_state2_offset = hash_cd_ctrl->hash_cfg_offset +
			((sizeof(struct icp_qat_hw_auth_setup) +
			 round_up(hash_cd_ctrl->inner_state1_sz, 8)) >> 3);
	ICP_QAT_FW_COMN_CURR_ID_SET(hash_cd_ctrl, ICP_QAT_FW_SLICE_AUTH);
	ICP_QAT_FW_COMN_NEXT_ID_SET(hash_cd_ctrl, ICP_QAT_FW_SLICE_DRAM_WR);
	return 0;
}

static int qat_alg_aead_init_dec_session(struct crypto_aead *aead_tfm,
					 int alg,
					 struct crypto_authenc_keys *keys,
					 int mode)
{
	struct qat_alg_aead_ctx *ctx = crypto_aead_ctx(aead_tfm);
	unsigned int digestsize = crypto_aead_authsize(aead_tfm);
	struct qat_dec *dec_ctx = &ctx->dec_cd->qat_dec_cd;
	struct icp_qat_hw_auth_algo_blk *hash = &dec_ctx->hash;
	struct icp_qat_hw_cipher_algo_blk *cipher =
		(struct icp_qat_hw_cipher_algo_blk *)((char *)dec_ctx +
		sizeof(struct icp_qat_hw_auth_setup) +
		roundup(crypto_shash_digestsize(ctx->tfm.shash_tfm), 8) * 2);
	struct icp_qat_fw_la_bulk_req *req_tmpl = &ctx->dec_fw_req;
	struct icp_qat_fw_comn_req_hdr_cd_pars *cd_pars = &req_tmpl->cd_pars;
	struct icp_qat_fw_comn_req_hdr *header = &req_tmpl->comn_hdr;
	void *ptr = &req_tmpl->cd_ctrl;
	struct icp_qat_fw_cipher_cd_ctrl_hdr *cipher_cd_ctrl = ptr;
	struct icp_qat_fw_auth_cd_ctrl_hdr *hash_cd_ctrl = ptr;
	struct icp_qat_fw_la_auth_req_params *auth_param =
		(struct icp_qat_fw_la_auth_req_params *)
		((char *)&req_tmpl->serv_specif_rqpars +
		sizeof(struct icp_qat_fw_la_cipher_req_params));

	/* CD setup */
	cipher->aes.cipher_config.val = QAT_AES_HW_CONFIG_DEC(alg, mode);
	memcpy(cipher->aes.key, keys->enckey, keys->enckeylen);
	hash->auth.sha.inner_setup.auth_config.config =
		ICP_QAT_HW_AUTH_CONFIG_BUILD(ICP_QAT_HW_AUTH_MODE1,
					     ctx->qat_hash_alg,
					     digestsize);
	hash->auth.sha.inner_setup.auth_counter.counter =
		cpu_to_be32(crypto_shash_blocksize(ctx->tfm.shash_tfm));

	if (qat_alg_do_precomputes(hash, ctx, keys->authkey, keys->authkeylen))
		return -EFAULT;

	/* Request setup */
	qat_alg_init_common_hdr(header);
	header->service_cmd_id = ICP_QAT_FW_LA_CMD_HASH_CIPHER;
	ICP_QAT_FW_LA_DIGEST_IN_BUFFER_SET(header->serv_specif_flags,
					   ICP_QAT_FW_LA_DIGEST_IN_BUFFER);
	ICP_QAT_FW_LA_RET_AUTH_SET(header->serv_specif_flags,
				   ICP_QAT_FW_LA_NO_RET_AUTH_RES);
	ICP_QAT_FW_LA_CMP_AUTH_SET(header->serv_specif_flags,
				   ICP_QAT_FW_LA_CMP_AUTH_RES);
	cd_pars->u.s.content_desc_addr = ctx->dec_cd_paddr;
	cd_pars->u.s.content_desc_params_sz = sizeof(struct qat_alg_cd) >> 3;

	/* Cipher CD config setup */
	cipher_cd_ctrl->cipher_key_sz = keys->enckeylen >> 3;
	cipher_cd_ctrl->cipher_state_sz = AES_BLOCK_SIZE >> 3;
	cipher_cd_ctrl->cipher_cfg_offset =
		(sizeof(struct icp_qat_hw_auth_setup) +
		 roundup(crypto_shash_digestsize(ctx->tfm.shash_tfm), 8) * 2) >> 3;
	ICP_QAT_FW_COMN_CURR_ID_SET(cipher_cd_ctrl, ICP_QAT_FW_SLICE_CIPHER);
	ICP_QAT_FW_COMN_NEXT_ID_SET(cipher_cd_ctrl, ICP_QAT_FW_SLICE_DRAM_WR);

	/* Auth CD config setup */
	hash_cd_ctrl->hash_cfg_offset = 0;
	hash_cd_ctrl->hash_flags = ICP_QAT_FW_AUTH_HDR_FLAG_NO_NESTED;
	hash_cd_ctrl->inner_res_sz = digestsize;
	hash_cd_ctrl->final_sz = digestsize;

	switch (ctx->qat_hash_alg) {
	case ICP_QAT_HW_AUTH_ALGO_SHA1:
		hash_cd_ctrl->inner_state1_sz =
			round_up(ICP_QAT_HW_SHA1_STATE1_SZ, 8);
		hash_cd_ctrl->inner_state2_sz =
			round_up(ICP_QAT_HW_SHA1_STATE2_SZ, 8);
		break;
	case ICP_QAT_HW_AUTH_ALGO_SHA256:
		hash_cd_ctrl->inner_state1_sz = ICP_QAT_HW_SHA256_STATE1_SZ;
		hash_cd_ctrl->inner_state2_sz = ICP_QAT_HW_SHA256_STATE2_SZ;
		break;
	case ICP_QAT_HW_AUTH_ALGO_SHA512:
		hash_cd_ctrl->inner_state1_sz = ICP_QAT_HW_SHA512_STATE1_SZ;
		hash_cd_ctrl->inner_state2_sz = ICP_QAT_HW_SHA512_STATE2_SZ;
		break;
	default:
		break;
	}

	hash_cd_ctrl->inner_state2_offset = hash_cd_ctrl->hash_cfg_offset +
			((sizeof(struct icp_qat_hw_auth_setup) +
			 round_up(hash_cd_ctrl->inner_state1_sz, 8)) >> 3);
	auth_param->auth_res_sz = digestsize;
	ICP_QAT_FW_COMN_CURR_ID_SET(hash_cd_ctrl, ICP_QAT_FW_SLICE_AUTH);
	ICP_QAT_FW_COMN_NEXT_ID_SET(hash_cd_ctrl, ICP_QAT_FW_SLICE_CIPHER);
	return 0;
}

static int qat_alg_aead_init_gcm_enc_session(struct crypto_aead *aead_tfm,
					     int alg,
					     const u8 *key,
					     unsigned int keylen,
					     int mode)
{
	struct qat_alg_aead_ctx *ctx = crypto_aead_ctx(aead_tfm);
	struct qat_enc *enc_ctx = &ctx->enc_cd->qat_enc_cd;
	struct icp_qat_hw_cipher_algo_blk *cipher = &enc_ctx->cipher;
	struct icp_qat_hw_auth_algo_blk *hash =
		(struct icp_qat_hw_auth_algo_blk *)(((uint8_t *)enc_ctx) +
		sizeof(struct icp_qat_hw_cipher_config) + keylen);
	struct icp_qat_fw_la_bulk_req *req_tmpl = &ctx->enc_fw_req;
	struct icp_qat_fw_comn_req_hdr_cd_pars *cd_pars = &req_tmpl->cd_pars;
	struct icp_qat_fw_comn_req_hdr *header = &req_tmpl->comn_hdr;
	void *ptr = &req_tmpl->cd_ctrl;
	struct icp_qat_fw_cipher_cd_ctrl_hdr *cipher_cd_ctrl = ptr;
	struct icp_qat_fw_auth_cd_ctrl_hdr *hash_cd_ctrl = ptr;
	unsigned int digestsize = crypto_aead_authsize(aead_tfm);

	/* CD setup */
	cipher->aes.cipher_config.val = QAT_AES_HW_CONFIG_ENC(alg, mode);
	memcpy(cipher->aes.key, key, keylen);

	hash->auth.ghash.inner_setup.auth_config.config =
		ICP_QAT_HW_AUTH_CONFIG_BUILD(ICP_QAT_HW_AUTH_MODE1,
					     ctx->qat_hash_alg,
					     0);

	if (qat_alg_do_gcm_precomputes(key, keylen, hash->auth.ghash.inner_state2))
		return -EFAULT;

	/* Request setup */
	qat_alg_init_common_hdr(header);
	ICP_QAT_FW_LA_PROTO_SET(header->serv_specif_flags,
				ICP_QAT_FW_LA_GCM_PROTO);
	header->service_cmd_id = ICP_QAT_FW_LA_CMD_CIPHER_HASH;
	ICP_QAT_FW_LA_DIGEST_IN_BUFFER_SET(header->serv_specif_flags,
					   ICP_QAT_FW_LA_DIGEST_IN_BUFFER);
	ICP_QAT_FW_LA_RET_AUTH_SET(header->serv_specif_flags,
				   ICP_QAT_FW_LA_RET_AUTH_RES);
	ICP_QAT_FW_LA_CMP_AUTH_SET(header->serv_specif_flags,
				   ICP_QAT_FW_LA_NO_CMP_AUTH_RES);
	ICP_QAT_FW_LA_GCM_IV_LEN_FLAG_SET(header->serv_specif_flags,
					  ICP_QAT_FW_LA_GCM_IV_LEN_12_OCTETS);
	ICP_QAT_FW_LA_CIPH_AUTH_CFG_OFFSET_FLAG_SET
		(header->serv_specif_flags,
		 ICP_QAT_FW_CIPH_AUTH_CFG_OFFSET_IN_CD_SETUP);
	cd_pars->u.s.content_desc_addr = ctx->enc_cd_paddr;
	cd_pars->u.s.content_desc_params_sz =
		(sizeof(struct icp_qat_hw_cipher_config)
		 + keylen + sizeof(struct icp_qat_hw_auth_ghash)) >> 3;

	/* Cipher CD config setup */
	cipher_cd_ctrl->cipher_key_sz = keylen >> 3;
	cipher_cd_ctrl->cipher_state_sz = AES_BLOCK_SIZE >> 3;
	cipher_cd_ctrl->cipher_cfg_offset = 0;
	ICP_QAT_FW_COMN_CURR_ID_SET(cipher_cd_ctrl, ICP_QAT_FW_SLICE_CIPHER);
	ICP_QAT_FW_COMN_NEXT_ID_SET(cipher_cd_ctrl, ICP_QAT_FW_SLICE_AUTH);
	/* Auth CD config setup */
	hash_cd_ctrl->hash_cfg_offset = ((char *)hash - (char *)cipher) >> 3;
	hash_cd_ctrl->hash_flags = ICP_QAT_FW_AUTH_HDR_FLAG_NO_NESTED;
	hash_cd_ctrl->inner_res_sz = GHASH_DIGEST_SIZE;
	hash_cd_ctrl->final_sz = digestsize;

	hash_cd_ctrl->inner_state1_sz = ICP_QAT_HW_GALOIS_128_STATE1_SZ;
	hash_cd_ctrl->inner_state2_sz = ICP_QAT_HW_GALOIS_H_SZ +
				ICP_QAT_HW_GALOIS_LEN_A_SZ + ICP_QAT_HW_GALOIS_E_CTR0_SZ;

	hash_cd_ctrl->inner_state2_offset = hash_cd_ctrl->hash_cfg_offset +
			((sizeof(struct icp_qat_hw_auth_setup) +
			  hash_cd_ctrl->inner_state1_sz) >> 3);

	ICP_QAT_FW_COMN_CURR_ID_SET(hash_cd_ctrl, ICP_QAT_FW_SLICE_AUTH);
	ICP_QAT_FW_COMN_NEXT_ID_SET(hash_cd_ctrl, ICP_QAT_FW_SLICE_DRAM_WR);
	return 0;
}

static int qat_alg_aead_init_gcm_dec_session(struct crypto_aead *aead_tfm,
					     int alg,
					     const u8 *key,
					     unsigned int keylen,
					     int mode)
{
	struct qat_alg_aead_ctx *ctx = crypto_aead_ctx(aead_tfm);
	unsigned int digestsize = crypto_aead_authsize(aead_tfm);
	struct qat_dec *dec_ctx = &ctx->dec_cd->qat_dec_cd;
	struct icp_qat_hw_auth_algo_blk *hash = &dec_ctx->hash;
	struct icp_qat_hw_cipher_algo_blk *cipher =
		(struct icp_qat_hw_cipher_algo_blk *)((uint8_t *)dec_ctx +
		sizeof(struct icp_qat_hw_auth_ghash));
	struct icp_qat_fw_la_bulk_req *req_tmpl = &ctx->dec_fw_req;
	struct icp_qat_fw_comn_req_hdr_cd_pars *cd_pars = &req_tmpl->cd_pars;
	struct icp_qat_fw_comn_req_hdr *header = &req_tmpl->comn_hdr;
	void *ptr = &req_tmpl->cd_ctrl;
	struct icp_qat_fw_cipher_cd_ctrl_hdr *cipher_cd_ctrl = ptr;
	struct icp_qat_fw_auth_cd_ctrl_hdr *hash_cd_ctrl = ptr;

	/* CD setup */
	cipher->aes.cipher_config.val = QAT_AES_HW_CONFIG_ENC(alg, mode);
	memcpy(cipher->aes.key, key, keylen);

	hash->auth.ghash.inner_setup.auth_config.config =
		ICP_QAT_HW_AUTH_CONFIG_BUILD(ICP_QAT_HW_AUTH_MODE1,
					     ctx->qat_hash_alg,
					     digestsize);

	if (qat_alg_do_gcm_precomputes(key, keylen, hash->auth.ghash.inner_state2))
		return -EFAULT;

	/* Request setup */
	qat_alg_init_common_hdr(header);
	ICP_QAT_FW_LA_PROTO_SET(header->serv_specif_flags,
				ICP_QAT_FW_LA_GCM_PROTO);
	header->service_cmd_id = ICP_QAT_FW_LA_CMD_HASH_CIPHER;
	ICP_QAT_FW_LA_DIGEST_IN_BUFFER_SET(header->serv_specif_flags,
					   ICP_QAT_FW_LA_DIGEST_IN_BUFFER);
	ICP_QAT_FW_LA_RET_AUTH_SET(header->serv_specif_flags,
				   ICP_QAT_FW_LA_NO_RET_AUTH_RES);
	ICP_QAT_FW_LA_CMP_AUTH_SET(header->serv_specif_flags,
				   ICP_QAT_FW_LA_CMP_AUTH_RES);
	ICP_QAT_FW_LA_GCM_IV_LEN_FLAG_SET(header->serv_specif_flags,
					  ICP_QAT_FW_LA_GCM_IV_LEN_12_OCTETS);
	ICP_QAT_FW_LA_CIPH_AUTH_CFG_OFFSET_FLAG_SET
		(header->serv_specif_flags,
		 ICP_QAT_FW_CIPH_AUTH_CFG_OFFSET_IN_CD_SETUP);
	cd_pars->u.s.content_desc_addr = ctx->dec_cd_paddr;
	cd_pars->u.s.content_desc_params_sz =
		(sizeof(struct icp_qat_hw_auth_ghash) +
		 sizeof(struct icp_qat_hw_cipher_config) + keylen) >> 3;

	/* Cipher CD config setup */
	cipher_cd_ctrl->cipher_key_sz = keylen >> 3;
	cipher_cd_ctrl->cipher_state_sz = AES_BLOCK_SIZE >> 3;
	cipher_cd_ctrl->cipher_cfg_offset =
		((char *)cipher - (char *)hash) >> 3;
	ICP_QAT_FW_COMN_CURR_ID_SET(cipher_cd_ctrl, ICP_QAT_FW_SLICE_CIPHER);
	ICP_QAT_FW_COMN_NEXT_ID_SET(cipher_cd_ctrl, ICP_QAT_FW_SLICE_DRAM_WR);

	/* Auth CD config setup */
	hash_cd_ctrl->hash_cfg_offset = 0;
	hash_cd_ctrl->hash_flags = ICP_QAT_FW_AUTH_HDR_FLAG_NO_NESTED;
	hash_cd_ctrl->inner_res_sz = GHASH_DIGEST_SIZE;
	hash_cd_ctrl->final_sz = digestsize;

	hash_cd_ctrl->inner_state1_sz = ICP_QAT_HW_GALOIS_128_STATE1_SZ;
	hash_cd_ctrl->inner_state2_sz = ICP_QAT_HW_GALOIS_H_SZ +
				ICP_QAT_HW_GALOIS_LEN_A_SZ + ICP_QAT_HW_GALOIS_E_CTR0_SZ;

	hash_cd_ctrl->inner_state2_offset = hash_cd_ctrl->hash_cfg_offset +
			((sizeof(struct icp_qat_hw_auth_setup) +
			 hash_cd_ctrl->inner_state1_sz) >> 3);

	ICP_QAT_FW_COMN_CURR_ID_SET(hash_cd_ctrl, ICP_QAT_FW_SLICE_AUTH);
	ICP_QAT_FW_COMN_NEXT_ID_SET(hash_cd_ctrl, ICP_QAT_FW_SLICE_CIPHER);
	return 0;
}

static void qat_alg_skcipher_init_com(struct qat_alg_skcipher_ctx *ctx,
				      struct icp_qat_fw_la_bulk_req *req,
				      struct icp_qat_hw_cipher_algo_blk *cd,
				      const u8 *key, unsigned int keylen)
{
	struct icp_qat_fw_comn_req_hdr_cd_pars *cd_pars = &req->cd_pars;
	struct icp_qat_fw_comn_req_hdr *header = &req->comn_hdr;
	struct icp_qat_fw_cipher_cd_ctrl_hdr *cd_ctrl = (void *)&req->cd_ctrl;

	memcpy(cd->aes.key, key, keylen);
	qat_alg_init_common_hdr(header);
	header->service_cmd_id = ICP_QAT_FW_LA_CMD_CIPHER;
	cd_pars->u.s.content_desc_params_sz =
				sizeof(struct icp_qat_hw_cipher_algo_blk) >> 3;
	/* Cipher CD config setup */
	cd_ctrl->cipher_key_sz = keylen >> 3;
	cd_ctrl->cipher_state_sz = AES_BLOCK_SIZE >> 3;
	cd_ctrl->cipher_cfg_offset = 0;
	ICP_QAT_FW_COMN_CURR_ID_SET(cd_ctrl, ICP_QAT_FW_SLICE_CIPHER);
	ICP_QAT_FW_COMN_NEXT_ID_SET(cd_ctrl, ICP_QAT_FW_SLICE_DRAM_WR);
}

static void qat_alg_skcipher_init_enc(struct qat_alg_skcipher_ctx *ctx,
				      int alg, const uint8_t *key,
				      unsigned int keylen, int mode)
{
	struct icp_qat_hw_cipher_algo_blk *enc_cd = ctx->enc_cd;
	struct icp_qat_fw_la_bulk_req *req = &ctx->enc_fw_req;
	struct icp_qat_fw_comn_req_hdr_cd_pars *cd_pars = &req->cd_pars;

	qat_alg_skcipher_init_com(ctx, req, enc_cd, key, keylen);
	cd_pars->u.s.content_desc_addr = ctx->enc_cd_paddr;
	enc_cd->aes.cipher_config.val = QAT_AES_HW_CONFIG_ENC(alg, mode);
}

static void qat_alg_skcipher_init_dec(struct qat_alg_skcipher_ctx *ctx,
				      int alg, const uint8_t *key,
				      unsigned int keylen, int mode)
{
	struct icp_qat_hw_cipher_algo_blk *dec_cd = ctx->dec_cd;
	struct icp_qat_fw_la_bulk_req *req = &ctx->dec_fw_req;
	struct icp_qat_fw_comn_req_hdr_cd_pars *cd_pars = &req->cd_pars;

	qat_alg_skcipher_init_com(ctx, req, dec_cd, key, keylen);
	cd_pars->u.s.content_desc_addr = ctx->dec_cd_paddr;

	if (mode != ICP_QAT_HW_CIPHER_CTR_MODE)
		dec_cd->aes.cipher_config.val =
					QAT_AES_HW_CONFIG_DEC(alg, mode);
	else
		dec_cd->aes.cipher_config.val =
					QAT_AES_HW_CONFIG_ENC(alg, mode);
}

static int qat_alg_validate_key(int key_len, int *alg, int mode)
{
	if (mode != ICP_QAT_HW_CIPHER_XTS_MODE) {
		switch (key_len) {
		case AES_KEYSIZE_128:
			*alg = ICP_QAT_HW_CIPHER_ALGO_AES128;
			break;
		case AES_KEYSIZE_192:
			*alg = ICP_QAT_HW_CIPHER_ALGO_AES192;
			break;
		case AES_KEYSIZE_256:
			*alg = ICP_QAT_HW_CIPHER_ALGO_AES256;
			break;
		default:
			return -EINVAL;
		}
	} else {
		switch (key_len) {
		case AES_KEYSIZE_128 << 1:
			*alg = ICP_QAT_HW_CIPHER_ALGO_AES128;
			break;
		case AES_KEYSIZE_256 << 1:
			*alg = ICP_QAT_HW_CIPHER_ALGO_AES256;
			break;
		default:
			return -EINVAL;
		}
	}
	return 0;
}

static int qat_alg_aead_init_sessions(struct crypto_aead *tfm,
				      const u8 *key,
				      unsigned int keylen,
				      int mode)
{
	struct crypto_authenc_keys keys;
	int alg;

	if (mode == ICP_QAT_HW_CIPHER_CTR_MODE) {
		if (qat_alg_validate_key(keylen, &alg, mode))
			goto bad_key;
		if (qat_alg_aead_init_gcm_enc_session(tfm, alg, key, keylen, mode))
			goto error;
		if (qat_alg_aead_init_gcm_dec_session(tfm, alg, key, keylen, mode))
			goto error;
	} else if (mode == ICP_QAT_HW_CIPHER_CBC_MODE) {
		if (crypto_authenc_extractkeys(&keys, key, keylen))
			goto bad_key;
		if (qat_alg_validate_key(keys.enckeylen, &alg, mode))
			goto bad_key;
		if (qat_alg_aead_init_enc_session(tfm, alg, &keys, mode))
			goto error;
		if (qat_alg_aead_init_dec_session(tfm, alg, &keys, mode))
			goto error;
	} else {
		goto error;
	}
	return 0;
bad_key:
	if (ICP_QAT_HW_CIPHER_CBC_MODE)
		memzero_explicit(&keys, sizeof(keys));
	return -EINVAL;
error:
	return -EFAULT;
}

static int qat_alg_skcipher_init_sessions(struct qat_alg_skcipher_ctx *ctx,
					  const u8 *key,
					  unsigned int keylen,
					  int mode)
{
	int alg;

	if (qat_alg_validate_key(keylen, &alg, mode))
		return -EINVAL;

	qat_alg_skcipher_init_enc(ctx, alg, key, keylen, mode);
	qat_alg_skcipher_init_dec(ctx, alg, key, keylen, mode);
	return 0;
}

static int qat_alg_aead_rekey(struct crypto_aead *tfm,
			      const u8 *key,
			      unsigned int keylen,
			      int mode)
{
	struct qat_alg_aead_ctx *ctx = crypto_aead_ctx(tfm);

	memset(ctx->enc_cd, 0, sizeof(*ctx->enc_cd));
	memset(ctx->dec_cd, 0, sizeof(*ctx->dec_cd));
	memset(&ctx->enc_fw_req, 0, sizeof(ctx->enc_fw_req));
	memset(&ctx->dec_fw_req, 0, sizeof(ctx->dec_fw_req));

	return qat_alg_aead_init_sessions(tfm, key, keylen, mode);
}

static int qat_alg_aead_newkey(struct crypto_aead *tfm,
			       const u8 *key,
			       unsigned int keylen,
			       int mode)
{
	struct qat_alg_aead_ctx *ctx = crypto_aead_ctx(tfm);
	struct qat_crypto_instance *inst = NULL;
	int node = numa_node_id();
	struct device *dev;
	int ret;

	inst = qat_crypto_get_instance_node(node);
	if (!inst)
		return -EINVAL;
	dev = &GET_DEV(inst->accel_dev);
	ctx->inst = inst;
	ctx->enc_cd = dma_alloc_coherent(dev, sizeof(*ctx->enc_cd),
					 &ctx->enc_cd_paddr,
					 GFP_ATOMIC);
	if (!ctx->enc_cd) {
		ret = -ENOMEM;
		goto out_free_inst;
	}
	ctx->dec_cd = dma_alloc_coherent(dev, sizeof(*ctx->dec_cd),
					 &ctx->dec_cd_paddr,
					 GFP_ATOMIC);
	if (!ctx->dec_cd) {
		ret = -ENOMEM;
		goto out_free_enc;
	}

	ret = qat_alg_aead_init_sessions(tfm, key, keylen, mode);
	if (ret)
		goto out_free_all;

	return 0;

out_free_all:
	memzero_explicit(ctx->dec_cd, sizeof(struct qat_alg_cd));
	dma_free_coherent(dev, sizeof(struct qat_alg_cd),
			  ctx->dec_cd, ctx->dec_cd_paddr);
	ctx->dec_cd = NULL;
out_free_enc:
	memzero_explicit(ctx->enc_cd, sizeof(struct qat_alg_cd));
	dma_free_coherent(dev, sizeof(struct qat_alg_cd),
			  ctx->enc_cd, ctx->enc_cd_paddr);
	ctx->enc_cd = NULL;
out_free_inst:
	ctx->inst = NULL;
	qat_crypto_put_instance(inst);
	return ret;
}

static int qat_alg_aead_setkey(struct crypto_aead *tfm,
			       const u8 *key,
			       unsigned int keylen,
			       int mode)
{
	struct qat_alg_aead_ctx *ctx = crypto_aead_ctx(tfm);

	if (ctx->enc_cd)
		return qat_alg_aead_rekey(tfm, key, keylen, mode);
	else
		return qat_alg_aead_newkey(tfm, key, keylen, mode);
}

static int qat_alg_aead_hmac_setkey(struct crypto_aead *tfm,
				    const u8 *key,
				    unsigned int keylen)
{
	return qat_alg_aead_setkey(tfm, key, keylen,
				   ICP_QAT_HW_CIPHER_CBC_MODE);
}

static int qat_alg_aead_gcm_setkey(struct crypto_aead *tfm,
				   const u8 *key,
				   unsigned int keylen)
{
	return qat_alg_aead_setkey(tfm, key, keylen,
				   ICP_QAT_HW_CIPHER_CTR_MODE);
}

static void qat_alg_free_bufl(struct qat_crypto_instance *inst,
			      struct qat_crypto_request *qat_req)
{
	struct device *dev = &GET_DEV(inst->accel_dev);
	struct qat_alg_buf_list *bl = qat_req->buf.bl;
	struct qat_alg_buf_list *blout = qat_req->buf.blout;
	dma_addr_t blp = qat_req->buf.blp;
	dma_addr_t blpout = qat_req->buf.bloutp;
	size_t sz = qat_req->buf.sz;
	size_t sz_out = qat_req->buf.sz_out;
	int i;

	for (i = 0; i < bl->num_bufs; i++) {
		if (bl->bufers[i].len != 0)
			dma_unmap_single(dev, bl->bufers[i].addr,
					 bl->bufers[i].len, DMA_BIDIRECTIONAL);
	}


	dma_unmap_single(dev, blp, sz, DMA_TO_DEVICE);
	if (!qat_req->buf.sgl_src_valid)
		kfree(bl);
	if (blp != blpout) {
		/* If out of place operation dma unmap only data */
		int bufless = blout->num_bufs - blout->num_mapped_bufs;

		for (i = bufless; i < blout->num_bufs; i++) {
			dma_unmap_single(dev, blout->bufers[i].addr,
					 blout->bufers[i].len,
					 DMA_BIDIRECTIONAL);
		}
		dma_unmap_single(dev, blpout, sz_out, DMA_TO_DEVICE);
		if (!qat_req->buf.sgl_dst_valid)
			kfree(blout);
	}
}

static int qat_alg_sgl_to_bufl(struct qat_crypto_instance *inst,
			       struct scatterlist *sgl,
			       struct scatterlist *sglout,
			       struct qat_crypto_request *qat_req,
			       gfp_t flags)
{
	struct device *dev = &GET_DEV(inst->accel_dev);
	int i = 0, sg_nctr = 0, n = sg_nents(sgl);
	struct qat_alg_buf_list *bufl = NULL, *buflout = NULL;
	dma_addr_t blp = 0, bloutp = 0;
	struct scatterlist *sg = NULL;
	size_t sz_out = 0, sz = 0;
	int node = dev_to_node(&GET_DEV(inst->accel_dev));

	if (unlikely(!n))
		return -EINVAL;

	qat_req->buf.sgl_src_valid = false;
	qat_req->buf.sgl_dst_valid = false;

	if (n > QAT_MAX_PRE_ALLOCATED_BUFFS) {
		/* Assumption: For dm-crypt, max SGLs can be 4.
		 * If SGLs are more than 4, memory for bufflists is done
		 * at run time.
		 */
		sz = sizeof(struct qat_alg_buf_list) +
			(n * sizeof(struct qat_alg_buf));

		bufl = kzalloc_node(sz, flags, node);
		if (unlikely(!bufl))
			return -ENOMEM;
	} else {
		bufl = &qat_req->buf.sgl_src.sgl_hdr;
		sz = sizeof(struct qat_alg_fixed_buf_list);
		memset(bufl, 0, sizeof(struct qat_alg_buf_list));
		qat_req->buf.sgl_src_valid = true;
	}

	blp = dma_map_single(dev, bufl, sz, DMA_TO_DEVICE);
	if (unlikely(dma_mapping_error(dev, blp)))
		goto err_in;

	for_each_sg(sgl, sg, n, i) {
		int y = sg_nctr;

		if (!sg)
			continue;

		if (!sg->length)
			continue;

		bufl->bufers[y].addr = dma_map_single(dev, sg_virt(sg),
						      sg->length,
						      DMA_BIDIRECTIONAL);
		bufl->bufers[y].len = sg->length;
		if (unlikely(dma_mapping_error(dev, bufl->bufers[y].addr)))
			goto err_in;
		sg_nctr++;
	}
	if (sg_nctr == 0)
		sg_nctr = 1;

	bufl->num_bufs = sg_nctr;
	qat_req->buf.bl = bufl;
	qat_req->buf.blp = blp;
	qat_req->buf.sz = sz;
	/* Handle out of place operation */
	if (sgl != sglout) {
		struct qat_alg_buf *bufers;

		sg_nctr = 0;
		n = sg_nents(sglout);
		if (n > QAT_MAX_PRE_ALLOCATED_BUFFS) {
			/* Assumption: For dm-crypt, max SGLs can be 4.
			 * If SGLs are more than 4, memory for bufflists is done
			 * at run time.
			 */
			sz_out = sizeof(struct qat_alg_buf_list) +
					(n * sizeof(struct qat_alg_buf));

			buflout = kzalloc_node(sz_out, flags, node);
			if (unlikely(!buflout))
				return -ENOMEM;
		} else {
			buflout = &qat_req->buf.sgl_dst.sgl_hdr;
			sz_out = sizeof(struct qat_alg_fixed_buf_list);
			memset(buflout, 0, sizeof(struct qat_alg_buf_list));
			qat_req->buf.sgl_dst_valid = true;
		}

		bloutp = dma_map_single(dev, buflout, sz_out, DMA_TO_DEVICE);
		if (unlikely(dma_mapping_error(dev, bloutp)))
			goto err_out;
		bufers = buflout->bufers;
		for_each_sg(sglout, sg, n, i) {
			int y = sg_nctr;

			if (!sg)
				continue;

			if (!sg->length)
				continue;
			bufers[y].addr = dma_map_single(dev, sg_virt(sg),
							sg->length,
							DMA_BIDIRECTIONAL);
			bufers[y].len = sg->length;
			if (unlikely(dma_mapping_error(dev, bufers[y].addr)))
				goto err_out;

			sg_nctr++;
		}
		buflout->num_bufs = sg_nctr;
		buflout->num_mapped_bufs = sg_nctr;
		qat_req->buf.blout = buflout;
		qat_req->buf.bloutp = bloutp;
		qat_req->buf.sz_out = sz_out;
	} else {
		/* Otherwise set the src and dst to the same address */
		qat_req->buf.bloutp = qat_req->buf.blp;
		qat_req->buf.sz_out = 0;
	}
	return 0;
err_out:
	if (sgl != sglout && buflout) {
		n = sg_nents(sglout);
		for (i = 0; i < n; i++)
			if (!dma_mapping_error(dev, buflout->bufers[i].addr))
				dma_unmap_single(dev, buflout->bufers[i].addr,
						 buflout->bufers[i].len,
						 DMA_BIDIRECTIONAL);

		if (!dma_mapping_error(dev, bloutp))
			dma_unmap_single(dev, bloutp, sz_out, DMA_TO_DEVICE);

		if (!qat_req->buf.sgl_dst_valid)
			kfree(buflout);
	}

err_in:
	n = sg_nents(sgl);
	for (i = 0; i < n; i++)
		if (!dma_mapping_error(dev, bufl->bufers[i].addr))
			dma_unmap_single(dev, bufl->bufers[i].addr,
					 bufl->bufers[i].len,
					 DMA_BIDIRECTIONAL);

	if (!dma_mapping_error(dev, blp))
		dma_unmap_single(dev, blp, sz, DMA_TO_DEVICE);

	if (!qat_req->buf.sgl_src_valid)
		kfree(bufl);

	dev_err(dev, "Failed to map buf for dma\n");
	return -ENOMEM;
}

static void qat_aead_alg_callback(struct icp_qat_fw_la_resp *qat_resp,
				  struct qat_crypto_request *qat_req)
{
	struct qat_alg_aead_ctx *ctx = qat_req->aead_ctx;
	struct qat_crypto_instance *inst = ctx->inst;
	struct aead_request *areq = qat_req->aead_req;
	u8 stat_filed = qat_resp->comn_resp.comn_status;
	struct device *dev = &GET_DEV(inst->accel_dev);
	int res = 0, qat_res = ICP_QAT_FW_COMN_RESP_CRYPTO_STAT_GET(stat_filed);

	if (qat_req->buf.aad_buf.virt_addr) {
		dma_free_coherent(dev, qat_req->buf.aad_buf.aad_sz,
				  qat_req->buf.aad_buf.virt_addr,
				  qat_req->buf.aad_buf.phys_addr);
		qat_req->buf.aad_buf.virt_addr = NULL;
	}

	qat_alg_free_bufl(inst, qat_req);
	if (unlikely(qat_res != ICP_QAT_FW_COMN_STATUS_FLAG_OK))
		res = -EBADMSG;
	aead_request_complete(areq, res);
}

static void qat_alg_update_iv_ctr_mode(struct qat_crypto_request *qat_req)
{
	struct skcipher_request *sreq = qat_req->skcipher_req;
	u64 iv_lo_prev;
	u64 iv_lo;
	u64 iv_hi;

	memcpy(qat_req->iv, sreq->iv, AES_BLOCK_SIZE);

	iv_lo = be64_to_cpu(qat_req->iv_lo);
	iv_hi = be64_to_cpu(qat_req->iv_hi);

	iv_lo_prev = iv_lo;
	iv_lo += DIV_ROUND_UP(sreq->cryptlen, AES_BLOCK_SIZE);
	if (iv_lo < iv_lo_prev)
		iv_hi++;

	qat_req->iv_lo = cpu_to_be64(iv_lo);
	qat_req->iv_hi = cpu_to_be64(iv_hi);
}

static void qat_alg_update_iv_cbc_mode(struct qat_crypto_request *qat_req)
{
	struct skcipher_request *sreq = qat_req->skcipher_req;
	int offset = sreq->cryptlen - AES_BLOCK_SIZE;
	struct scatterlist *sgl;

	if (qat_req->encryption)
		sgl = sreq->dst;
	else
		sgl = sreq->src;

	scatterwalk_map_and_copy(qat_req->iv, sgl, offset, AES_BLOCK_SIZE, 0);
}

static void qat_alg_update_iv(struct qat_crypto_request *qat_req)
{
	struct qat_alg_skcipher_ctx *ctx = qat_req->skcipher_ctx;
	struct device *dev = &GET_DEV(ctx->inst->accel_dev);

	switch (ctx->mode) {
	case ICP_QAT_HW_CIPHER_CTR_MODE:
		qat_alg_update_iv_ctr_mode(qat_req);
		break;
	case ICP_QAT_HW_CIPHER_CBC_MODE:
		qat_alg_update_iv_cbc_mode(qat_req);
		break;
	case ICP_QAT_HW_CIPHER_XTS_MODE:
		break;
	default:
		dev_warn(dev, "Unsupported IV update for cipher mode %d\n",
			 ctx->mode);
	}
}

static void qat_skcipher_alg_callback(struct icp_qat_fw_la_resp *qat_resp,
				      struct qat_crypto_request *qat_req)
{
	struct qat_alg_skcipher_ctx *ctx = qat_req->skcipher_ctx;
	struct qat_crypto_instance *inst = ctx->inst;
	struct skcipher_request *sreq = qat_req->skcipher_req;
	uint8_t stat_filed = qat_resp->comn_resp.comn_status;
	int res = 0, qat_res = ICP_QAT_FW_COMN_RESP_CRYPTO_STAT_GET(stat_filed);

	qat_alg_free_bufl(inst, qat_req);
	if (unlikely(qat_res != ICP_QAT_FW_COMN_STATUS_FLAG_OK))
		res = -EINVAL;

	if (qat_req->encryption)
		qat_alg_update_iv(qat_req);

	memcpy(sreq->iv, qat_req->iv, AES_BLOCK_SIZE);

	skcipher_request_complete(sreq, res);
}

void qat_alg_callback(void *resp)
{
	struct icp_qat_fw_la_resp *qat_resp = resp;
	struct qat_crypto_request *qat_req =
				(void *)(__force long)qat_resp->opaque_data;
	struct qat_instance_backlog *backlog = qat_req->alg_req.backlog;

	qat_req->cb(qat_resp, qat_req);
	qat_alg_send_backlog(backlog);
}

static int qat_alg_send_sym_message(struct qat_crypto_request *qat_req,
				    struct qat_crypto_instance *inst,
				    struct crypto_async_request *base)
{
	struct qat_alg_req *alg_req = &qat_req->alg_req;

	alg_req->fw_req = (u32 *)&qat_req->req;
	alg_req->tx_ring = inst->sym_tx;
	alg_req->base = base;
	alg_req->backlog = &inst->backlog;

	return qat_alg_send_message(alg_req);
}

static int qat_alg_aead_dec(struct aead_request *areq)
{
	struct crypto_aead *aead_tfm = crypto_aead_reqtfm(areq);
	struct crypto_tfm *tfm = crypto_aead_tfm(aead_tfm);
	struct qat_alg_aead_ctx *ctx = crypto_tfm_ctx(tfm);
	struct qat_crypto_request *qat_req = aead_request_ctx(areq);
	struct icp_qat_fw_la_cipher_req_params *cipher_param;
	struct icp_qat_fw_la_auth_req_params *auth_param;
	struct icp_qat_fw_la_bulk_req *msg;
	int digst_size = crypto_aead_authsize(aead_tfm);
	gfp_t flags = qat_algs_alloc_flags(&areq->base);
	u32 cipher_length = areq->cryptlen - digst_size;
	int ret;

	if (!digst_size || !areq->cryptlen || !cipher_length)
		return -EINVAL;

	if (cipher_length % AES_BLOCK_SIZE != 0)
		return -EINVAL;

	ret = qat_alg_sgl_to_bufl(ctx->inst, areq->src, areq->dst, qat_req, flags);
	if (unlikely(ret))
		return ret;

	msg = &qat_req->req;
	*msg = ctx->dec_fw_req;
	qat_req->aead_ctx = ctx;
	qat_req->aead_req = areq;
	qat_req->cb = qat_aead_alg_callback;
	qat_req->buf.aad_buf.virt_addr = NULL;
	qat_req->req.comn_mid.opaque_data = (uint64_t)(__force long)qat_req;
	qat_req->req.comn_mid.src_data_addr = qat_req->buf.blp;
	qat_req->req.comn_mid.dest_data_addr = qat_req->buf.bloutp;
	cipher_param = (void *)&qat_req->req.serv_specif_rqpars;
	cipher_param->cipher_length = cipher_length;
	cipher_param->cipher_offset = areq->assoclen;
	memcpy(cipher_param->u.cipher_IV_array, areq->iv, AES_BLOCK_SIZE);
	auth_param = (void *)((uint8_t *)cipher_param + sizeof(*cipher_param));
	auth_param->auth_off = 0;
	auth_param->auth_len = areq->assoclen + cipher_param->cipher_length;

	ret = qat_alg_send_sym_message(qat_req, ctx->inst, &areq->base);
	if (ret == -ENOSPC)
		qat_alg_free_bufl(ctx->inst, qat_req);

	return ret;
}

static int qat_alg_aead_enc(struct aead_request *areq)
{
	struct crypto_aead *aead_tfm = crypto_aead_reqtfm(areq);
	struct crypto_tfm *tfm = crypto_aead_tfm(aead_tfm);
	struct qat_alg_aead_ctx *ctx = crypto_tfm_ctx(tfm);
	struct qat_crypto_request *qat_req = aead_request_ctx(areq);
	struct icp_qat_fw_la_cipher_req_params *cipher_param;
	struct icp_qat_fw_la_auth_req_params *auth_param;
	gfp_t flags = qat_algs_alloc_flags(&areq->base);
	struct icp_qat_fw_la_bulk_req *msg;
	uint8_t *iv = areq->iv;
	int ret;

	if (!areq->cryptlen)
		return -EINVAL;

	if (areq->cryptlen % AES_BLOCK_SIZE != 0)
		return -EINVAL;

	ret = qat_alg_sgl_to_bufl(ctx->inst, areq->src, areq->dst, qat_req, flags);
	if (unlikely(ret))
		return ret;

	msg = &qat_req->req;
	*msg = ctx->enc_fw_req;
	qat_req->aead_ctx = ctx;
	qat_req->aead_req = areq;
	qat_req->cb = qat_aead_alg_callback;
	qat_req->buf.aad_buf.virt_addr = NULL;
	qat_req->req.comn_mid.opaque_data = (uint64_t)(__force long)qat_req;
	qat_req->req.comn_mid.src_data_addr = qat_req->buf.blp;
	qat_req->req.comn_mid.dest_data_addr = qat_req->buf.bloutp;
	cipher_param = (void *)&qat_req->req.serv_specif_rqpars;
	auth_param = (void *)((uint8_t *)cipher_param + sizeof(*cipher_param));

	memcpy(cipher_param->u.cipher_IV_array, iv, AES_BLOCK_SIZE);
	cipher_param->cipher_length = areq->cryptlen;
	cipher_param->cipher_offset = areq->assoclen;

	auth_param->auth_off = 0;
	auth_param->auth_len = areq->assoclen + areq->cryptlen;

	ret = qat_alg_send_sym_message(qat_req, ctx->inst, &areq->base);
	if (ret == -ENOSPC)
		qat_alg_free_bufl(ctx->inst, qat_req);
	return ret;
}

static int qat_alg_aead_gcm_dec(struct aead_request *areq)
{
	struct crypto_aead *aead_tfm = crypto_aead_reqtfm(areq);
	int digestsize = crypto_aead_authsize(aead_tfm);
	struct crypto_tfm *tfm = crypto_aead_tfm(aead_tfm);
	struct qat_alg_aead_ctx *ctx = crypto_tfm_ctx(tfm);
	struct qat_dec *dec_ctx = &ctx->dec_cd->qat_dec_cd;
	struct qat_crypto_request *qat_req = aead_request_ctx(areq);
	struct icp_qat_fw_la_cipher_req_params *cipher_param;
	struct icp_qat_fw_la_auth_req_params *auth_param;
	gfp_t flags = qat_algs_alloc_flags(&areq->base);
	struct icp_qat_fw_la_bulk_req *msg;
	struct qat_crypto_instance *inst = ctx->inst;
	struct device *dev = &GET_DEV(inst->accel_dev);
	struct icp_qat_hw_auth_algo_blk *hash = &dec_ctx->hash;
	unsigned int assoclen_be = cpu_to_be32(areq->assoclen);
	int ret;

	if (!areq->src || !areq->dst)
		return -EINVAL;

	if (!areq->cryptlen)
		return -EINVAL;

	ret = qat_alg_sgl_to_bufl(ctx->inst, areq->src, areq->dst, qat_req, flags);
	if (unlikely(ret))
		return ret;

	if (areq->assoclen > 0) {
		qat_req->buf.aad_buf.aad_sz =
					(areq->assoclen % GHASH_BLOCK_SIZE == 0) ?
					 areq->assoclen : (((areq->assoclen /
					 GHASH_BLOCK_SIZE) + 1) * GHASH_BLOCK_SIZE);
		qat_req->buf.aad_buf.virt_addr =
			dma_alloc_coherent(dev,
					   qat_req->buf.aad_buf.aad_sz,
					   &qat_req->buf.aad_buf.phys_addr,
					   flags);
		if (!qat_req->buf.aad_buf.virt_addr) {
			qat_alg_free_bufl(ctx->inst, qat_req);
			return -ENOMEM;
		}

		/* pad 0 if assoclen is not aligned to the block size */
		memset(qat_req->buf.aad_buf.virt_addr, 0, qat_req->buf.aad_buf.aad_sz);

		/* copy AAD to a separate flat buffer */
		if (areq->assoclen != copy_sgl_to_buf(areq->src, 0,
						      (u8 *)qat_req->buf.aad_buf.virt_addr,
						      0, areq->assoclen)) {
			qat_alg_free_bufl(ctx->inst, qat_req);
			dma_free_coherent(dev, qat_req->buf.aad_buf.aad_sz,
					  qat_req->buf.aad_buf.virt_addr,
					  qat_req->buf.aad_buf.phys_addr);
			qat_req->buf.aad_buf.virt_addr = NULL;
			return -ENOMEM;
		}
	} else {
		qat_req->buf.aad_buf.virt_addr = NULL;
		qat_req->buf.aad_buf.phys_addr = 0;
		qat_req->buf.aad_buf.aad_sz = 0;
	}

	msg = &qat_req->req;
	*msg = ctx->dec_fw_req;
	qat_req->aead_ctx = ctx;
	qat_req->aead_req = areq;
	qat_req->cb = qat_aead_alg_callback;
	qat_req->req.comn_mid.opaque_data = (uint64_t)(__force long)qat_req;
	qat_req->req.comn_mid.src_data_addr = qat_req->buf.blp;
	qat_req->req.comn_mid.dest_data_addr = qat_req->buf.bloutp;
	cipher_param = (void *)&qat_req->req.serv_specif_rqpars;
	auth_param = (void *)((uint8_t *)cipher_param + sizeof(*cipher_param));
	memcpy(cipher_param->u.cipher_IV_array, areq->iv, GCM_AES_IV_SIZE);
	cipher_param->cipher_length = areq->cryptlen - digestsize;
	cipher_param->cipher_offset = areq->assoclen;

	auth_param->auth_len = areq->cryptlen - digestsize;
	auth_param->auth_off = areq->assoclen;
	auth_param->u1.aad_adr = qat_req->buf.aad_buf.phys_addr;
	auth_param->u2.aad_sz = qat_req->buf.aad_buf.aad_sz;
	auth_param->hash_state_sz = qat_req->buf.aad_buf.aad_sz >> 3;
	auth_param->auth_res_sz = 0;
	memcpy(&hash->auth.ghash.inner_state2[ICP_QAT_HW_GALOIS_E_CTR0_SZ], &assoclen_be, 4);
	ret = qat_alg_send_sym_message(qat_req, ctx->inst, &areq->base);

	if (ret == -ENOSPC) {
		qat_alg_free_bufl(ctx->inst, qat_req);
		if (qat_req->buf.aad_buf.virt_addr) {
			dma_free_coherent(dev, qat_req->buf.aad_buf.aad_sz,
					  qat_req->buf.aad_buf.virt_addr,
					  qat_req->buf.aad_buf.phys_addr);
			qat_req->buf.aad_buf.virt_addr = NULL;
		}
	}

	return ret;
}

static int qat_alg_aead_gcm_enc(struct aead_request *areq)
{
	struct crypto_aead *aead_tfm = crypto_aead_reqtfm(areq);
	struct crypto_tfm *tfm = crypto_aead_tfm(aead_tfm);
	struct qat_alg_aead_ctx *ctx = crypto_tfm_ctx(tfm);
	struct qat_enc *enc_ctx = &ctx->enc_cd->qat_enc_cd;
	struct qat_crypto_request *qat_req = aead_request_ctx(areq);
	struct icp_qat_fw_la_cipher_req_params *cipher_param;
	struct icp_qat_fw_la_auth_req_params *auth_param;
	gfp_t flags = qat_algs_alloc_flags(&areq->base);
	struct icp_qat_fw_la_bulk_req *msg;
	struct qat_crypto_instance *inst = ctx->inst;
	struct device *dev = &GET_DEV(inst->accel_dev);
	struct icp_qat_fw_la_bulk_req *req_tmpl = &ctx->enc_fw_req;
	void *ptr = &req_tmpl->cd_ctrl;
	struct icp_qat_fw_cipher_cd_ctrl_hdr *cipher_cd_ctrl = ptr;
	unsigned int keylen = (unsigned int)(cipher_cd_ctrl->cipher_key_sz << 3);
	struct icp_qat_hw_auth_algo_blk *hash =
		(struct icp_qat_hw_auth_algo_blk *)(((uint8_t *)enc_ctx) +
		sizeof(struct icp_qat_hw_cipher_config) + keylen);
	unsigned int assoclen_be = cpu_to_be32(areq->assoclen);
	u8 *iv = areq->iv;
	int ret;

	if (!areq->src || !areq->dst)
		return -EINVAL;

	ret = qat_alg_sgl_to_bufl(ctx->inst, areq->src, areq->dst, qat_req, flags);
	if (unlikely(ret))
		return ret;

	if (areq->assoclen > 0) {
		qat_req->buf.aad_buf.aad_sz =
					(areq->assoclen % GHASH_BLOCK_SIZE == 0) ?
					 areq->assoclen : (((areq->assoclen /
					 GHASH_BLOCK_SIZE) + 1) * GHASH_BLOCK_SIZE);
		qat_req->buf.aad_buf.virt_addr =
			dma_alloc_coherent(dev,
					   qat_req->buf.aad_buf.aad_sz,
					   &qat_req->buf.aad_buf.phys_addr,
					   flags);
		if (!qat_req->buf.aad_buf.virt_addr) {
			qat_alg_free_bufl(ctx->inst, qat_req);
			return -ENOMEM;
		}

		/* pad 0 if assoclen is not aligned to the block size */
		memset(qat_req->buf.aad_buf.virt_addr, 0, qat_req->buf.aad_buf.aad_sz);

		/* copy AAD to a separate flat buffer */
		if (areq->assoclen != copy_sgl_to_buf(areq->src, 0,
						      (u8 *)qat_req->buf.aad_buf.virt_addr,
						      0, areq->assoclen)) {
			qat_alg_free_bufl(ctx->inst, qat_req);
			dma_free_coherent(dev, qat_req->buf.aad_buf.aad_sz,
					  qat_req->buf.aad_buf.virt_addr,
					  qat_req->buf.aad_buf.phys_addr);
			qat_req->buf.aad_buf.virt_addr = NULL;
			return -ENOMEM;
		}
	} else {
		qat_req->buf.aad_buf.virt_addr = NULL;
		qat_req->buf.aad_buf.phys_addr = 0;
		qat_req->buf.aad_buf.aad_sz = 0;
	}

	msg = &qat_req->req;
	*msg = ctx->enc_fw_req;
	qat_req->aead_ctx = ctx;
	qat_req->aead_req = areq;
	qat_req->cb = qat_aead_alg_callback;
	qat_req->req.comn_mid.opaque_data = (uint64_t)(__force long)qat_req;
	qat_req->req.comn_mid.src_data_addr = qat_req->buf.blp;
	qat_req->req.comn_mid.dest_data_addr = qat_req->buf.bloutp;
	cipher_param = (void *)&qat_req->req.serv_specif_rqpars;
	auth_param = (void *)((uint8_t *)cipher_param + sizeof(*cipher_param));
	memcpy(cipher_param->u.cipher_IV_array, iv, GCM_AES_IV_SIZE);
	cipher_param->cipher_length = areq->cryptlen;
	cipher_param->cipher_offset = areq->assoclen;

	auth_param->auth_len = areq->cryptlen;
	auth_param->auth_off = areq->assoclen;
	auth_param->u1.aad_adr = qat_req->buf.aad_buf.phys_addr;
	auth_param->u2.aad_sz = qat_req->buf.aad_buf.aad_sz;
	auth_param->hash_state_sz = qat_req->buf.aad_buf.aad_sz >> 3;
	auth_param->auth_res_sz = 0;
	memcpy(&hash->auth.ghash.inner_state2[ICP_QAT_HW_GALOIS_E_CTR0_SZ], &assoclen_be, 4);
	ret = qat_alg_send_sym_message(qat_req, ctx->inst, &areq->base);

	if (ret == -ENOSPC) {
		qat_alg_free_bufl(ctx->inst, qat_req);
		if (qat_req->buf.aad_buf.virt_addr) {
			dma_free_coherent(dev, qat_req->buf.aad_buf.aad_sz,
					  qat_req->buf.aad_buf.virt_addr,
					  qat_req->buf.aad_buf.phys_addr);
			qat_req->buf.aad_buf.virt_addr = NULL;
		}
	}
	return ret;
}

static int qat_alg_skcipher_rekey(struct qat_alg_skcipher_ctx *ctx,
				  const u8 *key, unsigned int keylen,
				  int mode)
{
	memset(ctx->enc_cd, 0, sizeof(*ctx->enc_cd));
	memset(ctx->dec_cd, 0, sizeof(*ctx->dec_cd));
	memset(&ctx->enc_fw_req, 0, sizeof(ctx->enc_fw_req));
	memset(&ctx->dec_fw_req, 0, sizeof(ctx->dec_fw_req));

	return qat_alg_skcipher_init_sessions(ctx, key, keylen, mode);
}

static int qat_alg_skcipher_newkey(struct qat_alg_skcipher_ctx *ctx,
				   const u8 *key, unsigned int keylen,
				   int mode)
{
	struct qat_crypto_instance *inst = NULL;
	struct device *dev;
	int node = numa_node_id();
	int ret;

	inst = qat_crypto_get_instance_node(node);
	if (!inst)
		return -EINVAL;
	dev = &GET_DEV(inst->accel_dev);
	ctx->inst = inst;
	ctx->enc_cd = dma_alloc_coherent(dev, sizeof(*ctx->enc_cd),
					 &ctx->enc_cd_paddr,
					 GFP_ATOMIC);
	if (!ctx->enc_cd) {
		ret = -ENOMEM;
		goto out_free_instance;
	}
	ctx->dec_cd = dma_alloc_coherent(dev, sizeof(*ctx->dec_cd),
					 &ctx->dec_cd_paddr,
					 GFP_ATOMIC);
	if (!ctx->dec_cd) {
		ret = -ENOMEM;
		goto out_free_enc;
	}

	ret = qat_alg_skcipher_init_sessions(ctx, key, keylen, mode);
	if (ret)
		goto out_free_all;

	return 0;

out_free_all:
	memzero_explicit(ctx->dec_cd, sizeof(*ctx->dec_cd));
	dma_free_coherent(dev, sizeof(*ctx->dec_cd),
			  ctx->dec_cd, ctx->dec_cd_paddr);
	ctx->dec_cd = NULL;
out_free_enc:
	memzero_explicit(ctx->enc_cd, sizeof(*ctx->enc_cd));
	dma_free_coherent(dev, sizeof(*ctx->enc_cd),
			  ctx->enc_cd, ctx->enc_cd_paddr);
	ctx->enc_cd = NULL;
out_free_instance:
	ctx->inst = NULL;
	qat_crypto_put_instance(inst);
	return ret;
}

static int qat_alg_skcipher_setkey(struct crypto_skcipher *tfm,
				   const u8 *key, unsigned int keylen,
				   int mode)
{
	struct qat_alg_skcipher_ctx *ctx = crypto_skcipher_ctx(tfm);

	ctx->mode = mode;

	if (ctx->enc_cd)
		return qat_alg_skcipher_rekey(ctx, key, keylen, mode);
	else
		return qat_alg_skcipher_newkey(ctx, key, keylen, mode);
}

static int qat_alg_skcipher_cbc_setkey(struct crypto_skcipher *tfm,
				       const u8 *key, unsigned int keylen)
{
	return qat_alg_skcipher_setkey(tfm, key, keylen,
				       ICP_QAT_HW_CIPHER_CBC_MODE);
}

static int qat_alg_skcipher_ctr_setkey(struct crypto_skcipher *tfm,
				       const u8 *key, unsigned int keylen)
{
	return qat_alg_skcipher_setkey(tfm, key, keylen,
				       ICP_QAT_HW_CIPHER_CTR_MODE);
}

static int qat_alg_skcipher_xts_setkey(struct crypto_skcipher *tfm,
				       const u8 *key, unsigned int keylen)
{
	return qat_alg_skcipher_setkey(tfm, key, keylen,
				       ICP_QAT_HW_CIPHER_XTS_MODE);
}

static int qat_alg_skcipher_encrypt(struct skcipher_request *req)
{
	struct crypto_skcipher *stfm = crypto_skcipher_reqtfm(req);
	struct crypto_tfm *tfm = crypto_skcipher_tfm(stfm);
	struct qat_alg_skcipher_ctx *ctx = crypto_tfm_ctx(tfm);
	struct qat_crypto_request *qat_req = skcipher_request_ctx(req);
	struct icp_qat_fw_la_cipher_req_params *cipher_param;
	gfp_t flags = qat_algs_alloc_flags(&req->base);
	struct icp_qat_fw_la_bulk_req *msg;
	int ret;

	if (req->cryptlen == 0)
		return 0;

	ret = qat_alg_sgl_to_bufl(ctx->inst, req->src, req->dst, qat_req, flags);
	if (unlikely(ret))
		return ret;

	msg = &qat_req->req;
	*msg = ctx->enc_fw_req;
	qat_req->skcipher_ctx = ctx;
	qat_req->skcipher_req = req;
	qat_req->cb = qat_skcipher_alg_callback;
	qat_req->req.comn_mid.opaque_data = (uint64_t)(__force long)qat_req;
	qat_req->req.comn_mid.src_data_addr = qat_req->buf.blp;
	qat_req->req.comn_mid.dest_data_addr = qat_req->buf.bloutp;
	qat_req->encryption = true;
	cipher_param = (void *)&qat_req->req.serv_specif_rqpars;
	cipher_param->cipher_length = req->cryptlen;
	cipher_param->cipher_offset = 0;
	memcpy(cipher_param->u.cipher_IV_array, req->iv, AES_BLOCK_SIZE);

	ret = qat_alg_send_sym_message(qat_req, ctx->inst, &req->base);
	if (ret == -ENOSPC)
		qat_alg_free_bufl(ctx->inst, qat_req);

	return ret;
}

static int qat_alg_skcipher_blk_encrypt(struct skcipher_request *req)
{
	if (req->cryptlen % AES_BLOCK_SIZE != 0)
		return -EINVAL;

	return qat_alg_skcipher_encrypt(req);
}

static int qat_alg_skcipher_decrypt(struct skcipher_request *req)
{
	struct crypto_skcipher *stfm = crypto_skcipher_reqtfm(req);
	struct crypto_tfm *tfm = crypto_skcipher_tfm(stfm);
	struct qat_alg_skcipher_ctx *ctx = crypto_tfm_ctx(tfm);
	struct qat_crypto_request *qat_req = skcipher_request_ctx(req);
	struct icp_qat_fw_la_cipher_req_params *cipher_param;
	gfp_t flags = qat_algs_alloc_flags(&req->base);
	struct icp_qat_fw_la_bulk_req *msg;
	int ret;

	if (req->cryptlen == 0)
		return 0;

	ret = qat_alg_sgl_to_bufl(ctx->inst, req->src, req->dst, qat_req, flags);
	if (unlikely(ret))
		return ret;

	msg = &qat_req->req;
	*msg = ctx->dec_fw_req;
	qat_req->skcipher_ctx = ctx;
	qat_req->skcipher_req = req;
	qat_req->cb = qat_skcipher_alg_callback;
	qat_req->req.comn_mid.opaque_data = (uint64_t)(__force long)qat_req;
	qat_req->req.comn_mid.src_data_addr = qat_req->buf.blp;
	qat_req->req.comn_mid.dest_data_addr = qat_req->buf.bloutp;
	qat_req->encryption = false;
	cipher_param = (void *)&qat_req->req.serv_specif_rqpars;
	cipher_param->cipher_length = req->cryptlen;
	cipher_param->cipher_offset = 0;
	memcpy(cipher_param->u.cipher_IV_array, req->iv, AES_BLOCK_SIZE);
	qat_alg_update_iv(qat_req);

	ret = qat_alg_send_sym_message(qat_req, ctx->inst, &req->base);
	if (ret == -ENOSPC)
		qat_alg_free_bufl(ctx->inst, qat_req);

	return ret;
}

static int qat_alg_skcipher_blk_decrypt(struct skcipher_request *req)
{
	if (req->cryptlen % AES_BLOCK_SIZE != 0)
		return -EINVAL;

	return qat_alg_skcipher_decrypt(req);
}

static int qat_alg_aead_init(struct crypto_aead *tfm,
			     enum icp_qat_hw_auth_algo hash,
			     const char *hash_name)
{
	struct qat_alg_aead_ctx *ctx = crypto_aead_ctx(tfm);

	if (hash == ICP_QAT_HW_AUTH_ALGO_GALOIS_128) {
		ctx->tfm.ahash_tfm = crypto_alloc_ahash(hash_name, 0, 0);
		if (IS_ERR(ctx->tfm.ahash_tfm))
			return PTR_ERR(ctx->tfm.ahash_tfm);
	} else {
		ctx->tfm.shash_tfm = crypto_alloc_shash(hash_name, 0, 0);
		if (IS_ERR(ctx->tfm.shash_tfm))
			return PTR_ERR(ctx->tfm.shash_tfm);
	}
	ctx->qat_hash_alg = hash;
	crypto_aead_set_reqsize(tfm, sizeof(struct qat_crypto_request));

	return 0;
}

#ifdef QAT_LEGACY_ALGORITHMS
static int qat_alg_aead_sha1_init(struct crypto_aead *tfm)
{
	return qat_alg_aead_init(tfm, ICP_QAT_HW_AUTH_ALGO_SHA1, "sha1");
}
#endif

static int qat_alg_aead_sha256_init(struct crypto_aead *tfm)
{
	return qat_alg_aead_init(tfm, ICP_QAT_HW_AUTH_ALGO_SHA256, "sha256");
}

static int qat_alg_aead_sha512_init(struct crypto_aead *tfm)
{
	return qat_alg_aead_init(tfm, ICP_QAT_HW_AUTH_ALGO_SHA512, "sha512");
}

static int qat_alg_aead_gcm_init(struct crypto_aead *tfm)
{
	return qat_alg_aead_init(tfm, ICP_QAT_HW_AUTH_ALGO_GALOIS_128, "ghash");
}

static void qat_alg_aead_exit(struct crypto_aead *tfm, int mode)
{
	struct qat_alg_aead_ctx *ctx = crypto_aead_ctx(tfm);
	struct qat_crypto_instance *inst = ctx->inst;
	struct device *dev;

	if (mode == ICP_QAT_HW_AUTH_ALGO_GALOIS_128)
		crypto_free_ahash(ctx->tfm.ahash_tfm);
	else
		crypto_free_shash(ctx->tfm.shash_tfm);

	if (!inst)
		return;

	dev = &GET_DEV(inst->accel_dev);
	if (ctx->enc_cd) {
		memzero_explicit(ctx->enc_cd, sizeof(struct qat_alg_cd));
		dma_free_coherent(dev, sizeof(struct qat_alg_cd),
				  ctx->enc_cd, ctx->enc_cd_paddr);
	}
	if (ctx->dec_cd) {
		memzero_explicit(ctx->dec_cd, sizeof(struct qat_alg_cd));
		dma_free_coherent(dev, sizeof(struct qat_alg_cd),
				  ctx->dec_cd, ctx->dec_cd_paddr);
	}

	qat_crypto_put_instance(inst);
}

#ifdef QAT_LEGACY_ALGORITHMS
static void qat_alg_aead_sha1_exit(struct crypto_aead *tfm)
{
	return qat_alg_aead_exit(tfm, ICP_QAT_HW_AUTH_ALGO_SHA1);
}
#endif

static void qat_alg_aead_sha256_exit(struct crypto_aead *tfm)
{
	return qat_alg_aead_exit(tfm, ICP_QAT_HW_AUTH_ALGO_SHA256);
}

static void qat_alg_aead_sha512_exit(struct crypto_aead *tfm)
{
	return qat_alg_aead_exit(tfm, ICP_QAT_HW_AUTH_ALGO_SHA512);
}

static void qat_alg_aead_gcm_exit(struct crypto_aead *tfm)
{
	return qat_alg_aead_exit(tfm, ICP_QAT_HW_AUTH_ALGO_GALOIS_128);
}

static int qat_alg_skcipher_init_tfm(struct crypto_skcipher *tfm)
{
	struct qat_alg_skcipher_ctx *ctx = crypto_skcipher_ctx(tfm);

	crypto_skcipher_set_reqsize(tfm, sizeof(struct qat_crypto_request));
	ctx->tfm = tfm;

	return 0;
}

static void qat_alg_skcipher_exit_tfm(struct crypto_skcipher *tfm)
{
	struct qat_alg_skcipher_ctx *ctx = crypto_skcipher_ctx(tfm);
	struct qat_crypto_instance *inst = ctx->inst;
	struct device *dev;

	if (!inst)
		return;

	dev = &GET_DEV(inst->accel_dev);
	if (ctx->enc_cd) {
		memzero_explicit(ctx->enc_cd,
				 sizeof(struct icp_qat_hw_cipher_algo_blk));
		dma_free_coherent(dev,
				  sizeof(struct icp_qat_hw_cipher_algo_blk),
				  ctx->enc_cd, ctx->enc_cd_paddr);
	}
	if (ctx->dec_cd) {
		memzero_explicit(ctx->dec_cd,
				 sizeof(struct icp_qat_hw_cipher_algo_blk));
		dma_free_coherent(dev,
				  sizeof(struct icp_qat_hw_cipher_algo_blk),
				  ctx->dec_cd, ctx->dec_cd_paddr);
	}

	qat_crypto_put_instance(inst);
}

#ifdef QAT_LEGACY_ALGORITHMS
static struct aead_alg qat_legacy_aeads[] = { {
	.base = {
		.cra_name = "authenc(hmac(sha1),cbc(aes))",
		.cra_driver_name = "qat_aes_cbc_hmac_sha1",
		.cra_priority = 4001,
		.cra_flags = CRYPTO_ALG_ASYNC,
		.cra_blocksize = AES_BLOCK_SIZE,
		.cra_ctxsize = sizeof(struct qat_alg_aead_ctx),
		.cra_module = THIS_MODULE,
	},
	.init = qat_alg_aead_sha1_init,
	.exit = qat_alg_aead_sha1_exit,
	.setkey = qat_alg_aead_hmac_setkey,
	.decrypt = qat_alg_aead_dec,
	.encrypt = qat_alg_aead_enc,
	.ivsize = AES_BLOCK_SIZE,
	.maxauthsize = SHA1_DIGEST_SIZE,
} };
#endif

static struct aead_alg qat_aeads[] = { {
	.base = {
		.cra_name = "authenc(hmac(sha256),cbc(aes))",
		.cra_driver_name = "qat_aes_cbc_hmac_sha256",
		.cra_priority = 4001,
		.cra_flags = CRYPTO_ALG_ASYNC,
		.cra_blocksize = AES_BLOCK_SIZE,
		.cra_ctxsize = sizeof(struct qat_alg_aead_ctx),
		.cra_module = THIS_MODULE,
	},
	.init = qat_alg_aead_sha256_init,
	.exit = qat_alg_aead_sha256_exit,
	.setkey = qat_alg_aead_hmac_setkey,
	.decrypt = qat_alg_aead_dec,
	.encrypt = qat_alg_aead_enc,
	.ivsize = AES_BLOCK_SIZE,
	.maxauthsize = SHA256_DIGEST_SIZE,
}, {
	.base = {
		.cra_name = "authenc(hmac(sha512),cbc(aes))",
		.cra_driver_name = "qat_aes_cbc_hmac_sha512",
		.cra_priority = 4001,
		.cra_flags = CRYPTO_ALG_ASYNC,
		.cra_blocksize = AES_BLOCK_SIZE,
		.cra_ctxsize = sizeof(struct qat_alg_aead_ctx),
		.cra_module = THIS_MODULE,
	},
	.init = qat_alg_aead_sha512_init,
	.exit = qat_alg_aead_sha512_exit,
	.setkey = qat_alg_aead_hmac_setkey,
	.decrypt = qat_alg_aead_dec,
	.encrypt = qat_alg_aead_enc,
	.ivsize = AES_BLOCK_SIZE,
	.maxauthsize = SHA512_DIGEST_SIZE,
}, {
	.base = {
		.cra_name = "gcm(aes)",
		.cra_driver_name = "qat_aes_gcm",
		.cra_priority = 4001,
		.cra_flags = CRYPTO_ALG_TYPE_AEAD | CRYPTO_ALG_ASYNC,
		.cra_alignmask = 0,
		.cra_blocksize = 1,
		.cra_ctxsize = sizeof(struct qat_alg_aead_ctx),
		.cra_module = THIS_MODULE,
	},
	.init = qat_alg_aead_gcm_init,
	.exit = qat_alg_aead_gcm_exit,
	.setkey = qat_alg_aead_gcm_setkey,
	.decrypt = qat_alg_aead_gcm_dec,
	.encrypt = qat_alg_aead_gcm_enc,
	.ivsize = GCM_AES_IV_SIZE,
	.maxauthsize = GHASH_DIGEST_SIZE,
} };

static struct skcipher_alg qat_skciphers[] = { {
	.base.cra_name = "cbc(aes)",
	.base.cra_driver_name = "qat_aes_cbc",
	.base.cra_priority = 4001,
	.base.cra_flags = CRYPTO_ALG_ASYNC,
	.base.cra_blocksize = AES_BLOCK_SIZE,
	.base.cra_ctxsize = sizeof(struct qat_alg_skcipher_ctx),
	.base.cra_alignmask = 0,
	.base.cra_module = THIS_MODULE,

	.init = qat_alg_skcipher_init_tfm,
	.exit = qat_alg_skcipher_exit_tfm,
	.setkey = qat_alg_skcipher_cbc_setkey,
	.decrypt = qat_alg_skcipher_blk_decrypt,
	.encrypt = qat_alg_skcipher_blk_encrypt,
	.min_keysize = AES_MIN_KEY_SIZE,
	.max_keysize = AES_MAX_KEY_SIZE,
	.ivsize = AES_BLOCK_SIZE,
}, {
	.base.cra_name = "ctr(aes)",
	.base.cra_driver_name = "qat_aes_ctr",
	.base.cra_priority = 4001,
	.base.cra_flags = CRYPTO_ALG_ASYNC,
	.base.cra_blocksize = 1,
	.base.cra_ctxsize = sizeof(struct qat_alg_skcipher_ctx),
	.base.cra_alignmask = 0,
	.base.cra_module = THIS_MODULE,

	.init = qat_alg_skcipher_init_tfm,
	.exit = qat_alg_skcipher_exit_tfm,
	.setkey = qat_alg_skcipher_ctr_setkey,
	.decrypt = qat_alg_skcipher_decrypt,
	.encrypt = qat_alg_skcipher_encrypt,
	.min_keysize = AES_MIN_KEY_SIZE,
	.max_keysize = AES_MAX_KEY_SIZE,
	.ivsize = AES_BLOCK_SIZE,
}, {
	.base.cra_name = "xts(aes)",
	.base.cra_driver_name = "qat_aes_xts",
	.base.cra_priority = 4001,
	.base.cra_flags = CRYPTO_ALG_ASYNC,
	.base.cra_blocksize = AES_BLOCK_SIZE,
	.base.cra_ctxsize = sizeof(struct qat_alg_skcipher_ctx),
	.base.cra_alignmask = 0,
	.base.cra_module = THIS_MODULE,

	.init = qat_alg_skcipher_init_tfm,
	.exit = qat_alg_skcipher_exit_tfm,
	.setkey = qat_alg_skcipher_xts_setkey,
	.decrypt = qat_alg_skcipher_blk_decrypt,
	.encrypt = qat_alg_skcipher_blk_encrypt,
	.min_keysize = 2 * AES_MIN_KEY_SIZE,
	.max_keysize = 2 * AES_MAX_KEY_SIZE,
	.ivsize = AES_BLOCK_SIZE,
} };

int qat_algs_register(void)
{
	int ret = 0;

	mutex_lock(&algs_lock);
	if (++active_devs != 1)
		goto unlock;

	ret = crypto_register_skciphers(qat_skciphers,
					ARRAY_SIZE(qat_skciphers));
	if (ret)
		goto unlock;

	ret = crypto_register_aeads(qat_aeads, ARRAY_SIZE(qat_aeads));
	if (ret)
		goto unreg_algs;
#ifdef QAT_LEGACY_ALGORITHMS
	ret = crypto_register_aeads(qat_legacy_aeads,
				    ARRAY_SIZE(qat_legacy_aeads));
	if (ret)
		goto unreg_all_algs;
#endif

unlock:
	mutex_unlock(&algs_lock);
	return ret;
#ifdef QAT_LEGACY_ALGORITHMS
unreg_all_algs:
	crypto_unregister_aeads(qat_aeads, ARRAY_SIZE(qat_aeads));
#endif
unreg_algs:
	crypto_unregister_skciphers(qat_skciphers, ARRAY_SIZE(qat_skciphers));
	goto unlock;
}

void qat_algs_unregister(void)
{
	mutex_lock(&algs_lock);
	if (--active_devs != 0)
		goto unlock;
#ifdef QAT_LEGACY_ALGORITHMS
	crypto_unregister_aeads(qat_legacy_aeads,
				ARRAY_SIZE(qat_legacy_aeads));
#endif
	crypto_unregister_aeads(qat_aeads, ARRAY_SIZE(qat_aeads));
	crypto_unregister_skciphers(qat_skciphers, ARRAY_SIZE(qat_skciphers));

unlock:
	mutex_unlock(&algs_lock);
}
#endif
