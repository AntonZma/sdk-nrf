/*
 * Copyright (c) 2026 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <cracen/mem_helpers.h>
#include <psa/crypto.h>
#include <psa/crypto_values.h>
#include <stdbool.h>
#include <string.h>
// #include <sxsymcrypt/aes.h>
#include <sxsymcrypt/internal.h>
#include <sxsymcrypt/keyref.h>
#include <cracen/statuscodes.h>
#include <zephyr/sys/util.h>
#include <zephyr/sys/__assert.h>

#include <cracen_psa_primitives.h>
#include "../../../cracenpsa/src/common.h"
#include <cracen_sw_common.h>
#include <cracen_sw_aead.h>
#include <cracen_sw_chacha20_poly1305.h>

/* Nonce size must be 96 bits (RFC8439) */
#define CHACHA20_POLY1305_VALID_NONCE_LEN	12u
/* Masks required for Poly1305 "r" value clamping */
#define POLY1305_CLAMP_ODD_MASK			0x0F
#define POLY1305_CLAMP_EVEN_MASK		0xFC

// /* Compute Q (length field size) from nonce length: Q = 16 - nonce_len */
// #define GCM_Q_LEN_FROM_NONCE(nonce_len) (SX_BLKCIPHER_AES_BLK_SZ - (nonce_len))

static bool is_nonce_length_valid(size_t nonce_length)
{
	return nonce_length == CHACHA20_POLY1305_VALID_NONCE_LEN;
}

static bool is_tag_length_valid(size_t tag_length)
{
	return tag_length == CRACEN_POLY1305_TAG_SIZE;
}

static psa_status_t increment_counter(uint32_t *ctr)
{
	if (++ctr != 0) {
		return PSA_SUCCESS;
	}

	/* All counter bytes wrapped to zero which means it overflowed */
	return PSA_ERROR_INVALID_ARGUMENT;
}

static psa_status_t cracen_chacha20_primitive(struct sxblkcipher *blkciph, const struct sxkeyref *key,
				       const uint8_t *counter, const uint8_t *nonce,
				       const uint8_t *input, uint8_t *output, size_t data_size)
{
	int sx_status;
	size_t output_size;

	sx_status = sx_blkcipher_create_chacha20_enc(blkciph, key, counter, nonce);
	if (sx_status != SX_OK) {
		return silex_statuscodes_to_psa(sx_status);
	}

	// TODO: check if the following function will work.
	// If yes, it must be renamed inside "cracen_sw_common.c" so as not to
	// specifically include block algorithm in its name.
	return cracen_aes_ecb_crypt(blkciph, input, data_size, output, data_size, &output_size);
}

/** a = a + b,
 *  assuming sz_a > sz_b
*/
static void cracen_be_addbytes(uint8_t *a, const uint8_t *b, size_t sz_a, size_t sz_b)
{
	size_t carry = 0;
	size_t mask;
	size_t next_byte;
	size_t sum;

	while (sz_a > 0) {
		sz_a--;
		/* mask: 0xFFFFFFFF if sz_b > 0, else 0 */
		mask = 0;
		mask -= (sz_b > 0);

		/* load b byte or 0 */
		next_byte = b[sz_b - 1] & mask;

		sum = (size_t)a[sz_a] + next_byte + carry;
		a[sz_a] = (uint8_t)(sum & 0xFF);
		carry = sum >> 8;

		sz_b -= (sz_b > 0);
	}
}

/* Modified function from Silex (needed to test the ability to switch counter value during initialization) */
// static int create_chacha20poly1305(struct sxaead *aead_ctx, const struct sxkeyref *key,
// 				   uint32_t counter,
// 				   const uint8_t *nonce, const uint32_t dir, size_t tagsz)
// {
// 	if (key->sz != SX_CHACHAPOLY_KEY_SZ) {
// 		return SX_ERR_INVALID_KEY_SZ;
// 	}

// 	/* has countermeasures and the key need to be set before callling sx_aead_hw_reserve */
// 	aead_ctx->has_countermeasures = false;
// 	aead_ctx->key = key;
// 	sx_aead_hw_reserve(aead_ctx);

// 	aead_ctx->cfg = &ba417chachapolycfg;

// 	sx_cmdma_newcmd(&aead_ctx->dma, aead_ctx->descs, aead_ctx->cfg->mode | dir,
// 			aead_ctx->cfg->dmatags->cfg);
// 	ADD_CFGDESC(aead_ctx->dma, key->key, SX_CHACHAPOLY_KEY_SZ, aead_ctx->cfg->dmatags->key);

// 	/* In AEAD context, for BA417, the counter that must be provided and
// 	 * initialized with 1. counter size is 4 bytes. Starting at position 16
// 	 * due to lenAlenC that uses first 16 bytes of extramem
// 	 */
// 	// aead_ctx->extramem[16] = 0;
// 	// aead_ctx->extramem[17] = 0;
// 	// aead_ctx->extramem[18] = 0;
// 	// aead_ctx->extramem[19] = 1;
// 	memcpy(&aead_ctx->extramem[16], (uint8_t *)counter, sizeof(uint32_t));

// 	ADD_INDESC_PRIV(aead_ctx->dma, OFFSET_EXTRAMEM(aead_ctx) + 16, SX_CHACHAPOLY_COUNTER_SIZE,
// 			aead_ctx->cfg->dmatags->iv_or_state);
// 	ADD_CFGDESC(aead_ctx->dma, nonce, SX_CHACHAPOLY_NONCE_SZ, aead_ctx->cfg->dmatags->nonce);

// 	aead_ctx->tagsz = tagsz;
// 	aead_ctx->expectedtag = aead_ctx->cfg->verifier;
// 	aead_ctx->discardaadsz = 0;
// 	aead_ctx->totalaadsz = 0;
// 	aead_ctx->datainsz = 0;
// 	aead_ctx->dataintotalsz = 0;

// 	return SX_OK;
// }

// int create_chacha20poly1305_enc(struct sxaead *aead_ctx, const struct sxkeyref *key, uint32_t counter,
// 					const uint8_t *nonce, size_t tagsz)
// {
// 	return create_chacha20poly1305(aead_ctx, key, counter, nonce, 0, tagsz);
// }

// int create_chacha20poly1305_dec(struct sxaead *aead_ctx, const struct sxkeyref *key, uint32_t counter,
// 					const uint8_t *nonce, size_t tagsz)
// {
// 	return create_chacha20poly1305(aead_ctx, key, counter, nonce, ba417chachapolycfg.decr,
// 					       tagsz);
// }

// + for ChaCha
static psa_status_t setup(cracen_aead_operation_t *operation, enum cipher_operation dir,
			  const psa_key_attributes_t *attributes, const uint8_t *key_buffer,
			  size_t key_buffer_size, psa_algorithm_t alg)
{
	psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
	size_t tag_size;

	safe_memzero(&operation->sw_chacha_poly_ctx, sizeof(operation->sw_chacha_poly_ctx));

	tag_size = PSA_AEAD_TAG_LENGTH(PSA_KEY_TYPE_CHACHA20,
				       PSA_BYTES_TO_BITS(key_buffer_size), alg);
	if (!is_tag_length_valid(tag_size)) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}

	memcpy(operation->key_buffer, key_buffer, key_buffer_size);
	status = cracen_load_keyref(attributes, operation->key_buffer, key_buffer_size,
				    &operation->keyref);
	if (status != PSA_SUCCESS) {
		return status;
	}
	operation->alg = PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(alg);
	operation->dir = dir;
	operation->tag_size = tag_size;
	return status;
}

static void poly_generate_rs_key(const uint8_t *chacha20_res_block, uint8_t *rs_key)
{
	/** RFC8439:
	 *  We take the first 256 bits of the serialized state,
	 *  and use those as the one-time Poly1305 key:
	 *  the first 128 bits are clamped and form "r", while
	 *  the next 128 bits become "s". 
	 *  The other 256 bits are discarded.
	 */
	const size_t r_value_size = CRACEN_POLY1305_KEY_SIZE / 2;

	memcpy(rs_key, chacha20_res_block, CRACEN_POLY1305_KEY_SIZE);
	/* Clamping "r" value */
	for (size_t i = 3; i < r_value_size; i++) {
		chacha20_res_block[i] &= POLY1305_CLAMP_ODD_MASK;
		if (i + 1 < r_value_size) {
			chacha20_res_block[i + 1] &= POLY1305_CLAMP_EVEN_MASK;
		}
	}
}

// + for ChaCha
static psa_status_t initialize_poly_key(cracen_aead_operation_t *operation,
				     struct sxblkcipher *cipher)
{
	cracen_sw_chacha20_poly1305_context_t *chacha_poly_ctx = &operation->sw_chacha_poly_ctx;
	// feeding zeros as the input should return "keystream" value (RFC8439, 2.4.1)
	const uint8_t zero[SX_BLKCIPHER_CHACHA20_BLK_SZ] = {};
	const uint32_t zero_counter = 0;
	uint8_t res_block[SX_BLKCIPHER_CHACHA20_BLK_SZ] = {};
	psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

	if (chacha_poly_ctx->rs_key_initialized) {
		return PSA_SUCCESS;
	}
	status = cracen_chacha20_primitive(cipher, &operation->keyref, (uint8_t *)zero_counter,
			operation->nonce, zero /* TODO: check if this is the correct input */, res_block,
			SX_BLKCIPHER_CHACHA20_BLK_SZ);

	if (status == PSA_SUCCESS) {
		poly_generate_rs_key(res_block, chacha_poly_ctx->rs_key);
		gcm_ctx->rs_key_initialized = true;
	}
	return status;
}

// TODO
static void calc_poly1305_mac(cracen_aead_operation_t *operation, const uint8_t *input,
			   size_t input_len)
{
	cracen_sw_chacha20_poly1305_context_t *chacha_poly_ctx = &operation->sw_chacha_poly_ctx;

	for (size_t i = 0; i < input_len; i++) {
		chacha_poly_ctx->partial_block[gcm_ctx->data_partial_len++] = input[i];
		if (chacha_poly_ctx->data_partial_len == CRACEN_POLY1305_TAG_SIZE) {
			/** The size of the input data chunk of GHASH algorithm
			 * is expected to be multiple of block size (NIST SP800-38D)
			 */
			// cracen_xorbytes(gcm_ctx->ghash_block, gcm_ctx->partial_block,
			// 		SX_BLKCIPHER_AES_BLK_SZ);
			// multiply_blocks_gf(operation, gcm_ctx->ghash_block, gcm_ctx->ghash_block);

			// Note: for the "partial" case second parameter should be "data_partial_len"
			// cracen_be_add(chacha_poly_ctx->partial_block, CRACEN_POLY1305_TAG_SIZE, 0x01); // NOTE: This must be added as the 17th byte
			cracen_be_addbytes(chacha_poly_ctx->poly_acc, chacha_poly_ctx->partial_block,
					CRACEN_POLY1305_ACC_SIZE, CRACEN_POLY1305_TAG_SIZE);
			
			// TODO: add modulo operation from CRACEN primitive
			/* a = (r * a) % p */
			// chacha_poly_ctx->poly_acc = ...;

			chacha_poly_ctx->data_partial_len = 0;
		}
	}
}

static psa_status_t calc_chacha20(cracen_aead_operation_t *operation, struct sxblkcipher *cipher,
			    const uint8_t *input, uint8_t *output, size_t length)
{
	cracen_sw_chacha20_poly1305_context_t *chacha_poly_ctx = &operation->sw_chacha_poly_ctx;
	psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

	status = cracen_chacha20_primitive(cipher, &operation->keyref,
					   (uint8_t *)chacha_poly_ctx->ctr,
					   operation->nonce, input, output, length);
	if (status != PSA_SUCCESS) {
		return status;
	}
			
	if (length == SX_BLKCIPHER_CHACHA20_BLK_SZ) {
		return increment_counter(&chacha_poly_ctx->ctr);
	}
	return PSA_SUCCESS;
}

// + for ChaCha
psa_status_t cracen_sw_chacha20_poly1305_encrypt_setup(cracen_aead_operation_t *operation,
					     const psa_key_attributes_t *attributes,
					     const uint8_t *key_buffer, size_t key_buffer_size,
					     psa_algorithm_t alg)
{
	return setup(operation, CRACEN_ENCRYPT, attributes, key_buffer, key_buffer_size, alg);
}

// + for ChaCha
psa_status_t cracen_sw_chacha20_poly1305_decrypt_setup(cracen_aead_operation_t *operation,
					     const psa_key_attributes_t *attributes,
					     const uint8_t *key_buffer, size_t key_buffer_size,
					     psa_algorithm_t alg)
{
	return setup(operation, CRACEN_DECRYPT, attributes, key_buffer, key_buffer_size, alg);
}

// + for ChaCha
psa_status_t cracen_sw_chacha20_poly1305_set_nonce(cracen_aead_operation_t *operation, const uint8_t *nonce,
					 size_t nonce_length)
{
	if (!is_nonce_length_valid(nonce_length)) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	memcpy(operation->nonce, nonce, nonce_length);
	operation->nonce_length = nonce_length;
	return PSA_SUCCESS;
}

// + for ChaCha
psa_status_t cracen_sw_chacha20_poly1305_set_lengths(cracen_aead_operation_t *operation, size_t ad_length,
					   size_t plaintext_length)
{
	operation->ad_length = ad_length;
	operation->plaintext_length = plaintext_length;
	return PSA_SUCCESS;
}

// +- for ChaCha (to be tested)
psa_status_t cracen_sw_chacha20_poly1305_update_ad(cracen_aead_operation_t *operation, const uint8_t *input,
					 size_t input_length)
{
	cracen_sw_chacha20_poly1305_context_t *chacha_poly_ctx = &operation->sw_chacha_poly_ctx;
	struct sxblkcipher cipher;
	psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
	size_t processed = 0;

	status = initialize_poly_key(operation, &cipher);
	if (status != PSA_SUCCESS) {
		return status;
	}

	while (processed < input_length) {
		size_t chunk_size = MIN(input_length - processed,
					CRACEN_POLY1305_TAG_SIZE - gcm_ctx->data_partial_len);

		calc_poly1305_mac(operation, input, input_length);
		processed += chunk_size;
	}
	gcm_ctx->total_ad_fed += processed;
	return status;
}

// +- for ChaCha (to be tested)
static void finalize_ad_padding(cracen_aead_operation_t *operation)
{
	cracen_sw_chacha20_poly1305_context_t *chacha_poly_ctx = &operation->sw_chacha_poly_ctx;
	const uint8_t padding_block[CRACEN_POLY1305_TAG_SIZE] = {0};

	if (operation->ad_finished) {
		return;
	}

	/* ChaCha20-Poly1305 requires AD to be padded to block boundary before processing plaintext */
	if (gcm_ctx->data_partial_len != 0) {
		/* Apply zero padding */
		calc_poly1305_mac(operation, padding_block,
				  CRACEN_POLY1305_TAG_SIZE - gcm_ctx->data_partial_len);
		gcm_ctx->total_ad_fed = ROUND_UP(gcm_ctx->total_ad_fed, CRACEN_POLY1305_TAG_SIZE);
	}
}

// +- for ChaCha (to be tested)
/* Finalize any partial data block with zero-padding and update MAC */
static void finalize_data_padding(cracen_aead_operation_t *operation)
{
	cracen_sw_chacha20_poly1305_context_t *chacha_poly_ctx = &operation->sw_chacha_poly_ctx;
	uint8_t padding_block[CRACEN_POLY1305_TAG_SIZE] = {0};

	chacha_poly_ctx->total_data_enc += chacha_poly_ctx->data_partial_len;

	if (chacha_poly_ctx->data_partial_len != 0) {
		/* Apply zero padding */
		calc_poly1305_mac(operation, padding_block,
				  CRACEN_POLY1305_TAG_SIZE - chacha_poly_ctx->data_partial_len);
		chacha_poly_ctx->total_data_enc = ROUND_UP(chacha_poly_ctx->total_data_enc,
							   CRACEN_POLY1305_TAG_SIZE);
	}
	safe_memzero(padding_block, sizeof(padding_block));

	/* Poly1305( [len(AAD)]64 || [LEN(C)]64 ) */
	// NOTE: RFC8439 requires to convert these values to little endian. TODO: Check Cracen requirements
	encode_big_endian_length(padding_block,
				 CRACEN_POLY1305_TAG_SIZE / 2,
				 PSA_BYTES_TO_BITS(gcm_ctx->total_ad_fed),
				 CRACEN_POLY1305_TAG_SIZE / 2);
	encode_big_endian_length(padding_block + CRACEN_POLY1305_TAG_SIZE / 2,
				 CRACEN_POLY1305_TAG_SIZE / 2,
				 PSA_BYTES_TO_BITS(gcm_ctx->total_data_enc),
				 CRACEN_POLY1305_TAG_SIZE / 2);
	calc_poly1305_mac(operation, padding_block, CRACEN_POLY1305_TAG_SIZE);

	chacha_poly_ctx->data_partial_len = 0;
	safe_memzero(padding_block, sizeof(padding_block));
}

/* Generate authentication tag by encrypting J0 block (counter=0) */
static psa_status_t generate_tag(cracen_aead_operation_t *operation, uint8_t *tag,
				 struct sxblkcipher *cipher)
{
	cracen_sw_chacha20_poly1305_context_t *chacha_poly_ctx = &operation->sw_chacha_poly_ctx;
	
	// TODO: Execute last operation on chacha_poly_ctx->poly_acc: add "s"
	//	 or use native Cracen HW (sx_aead_produce_tag())

	return status;
}

// +- for ChaCha (to be tested)
psa_status_t cracen_sw_chacha20_poly1305_update(cracen_aead_operation_t *operation, const uint8_t *input,
				      size_t input_length, uint8_t *output, size_t output_size,
				      size_t *output_length)
{
	// TODO
	cracen_sw_chacha20_poly1305_context_t *chacha_poly_ctx = &operation->sw_chacha_poly_ctx;
	struct sxblkcipher cipher;
	psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
	size_t processed = 0;
	// size_t counter_size = GCM_Q_LEN_FROM_NONCE(operation->nonce_length);

	status = initialize_poly_key(operation, &cipher);
	if (status != PSA_SUCCESS) {
		return status;
	}
	// initialize_ctr(operation);

	finalize_ad_padding(operation);
	operation->ad_finished = true;

	safe_memzero(output, input_length);

	/* Process data with CTR mode encryption/decryption */
	if (operation->dir == CRACEN_ENCRYPT) {
		/* Encrypt: apply ChaCha20 keystream, then calc Poly1305 MAC */
		while (processed < input_length) {
			size_t chunk_size =
				MIN(input_length - processed,
				    SX_BLKCIPHER_CHACHA20_BLK_SZ - gcm_ctx->data_partial_len);

			// status = ctr_xor(operation, &cipher, &input[processed], &output[processed],
			// 		 chunk_size, counter_size);
			status = calc_chacha20(operation, &cipher, &input[processed],
					       &output[processed], chunk_size);
			if (status != PSA_SUCCESS) {
				return status;
			}

			// TODO: add "while" loop to divide data chunks (max 64 bytes) to "subchunks" (16 bytes) for MAC calculation
			// NOTE: this might require second buffer with padding
			// {
			calc_poly1305_mac(operation, &output[processed], chunk_size);
			// }

			processed += chunk_size;
		}
	} else {
		/* Decryption does the reverse of encryption, so apply Poly1305 first, then ChaCha20 */
		while (processed < input_length) {
			size_t chunk_size =
				MIN(input_length - processed,
				    SX_BLKCIPHER_CHACHA20_BLK_SZ - gcm_ctx->data_partial_len);

			// TODO: add "while" loop to divide data chunks (max 64 bytes) to "subchunks" (16 bytes) for MAC calculation
			// {
			calc_poly1305_mac(operation, &input[processed], chunk_size);
			// }

			// status = ctr_xor(operation, &cipher, &input[processed], &output[processed],
			// 		 chunk_size, counter_size);
			status = calc_chacha20(operation, &cipher, &input[processed],
					       &output[processed], chunk_size);
			if (status != PSA_SUCCESS) {
				return status;
			}
			processed += chunk_size;
		}
	}
	*output_length = processed;
	gcm_ctx->total_data_enc += processed;
	return status;
}

psa_status_t cracen_sw_chacha20_poly1305_finish(cracen_aead_operation_t *operation, uint8_t *ciphertext,
				      size_t ciphertext_size, size_t *ciphertext_length,
				      uint8_t *tag, size_t tag_size, size_t *tag_length)
{
	struct sxblkcipher cipher;
	psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

	status = initialize_poly_key(operation, &cipher);
	if (status != PSA_SUCCESS) {
		return status;
	}
	// initialize_ctr(operation);

	finalize_ad_padding(operation);
	finalize_data_padding(operation);

	status = generate_tag(operation, tag, &cipher);
	if (status != PSA_SUCCESS) {
		return status;
	}
	*tag_length = operation->tag_size;
	return status;
}

// + for ChaCha
psa_status_t cracen_sw_chacha20_poly1305_verify(cracen_aead_operation_t *operation, uint8_t *plaintext,
				      size_t plaintext_size, size_t *plaintext_length,
				      const uint8_t *tag, size_t tag_length)
{
	struct sxblkcipher cipher;
	psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
	uint8_t computed_tag[CRACEN_POLY1305_TAG_SIZE] = {0};
	uint32_t tag_mismatch = 0;

	status = initialize_poly_key(operation, &cipher);
	if (status != PSA_SUCCESS) {
		return status;
	}
	// initialize_ctr(operation);

	finalize_ad_padding(operation);
	finalize_data_padding(operation);

	status = generate_tag(operation, computed_tag, &cipher);
	if (status != PSA_SUCCESS) {
		goto exit;
	}

	/* Constant-time tag comparison to prevent timing attacks */
	for (size_t i = 0; i < operation->tag_size; i++) {
		tag_mismatch |= computed_tag[i] ^ tag[i];
	}
	if (tag_mismatch != 0) {
		status = PSA_ERROR_INVALID_SIGNATURE;
	}

exit:
	safe_memzero(computed_tag, sizeof(computed_tag));
	return status;
}

// + for ChaCha
psa_status_t cracen_sw_chacha20_poly1305_abort(cracen_aead_operation_t *operation)
{
	safe_memzero(operation, sizeof(*operation));
	return PSA_SUCCESS;
}
