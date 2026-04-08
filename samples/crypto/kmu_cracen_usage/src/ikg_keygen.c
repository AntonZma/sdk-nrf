/*
 * Copyright (c) 2026 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include "ikg_keygen.h"
#include "main.h"

#include <zephyr/device.h>
#include <zephyr/logging/log.h>
#include <zephyr/settings/settings.h>

#include <cracen/common.h>
#include <sxsymcrypt/blkcipher.h>

LOG_MODULE_DECLARE(kmu_cracen_usage, LOG_LEVEL_DBG);

/* ====================================================================== */
/*	Global variables/defines for operations 			  */

#define PRINT_HEX(p_label, p_text, len)                                                            \
	({                                                                                         \
		LOG_INF("---- %s (len: %u): ----", p_label, len);                                  \
		LOG_HEXDUMP_INF(p_text, len, "Content:");                                          \
		LOG_INF("---- %s end  ----", p_label);                                             \
	})

#define NRF_CRYPTO_EXAMPLE_P256_KEY_SIZE (32)
#define NRF_CRYPTO_EXAMPLE_AES_256_KEY_SIZE (32)
#define NRF_CRYPTO_EXAMPLE_INPUT_KEY_SIZE (64)
#define NRF_CRYPTO_SAMPLE_SEED_VALUE_LENGTH (48)

// from NIST CTR_DRBG (no_df, no personalization string) test vector (entropy input)
//
// fc 7f 26 29 c9 d8 86 72
// f8 12 29 bb cc 0c 7e 75
// c4 b7 d8 e5 d9 38 07 02
// ea 52 dc 49 56 00 a5 6e
// 4a e5 f0 a5 c2 5f b5 d7
// e3 1f 5a ef 47 12 bc 19
static uint8_t m_seed_value[NRF_CRYPTO_SAMPLE_SEED_VALUE_LENGTH] = {
	0xfc, 0x7f, 0x26, 0x29, 0xc9, 0xd8, 0x86, 0x72,
	0xf8, 0x12, 0x29, 0xbb, 0xcc, 0x0c, 0x7e, 0x75,
	0xc4, 0xb7, 0xd8, 0xe5, 0xd9, 0x38, 0x07, 0x02,
	0xea, 0x52, 0xdc, 0x49, 0x56, 0x00, 0xa5, 0x6e,
	0x4a, 0xe5, 0xf0, 0xa5, 0xc2, 0x5f, 0xb5, 0xd7,
	0xe3, 0x1f, 0x5a, 0xef, 0x47, 0x12, 0xbc, 0x19
};

#if !defined(NRF_CRYPTO_EXAMPLE_DEMO_ECDSA)
// NOTE: the following buffer is the same as the one in "key_operations.c"
static const uint8_t m_required_plain_text[NRF_CRYPTO_EXAMPLE_KMU_USAGE_KEY_MAX_TEXT_SIZE] = {
	"Example string to demonstrate basic usage of KMU."};

static const uint8_t m_required_ciphertext[NRF_CRYPTO_EXAMPLE_KMU_USAGE_KEY_MAX_TEXT_SIZE] = {
	// for MKEK key
	0xd8, 0x14, 0x63, 0x81, 0x41, 0x4b, 0x4d, 0x46, 0x10, 0x8c, 0xd8, 0x71, 0xa9, 0x7f, 0xae, 0x82,
	0x55, 0x65, 0x4f, 0x0a, 0xb2, 0xd6, 0x8f, 0x73, 0x4c, 0xac, 0x24, 0xef, 0xd8, 0x30, 0x02, 0x8d,
	0xb8, 0x4a, 0x8b, 0xda, 0xf6, 0xf7, 0x77, 0xd4, 0xbd, 0xcc, 0x06, 0x1f, 0xc9, 0x8a, 0x7b, 0xd4,
	0x5c, 0xb0, 0x47, 0xf6, 0xab, 0x83, 0x91, 0x02, 0xe9, 0x4f, 0x93, 0x01, 0x91, 0x27, 0x52, 0x89,
	0x42, 0xad, 0x9e, 0xde, 0xd3, 0xae, 0xf8, 0xb0, 0x53, 0xa7, 0xfa, 0xe3, 0x5f, 0xc6, 0x2f, 0xaf,
	0x42, 0xad, 0x9e, 0xde, 0xd3, 0xae, 0xf8, 0xb0, 0x53, 0xa7, 0xfa, 0xe3, 0x5f, 0xc6, 0x2f, 0xaf,

	// for MEXT key
	// 0x29, 0x94, 0xb4, 0xe4, 0x4b, 0xec, 0x2d, 0x0d, 0x35, 0xe8, 0x58, 0xf5, 0x25, 0xe8, 0x18, 0x0c,
	// 0x21, 0xb3, 0xb1, 0x16, 0x8c, 0x80, 0xda, 0xaa, 0x10, 0x92, 0xcd, 0xd0, 0x72, 0xda, 0xcc, 0x0b,
	// 0xfe, 0x8b, 0x32, 0xf0, 0xf4, 0x12, 0x5b, 0x85, 0x80, 0xff, 0x47, 0xd2, 0xb0, 0xf8, 0x7e, 0x6f,
	// 0x64, 0x48, 0xff, 0x1c, 0x54, 0xe7, 0x46, 0x0e, 0x5f, 0x17, 0xc8, 0xb8, 0xf2, 0xf5, 0x72, 0x92,
	// 0x45, 0xcb, 0x7e, 0x55, 0x0a, 0xe3, 0x75, 0x1c, 0x73, 0x4a, 0x52, 0x25, 0xac, 0x3f, 0x60, 0x01,
	// 0x45, 0xcb, 0x7e, 0x55, 0x0a, 0xe3, 0x75, 0x1c, 0x73, 0x4a, 0x52, 0x25, 0xac, 0x3f, 0x60, 0x01,
};
#endif /* NRF_CRYPTO_EXAMPLE_DEMO_ECDSA */

static psa_key_id_t output_key_id;

#ifdef CONFIG_CRACEN_HW_VERSION_LITE
#define MAX_BITS_PER_REQUEST (1 << 16) /* Cracen Lite only supports 2^16 ctr size */
/* Cracen Lite only supports 2^16 ctr size so will need to reseed before it overflows */
#define RESEED_INTERVAL ((uint64_t)1 << 16)
#else
#define MAX_BITS_PER_REQUEST (1 << 19) /* NIST.SP.800-90Ar1:Table 3 */
#define RESEED_INTERVAL ((uint64_t)1 << 48) /* 2^48 as per NIST spec */
#endif

/* IAR Doesn't support aligned stack variables */
#define ALIGN_UP(value, alignment) \
  (((value) + (alignment) - 1) & ~((alignment) - 1))

#ifdef __IAR_SYSTEMS_ICC__
#define ALIGN_ON_STACK(type, var, size, alignment)                    \
  type var##base[(size) + ((alignment)/sizeof(type))]; \
  type * var = (type *)ALIGN_UP((intptr_t)var##base, alignment)
#else
#define ALIGN_ON_STACK(type, var, size, alignment)                    \
  type var[size] __attribute__((aligned(alignment)));
#endif

#define CRACEN_ENTROPY_AND_NONCE_SIZE (CRACEN_PRNG_ENTROPY_SIZE + CRACEN_PRNG_NONCE_SIZE)

static cracen_prng_context_t prng;
/* ====================================================================== */

static void reverse_bytes(uint8_t *data, size_t len)
{
	size_t i = 0;
	size_t j = len - 1;

	while (i < j) {
		uint8_t tmp = data[i];
		data[i] = data[j];
		data[j] = tmp;
		i++;
		j--;
	}
}

/**
 *  Implementation of the CTR_DRBG_Update process as described in NIST.SP.800-90Ar1
 *  with ctr_len equal to blocklen.
 * 
 *  Note: this function is mainly taken from "cracen_psa_ctr_drbg.c"
 * 
 *  data is expected to be the entropy (SEED) buffer
 */
static psa_status_t ctr_drbg_update(uint8_t *seed)
{
	psa_status_t status = PSA_SUCCESS;

	ALIGN_ON_STACK(uint8_t, temp, CRACEN_ENTROPY_AND_NONCE_SIZE, CONFIG_DCACHE_LINE_SIZE);

	size_t temp_length = 0;
	_Static_assert(CRACEN_ENTROPY_AND_NONCE_SIZE % SX_BLKCIPHER_AES_BLK_SZ == 0, "");

	while (temp_length < CRACEN_ENTROPY_AND_NONCE_SIZE) {

		cracen_be_add(prng.V, SX_BLKCIPHER_AES_BLK_SZ, 1);
		status = sx_blkcipher_ecb_simple(prng.key, sizeof(prng.key), prng.V, sizeof(prng.V),
						 temp + temp_length, SX_BLKCIPHER_AES_BLK_SZ);

		if (status != PSA_SUCCESS) {
			return status;
		}
		temp_length += SX_BLKCIPHER_AES_BLK_SZ;
		prng.reseed_counter++;
	}

	if (seed) {
		cracen_xorbytes(temp, seed, CRACEN_ENTROPY_AND_NONCE_SIZE);
	}

	memcpy(prng.key, temp, sizeof(prng.key));
	memcpy(prng.V, temp + sizeof(prng.key), sizeof(prng.V));

	// PRINT_HEX("Key", prng.key, sizeof(prng.key));
	// PRINT_HEX("V", prng.V, sizeof(prng.V));

	return status;
}

/**
 * @brief Implementation is taken from "cracen_get_random()"
 *
 * @param output 
 * @param output_size 
 * @return 
 */
static psa_status_t ctr_drbg_generate(uint8_t *output, size_t output_size)
{
	psa_status_t status = PSA_SUCCESS;
	size_t len_left = output_size;
	size_t number_of_blocks = DIV_ROUND_UP(output_size, SX_BLKCIPHER_AES_BLK_SZ);

	if (output_size > 0 && output == NULL) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}

	if (output_size > PSA_BITS_TO_BYTES(MAX_BITS_PER_REQUEST)) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}

	// nrf_security_mutex_lock(cracen_prng_trng_mutex);

	// if (prng.reseed_counter == 0) {
	// 	/* Zephyr mutexes allow the same thread to lock a
	// 	 * mutex multiple times. So we can call cracen_init_random
	// 	 * here even though we hold the mutex.
	// 	 */
	// 	status = cracen_init_random(context);
	// 	if (status != PSA_SUCCESS) {
	// 		// nrf_security_mutex_unlock(cracen_prng_trng_mutex);
	// 		return status;
	// 	}
	// }

	// if (prng.reseed_counter + number_of_blocks >= RESEED_INTERVAL) {
	// 	status = cracen_reseed();
	// 	if (status != PSA_SUCCESS) {
	// 		// nrf_security_mutex_unlock(cracen_prng_trng_mutex);
	// 		return status;
	// 	}
	// }

	while (len_left > 0) {
		size_t cur_len = MIN(len_left, SX_BLKCIPHER_AES_BLK_SZ);
		ALIGN_ON_STACK(uint8_t, temp, SX_BLKCIPHER_AES_BLK_SZ, CONFIG_DCACHE_LINE_SIZE);

		cracen_be_add(prng.V, SX_BLKCIPHER_AES_BLK_SZ, 1);
		status = sx_blkcipher_ecb_simple(prng.key, sizeof(prng.key), prng.V, sizeof(prng.V),
						 temp, SX_BLKCIPHER_AES_BLK_SZ);

		if (status != PSA_SUCCESS) {
			// nrf_security_mutex_unlock(cracen_prng_trng_mutex);
			return status;
		}

		for (int i = 0; i < cur_len; i++) {
			output[i] = temp[i];
		}

		len_left -= cur_len;
		output += cur_len;
		prng.reseed_counter++;
	}

	status = ctr_drbg_update(NULL);
	// nrf_security_mutex_unlock(cracen_prng_trng_mutex);
	return status;
}

#if !defined(NRF_CRYPTO_EXAMPLE_DEMO_ECDSA)
static bool check_aes_key(psa_key_id_t *key_id)
{
	bool ciphertext_match = false;
	uint32_t olen;
	psa_status_t status;

	psa_algorithm_t alg = PSA_ALG_ECB_NO_PADDING;

	uint8_t encrypted_text[PSA_CIPHER_ENCRYPT_OUTPUT_SIZE(
		PSA_KEY_TYPE_AES, alg, NRF_CRYPTO_EXAMPLE_KMU_USAGE_KEY_MAX_TEXT_SIZE)];
	uint8_t decrypted_text[NRF_CRYPTO_EXAMPLE_KMU_USAGE_KEY_MAX_TEXT_SIZE];

	status = psa_cipher_encrypt(*key_id, alg, m_required_plain_text, sizeof(m_required_plain_text),
				    encrypted_text, sizeof(encrypted_text), &olen);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_cipher_encrypt failed! (Error: %d)", status);
		return false;
	}

	PRINT_HEX("Encrypted text", encrypted_text, sizeof(encrypted_text));

	/* Check the validity of the decryption */
	ciphertext_match = memcmp(encrypted_text, m_required_ciphertext, olen) == 0;

	return ciphertext_match;
}
#endif /* NRF_CRYPTO_EXAMPLE_DEMO_ECDSA */

void demo_ikg_keygen()
{
	psa_status_t status;
	uint8_t gen_key[NRF_CRYPTO_EXAMPLE_AES_256_KEY_SIZE];
	bool key_found = false;
	psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;

	reverse_bytes(m_seed_value, sizeof(m_seed_value));

	/* Instantiate */
	status = ctr_drbg_update(m_seed_value);
	if (status != PSA_SUCCESS) {
		LOG_INF("ctr_drbg_update failed! (Error: %d)", status);
		return;
	}

#if !defined(NRF_CRYPTO_EXAMPLE_DEMO_ECDSA)

	/* Configure the input key attributes */
	psa_set_key_lifetime(&key_attributes, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_type(&key_attributes, PSA_KEY_TYPE_AES);
	psa_set_key_algorithm(&key_attributes, PSA_ALG_ECB_NO_PADDING);
	psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT | PSA_KEY_USAGE_EXPORT);
	psa_set_key_bits(&key_attributes, 256);

	/* Generating keys from SEED */
	for (uint32_t i = 0; i < 3; i++) {
		status = ctr_drbg_generate(gen_key, NRF_CRYPTO_EXAMPLE_AES_256_KEY_SIZE);
		if (status != PSA_SUCCESS) {
			LOG_INF("ctr_drbg_generate failed! (Error: %d, counter: %d)", status, i);
			return;
		}
		// PRINT_HEX("gen_key (cntr)", gen_key, NRF_CRYPTO_EXAMPLE_AES_256_KEY_SIZE);

		/* Import the master key into the keystore */
		status = psa_import_key(&key_attributes,
					gen_key,
					NRF_CRYPTO_EXAMPLE_AES_256_KEY_SIZE,
					&output_key_id);
		if (status != PSA_SUCCESS) {
			LOG_INF("psa_import_key failed! (Error: %d)", status);
			return;
		}

		safe_memzero(gen_key, NRF_CRYPTO_EXAMPLE_AES_256_KEY_SIZE);

		key_found = check_aes_key(&output_key_id);
		if (key_found) {
			break;
		}

		psa_destroy_key(output_key_id);
	}

	LOG_WRN("Key is %sfound", key_found ? "" : "NOT ");
#else
	/* Configure the input key attributes */
	psa_set_key_lifetime(&key_attributes, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_type(&key_attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_algorithm(&key_attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
	psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_SIGN_HASH |
						 PSA_KEY_USAGE_VERIFY_MESSAGE| PSA_KEY_USAGE_VERIFY_HASH |
						 PSA_KEY_USAGE_EXPORT);
	psa_set_key_bits(&key_attributes, 256);

	/* Generating symmetric keys from SEED */
	for (uint32_t i = 0; i < 2; i++) { /* IKG generates 2 symmetric keys */
		status = ctr_drbg_generate(gen_key, NRF_CRYPTO_EXAMPLE_AES_256_KEY_SIZE);
		if (status != PSA_SUCCESS) {
			LOG_INF("ctr_drbg_generate failed! (Error: %d, counter: %d)", status, i);
			return;
		}
	}

	/** ECC curve for IKG is P256.
	 *  CRACEN generates just a single one.
	 */
	status = ctr_drbg_generate(gen_key, NRF_CRYPTO_EXAMPLE_P256_KEY_SIZE);
	if (status != PSA_SUCCESS) {
		LOG_INF("ctr_drbg_generate failed (P256)! (Error: %d)", status);
		return;
	}

	/* Import the master key into the keystore */
	status = psa_import_key(&key_attributes,
				gen_key,
				NRF_CRYPTO_EXAMPLE_P256_KEY_SIZE,
				&output_key_id);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_import_key failed! (Error: %d)", status);
		return;
	}

	/* NOTE: Public keys must be equal for key taken from the KMU and output_key_id */
	key_operations_use_ecdsa_key_pair(&output_key_id);

#endif /* NRF_CRYPTO_EXAMPLE_DEMO_ECDSA */
}
