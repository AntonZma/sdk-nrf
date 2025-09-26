/*
 * Copyright (c) 2025 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/logging/log.h>
#include <stdio.h>
#include <psa/crypto.h>
#include <psa/crypto_extra.h>

#include <cracen_psa_kmu.h>

#ifdef CONFIG_BUILD_WITH_TFM
#include <tfm_ns_interface.h>
#endif

#include "init.h"

#define APP_SUCCESS	    (0)
#define APP_ERROR	    (-1)
#define APP_SUCCESS_MESSAGE "Example finished successfully!"
#define APP_ERROR_MESSAGE   "Example exited with error!"

#define PRINT_HEX(p_label, p_text, len)                                                            \
	({                                                                                         \
		LOG_INF("---- %s (len: %u): ----", p_label, len);                                  \
		LOG_HEXDUMP_INF(p_text, len, "Content:");                                          \
		LOG_INF("---- %s end  ----", p_label);                                             \
	})

LOG_MODULE_REGISTER(kmu_usage_nrf54l, LOG_LEVEL_DBG);

/* ====================================================================== */
/*			Global variables/defines for the KMU usage example	  		  */

/* The slot id for the KMU key. The macros PSA_KEY_ID_USER_MIN and
 * PSA_KEY_ID_USER_MAX define the range of freely available key slot ids.
 */
#define SAMPLE_KMU_SLOT_ID			       PSA_KEY_ID_USER_MIN
#define SAMPLE_KEY_TYPE				       PSA_KEY_TYPE_AES
#define SAMPLE_ALG				       PSA_ALG_CTR
#define SAMPLE_KMU_USAGE_SCHEME			       CRACEN_KMU_KEY_USAGE_SCHEME_RAW
#define NRF_CRYPTO_EXAMPLE_KMU_USAGE_KEY_MAX_TEXT_SIZE (100)

static psa_key_id_t key_id;

/* Below text is used as plaintext for encryption/decryption */
static uint8_t m_plain_text[NRF_CRYPTO_EXAMPLE_KMU_USAGE_KEY_MAX_TEXT_SIZE] = {
	"Example string to demonstrate basic usage of KMU."};

static uint8_t m_encrypted_text[PSA_CIPHER_ENCRYPT_OUTPUT_SIZE(
	SAMPLE_KEY_TYPE, SAMPLE_ALG, NRF_CRYPTO_EXAMPLE_KMU_USAGE_KEY_MAX_TEXT_SIZE)];
static uint8_t m_decrypted_text[NRF_CRYPTO_EXAMPLE_KMU_USAGE_KEY_MAX_TEXT_SIZE];
/* ====================================================================== */

int crypto_init(void)
{
	psa_status_t status;

#if	defined(CONFIG_TRUSTED_STORAGE_BACKEND_AEAD_KEY_DERIVE_FROM_HUK) || \
	defined(CONFIG_SECURE_STORAGE_ITS_TRANSFORM_AEAD_KEY_PROVIDER_HUK_LIBRARY)
	write_huk();
#endif

	/* Initialize PSA Crypto */
	status = psa_crypto_init();
	if (status != PSA_SUCCESS) {
		return APP_ERROR;
	}

	return APP_SUCCESS;
}

int crypto_finish(void)
{
	psa_status_t status;

	/* Destroy the key handle */
	status = psa_destroy_key(key_id);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_destroy_key failed! (Error: %d)", status);
		return APP_ERROR;
	}

	return APP_SUCCESS;
}

int generate_kmu_key(void)
{
	psa_status_t status;

	LOG_INF("Generating random AES key...");

	/* Configure the key attributes */
	psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;

	psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
	psa_set_key_algorithm(&key_attributes, SAMPLE_ALG);
	psa_set_key_type(&key_attributes, SAMPLE_KEY_TYPE);
	psa_set_key_bits(&key_attributes, 128);

	key_id = PSA_KEY_HANDLE_FROM_CRACEN_KMU_SLOT(SAMPLE_KMU_USAGE_SCHEME, SAMPLE_KMU_SLOT_ID);

	/* Persistent key specific settings */
	psa_set_key_lifetime(&key_attributes,
			     PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(
				     PSA_KEY_PERSISTENCE_DEFAULT, PSA_KEY_LOCATION_CRACEN_KMU));
	psa_set_key_id(&key_attributes, key_id);

	/* Generate a random AES key with persistent lifetime. The key can be used for
	 * encryption/decryption using the key_id.
	 * The key itself will be stored to the KMU peripheral.
	 */
	status = psa_generate_key(&key_attributes, &key_id);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_generate_key failed! (Error: %d)", status);
		return APP_ERROR;
	}

	/* Make sure the key metadata is not in memory anymore,
	 * has the same affect then resetting the device
	 */
	status = psa_purge_key(key_id);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_purge_key failed! (Error: %d)", status);
		return APP_ERROR;
	}

	/* After the key handle is acquired the attributes are not needed */
	psa_reset_key_attributes(&key_attributes);

	LOG_INF("A key generated successfully!");

	return APP_SUCCESS;
}

int use_kmu_key(void)
{
	uint32_t olen;
	psa_status_t status;

	status = psa_cipher_encrypt(key_id, SAMPLE_ALG, m_plain_text,
				    sizeof(m_plain_text), m_encrypted_text,
				    sizeof(m_encrypted_text), &olen);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_cipher_encrypt failed! (Error: %d)", status);
		return APP_ERROR;
	}

	LOG_INF("Encryption successful!");
	PRINT_HEX("Plaintext", m_plain_text, sizeof(m_plain_text));
	PRINT_HEX("Encrypted text", m_encrypted_text, sizeof(m_encrypted_text));

	status = psa_cipher_decrypt(key_id, SAMPLE_ALG, m_encrypted_text,
				    sizeof(m_encrypted_text), m_decrypted_text,
				    sizeof(m_decrypted_text), &olen);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_cipher_decrypt failed! (Error: %d)", status);
		return APP_ERROR;
	}

	PRINT_HEX("Decrypted text", m_decrypted_text, sizeof(m_decrypted_text));

	/* Check the validity of the decryption */
	if (memcmp(m_decrypted_text, m_plain_text,
		   NRF_CRYPTO_EXAMPLE_KMU_USAGE_KEY_MAX_TEXT_SIZE) != 0) {
		LOG_INF("Error: Decrypted text doesn't match the plaintext");
		return APP_ERROR;
	}

	LOG_INF("Decryption successful!");

	return APP_SUCCESS;
}

int main(void)
{
	int status;

	LOG_INF("Starting KMU usage example...");

	status = crypto_init();
	if (status != APP_SUCCESS) {
		LOG_INF(APP_ERROR_MESSAGE);
		return APP_ERROR;
	}

	status = generate_kmu_key();
	if (status != APP_SUCCESS) {
		LOG_INF(APP_ERROR_MESSAGE);
		return APP_ERROR;
	}

	status = use_kmu_key();
	if (status != APP_SUCCESS) {
		LOG_INF(APP_ERROR_MESSAGE);
		return APP_ERROR;
	}

	status = crypto_finish();
	if (status != APP_SUCCESS) {
		LOG_INF(APP_ERROR_MESSAGE);
		return APP_ERROR;
	}

	LOG_INF(APP_SUCCESS_MESSAGE);

	return APP_SUCCESS;
}
