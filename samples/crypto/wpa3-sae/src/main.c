/*
 * Copyright (c) 2025 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <psa/crypto.h>
#include <stdint.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/util.h>

/** Uncomment the following macro to use looping method (hunt-and-peck) for 
 *  PWE generation.
*/
// #define TEST_HNP

#ifndef TEST_HNP
/** Uncomment the following macro to test PT import via PSA API.
*/
#define TEST_KEY_REIMPORT
#endif /* TEST_HNP */

LOG_MODULE_REGISTER(wpa3_sae, LOG_LEVEL_DBG);

#define PRINT_HEX(p_label, p_text, len)                                                            \
	({                                                                                         \
		LOG_INF("---- %s (len: %u): ----", p_label, len);                                  \
		LOG_HEXDUMP_INF(p_text, len, "Content:");                                          \
		LOG_INF("---- %s end  ----", p_label);                                             \
	})

#define APP_SUCCESS	    (0)
#define APP_ERROR	    (-1)
#define APP_SUCCESS_MESSAGE "Example finished successfully!"
#define APP_ERROR_MESSAGE   "Example exited with error!"

const char *ssid = "byteme";
const char *pwd = "mekmitasdigoat";
const char *pwid = 
#ifndef TEST_KEY_REIMPORT
	NULL;
#else
	"psk4internet";
#endif /* TEST_KEY_REIMPORT */
const uint8_t count = 77;

#ifndef TEST_KEY_REIMPORT
const uint8_t mac[6] = {0x4d, 0x3f, 0x2f, 0xff, 0xe3, 0x87};
const uint8_t peer_mac[6] = {0xa5, 0xd8, 0xaa, 0x95, 0x8e, 0x3c};
#else
const uint8_t mac[6] = {0x00, 0x09, 0x5b, 0x66, 0xec, 0x1e};
const uint8_t peer_mac[6] = {0x00, 0x0b, 0x6b, 0xd9, 0x02, 0x46};
#endif /* TEST_KEY_REIMPORT */

static psa_status_t send_message(psa_pake_operation_t *from, psa_pake_operation_t *to,
				 psa_pake_step_t step)
{
	uint8_t data[1024];
	size_t length;

	psa_status_t status = psa_pake_output(from, step, data, sizeof(data), &length);

	if (status) {
		return status;
	}
	PRINT_HEX("send_message", data, length);
	status = psa_pake_input(to, step, data, length);
	return status;
}

static psa_status_t sae_endpoint_setup(psa_pake_operation_t *op, psa_pake_role_t role, psa_key_id_t key,
			       psa_pake_cipher_suite_t *cipher_suite)
{
	psa_status_t status;

	status = psa_pake_setup(op, key, cipher_suite);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_pake_setup failed. (Error: %d)", status);
		return status;
	}

	if (role == PSA_PAKE_ROLE_SERVER) {
		status = psa_pake_set_user(op, mac, sizeof(mac));
		if (status != PSA_SUCCESS) {
			LOG_INF("psa_pake_set_user failed. (Error: %d)", status);
			return status;
		}

		status = psa_pake_set_peer(op, peer_mac, sizeof(peer_mac));
		if (status != PSA_SUCCESS) {
			LOG_INF("psa_pake_set_peer failed. (Error: %d)", status);
			return status;
		}
	} else {
		status = psa_pake_set_user(op, peer_mac, sizeof(peer_mac));
		if (status != PSA_SUCCESS) {
			LOG_INF("psa_pake_set_user failed. (Error: %d)", status);
			return status;
		}

		status = psa_pake_set_peer(op, mac, sizeof(mac));
		if (status != PSA_SUCCESS) {
			LOG_INF("psa_pake_set_peer failed. (Error: %d)", status);
			return status;
		}
	}

	return status;
}

int main(void)
{
	/* Different alg variations possible (e.g PSA_ALG_WPA3_SAE_GDH(PSA_ALG_SHA_256)) */
	psa_algorithm_t alg = PSA_ALG_WPA3_SAE_FIXED(PSA_ALG_SHA_256);
	psa_status_t status = psa_crypto_init();

	if (status != PSA_SUCCESS) {
		LOG_INF("psa_crypto_init failed. (Error: %d)", status);
	}

	psa_pake_cipher_suite_t cipher_suite = PSA_PAKE_CIPHER_SUITE_INIT;

	psa_pake_cs_set_algorithm(&cipher_suite, alg);
	psa_pake_cs_set_primitive(&cipher_suite, PSA_PAKE_PRIMITIVE(PSA_PAKE_PRIMITIVE_TYPE_ECC,
								    PSA_ECC_FAMILY_SECP_R1, 256));

	psa_key_derivation_operation_t kdf = PSA_KEY_DERIVATION_OPERATION_INIT;
	psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;

	psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_DERIVE);
	psa_set_key_type(&key_attributes, PSA_KEY_TYPE_PASSWORD);

	psa_key_id_t ekey;

#ifndef TEST_HNP
	/* Using H2E */
	psa_set_key_algorithm(&key_attributes, PSA_ALG_WPA3_SAE_H2E(PSA_ALG_SHA_256));

	psa_key_id_t key;

	status = psa_import_key(&key_attributes, (const uint8_t*)pwd, strlen(pwd), &key);
	if (status != PSA_SUCCESS) {
		LOG_INF("Key pair psa_import_key failed. (Error: %d)", status);
		goto error;
	}

	status = psa_key_derivation_setup(&kdf, PSA_ALG_WPA3_SAE_H2E(PSA_ALG_SHA_256));
	if (status != PSA_SUCCESS) {
		LOG_ERR("psa_key_derivation_setup failed. (Error: %d)", status);
		goto error;
	}

        status = psa_key_derivation_input_bytes(&kdf, PSA_KEY_DERIVATION_INPUT_SALT, (const uint8_t*)ssid, strlen(ssid));
	if (status != PSA_SUCCESS) {
		LOG_ERR("SSID psa_key_derivation_input_bytes failed. (Error: %d)", status);
		goto error;
	}

        status = psa_key_derivation_input_key(&kdf, PSA_KEY_DERIVATION_INPUT_PASSWORD, key);
	if (status != PSA_SUCCESS) {
		LOG_ERR("psa_key_derivation_input_key failed. (Error: %d)", status);
		goto error;
	}

        if (pwid != NULL) {
		status = psa_key_derivation_input_bytes(&kdf, PSA_KEY_DERIVATION_INPUT_INFO, (const uint8_t*)pwid, strlen(pwid));
		if (status != PSA_SUCCESS) {
			LOG_ERR("PWID psa_key_derivation_input_bytes failed. (Error: %d)", status);
			goto error;
		}
        }
        status = psa_destroy_key(key);
	if (status != PSA_SUCCESS) {
		LOG_ERR("PWD psa_destroy_key failed. (Error: %d)", status);
		goto error;
	}

#ifdef TEST_KEY_REIMPORT
	psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
#else
	psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_DERIVE);
#endif /* TEST_KEY_REIMPORT */

	psa_set_key_algorithm(&key_attributes, alg);
	psa_set_key_type(&key_attributes, PSA_KEY_TYPE_WPA3_SAE_ECC_PT(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&key_attributes, 256);

	status = psa_key_derivation_output_key(&key_attributes, &kdf, &ekey);
	if (status != PSA_SUCCESS) {
		LOG_ERR("psa_key_derivation_output_key failed (for PWD). (Error: %d)", status);
		goto error;
	}

#ifdef TEST_KEY_REIMPORT
	size_t exp_key_length;
	uint8_t data[64] = {};

	status = psa_export_key(ekey, data, sizeof(data), &exp_key_length);
	if (status != PSA_SUCCESS) {
		LOG_ERR("psa_export_key failed (for PWD). (Error: %d)", status);
		goto error;
	}

	PRINT_HEX("derived key (export)", data, exp_key_length);

	status = psa_destroy_key(ekey);
	if (status != PSA_SUCCESS) {
		LOG_ERR("psa_destroy_key failed (ekey). (Error: %d)", status);
		goto error;
	}

	status = psa_import_key(&key_attributes, data, exp_key_length, &ekey);
	if (status != PSA_SUCCESS) {
		LOG_ERR("psa_import_key failed (ekey). (Error: %d)", status);
		goto error;
	}
#endif /* TEST_KEY_REIMPORT */

	psa_key_derivation_abort(&kdf);
#else
	/* Using basic SAE */
        psa_set_key_algorithm(&key_attributes, alg);
        status = psa_import_key(&key_attributes, (const uint8_t*)pwd, strlen(pwd), &ekey);
#endif /* TEST_HNP */

	psa_reset_key_attributes(&key_attributes);

	psa_pake_operation_t local = PSA_PAKE_OPERATION_INIT;

	status = sae_endpoint_setup(&local, PSA_PAKE_ROLE_CLIENT, ekey, &cipher_suite);
	if (status != PSA_SUCCESS) {
		goto error;
	}

	psa_pake_operation_t peer = PSA_PAKE_OPERATION_INIT;

	status = sae_endpoint_setup(&peer, PSA_PAKE_ROLE_SERVER, ekey, &cipher_suite);
	if (status != PSA_SUCCESS) {
		goto error;
	}
	
	status = send_message(&local, &peer, PSA_PAKE_STEP_COMMIT);
	if (status != PSA_SUCCESS) {
		LOG_INF("send_message failed. (Error: %d, step: %d)", status,
			PSA_PAKE_STEP_COMMIT);
		goto error;
	}
	
	status = send_message(&peer, &local, PSA_PAKE_STEP_COMMIT);
	if (status != PSA_SUCCESS) {
		LOG_INF("send_message failed. (Error: %d, step: %d)", status,
			PSA_PAKE_STEP_COMMIT);
		goto error;
	}

	/**
	 * If the Hash-To-Element variant is used and a list of rejected groups
 	 * is available, it must be provided as a salt:
	 */
	/* Commented out since there is no salt now (WPA3-SAE) */
	// if (salt_len) {
	// 	// set salt
	// 	status = psa_pake_input(&local, PSA_PAKE_STEP_SALT, salt, salt_len);
	// 	if (status != PSA_SUCCESS) {
	// 		LOG_INF("Failed to set set salt for local. (Error: %d)", status);
	// 		goto error;
	// 	}

	// 	status = psa_pake_input(&peer, PSA_PAKE_STEP_SALT, salt, salt_len);
	// 	if (status != PSA_SUCCESS) {
	// 		LOG_INF("Failed to set set salt for peer. (Error: %d)", status);
	// 		goto error;
	// 	}
	// }

	/* set send-confirm counter */
	uint8_t send_count[2];
	send_count[0] = (uint8_t)count;
	send_count[1] = (uint8_t)(count >> 8);

	status = psa_pake_input(&local, PSA_PAKE_STEP_SEND_CONFIRM, send_count, 2);
	if (status != PSA_SUCCESS) {
		LOG_INF("Failed to set send-configrm counter for local. (Error: %d)", status);
		goto error;
	}
        status = psa_pake_input(&peer, PSA_PAKE_STEP_SEND_CONFIRM, send_count, 2);
	if (status != PSA_SUCCESS) {
		LOG_INF("Failed to set send-configrm counter for peer. (Error: %d)", status);
		goto error;
	}
	
	status = send_message(&peer, &local, PSA_PAKE_STEP_CONFIRM);
	if (status != PSA_SUCCESS) {
		LOG_INF("send_message failed. (Error: %d, step: %d)", status,
			PSA_PAKE_STEP_CONFIRM);
		goto error;
	}

	
	status = send_message(&local, &peer, PSA_PAKE_STEP_CONFIRM);
	if (status != PSA_SUCCESS) {
		LOG_INF("send_message failed. (Error: %d, step: %d)", status,
			PSA_PAKE_STEP_CONFIRM);
		goto error;
	}

	uint8_t client_secret[32] = {0};
	uint8_t server_secret[32] = {0};

	psa_set_key_type(&key_attributes, PSA_KEY_TYPE_DERIVE);
	psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_DERIVE);
	psa_set_key_algorithm(&key_attributes, PSA_ALG_HKDF(PSA_ALG_SHA_256));

	struct {
		psa_pake_operation_t *op;
		uint8_t *secret;
	} client_server[] = {{&local, client_secret}, {&peer, server_secret}};

	for (size_t i = 0; i < ARRAY_SIZE(client_server); i++) {
		psa_key_id_t key;

		status = psa_pake_get_shared_key(client_server[i].op, &key_attributes, &key);
		if (status != PSA_SUCCESS) {
			LOG_INF("psa_pake_get_shared_key failed. (Error: %d)", status);
			goto error;
		}

		status = psa_key_derivation_setup(&kdf, PSA_ALG_HKDF(PSA_ALG_SHA_256));
		if (status != PSA_SUCCESS) {
			LOG_INF("psa_key_derivation_setup failed. (Error: %d)", status);
			goto error;
		}

		status = psa_key_derivation_input_key(&kdf, PSA_KEY_DERIVATION_INPUT_SECRET, key);
		if (status != PSA_SUCCESS) {
			LOG_INF("psa_key_derivation_input_key failed. (Error: %d)", status);
			goto error;
		}

		status = psa_key_derivation_input_bytes(&kdf, PSA_KEY_DERIVATION_INPUT_INFO, "Info",
							4);
		if (status != PSA_SUCCESS) {
			LOG_INF("psa_key_derivation_input_bytes failed. (Error: %d)", status);
			goto error;
		}

		status = psa_key_derivation_output_bytes(&kdf, client_server[i].secret,
							 sizeof(client_secret));
		if (status != PSA_SUCCESS) {
			LOG_INF("psa_key_derivation_output_bytes failed. (Error: %d)", status);
			goto error;
		}

		status = psa_key_derivation_abort(&kdf);
		if (status != PSA_SUCCESS) {
			LOG_INF("psa_key_derivation_abort failed. (Error: %d)", status);
			goto error;
		}

		status = psa_destroy_key(key);
		if (status != PSA_SUCCESS) {
			LOG_INF("psa_destroy_key failed. (Error: %d)", status);
			goto error;
		}
	}

	psa_reset_key_attributes(&key_attributes);
	PRINT_HEX("server_secret", client_secret, sizeof(client_secret));
	PRINT_HEX("client_secret", server_secret, sizeof(server_secret));

	bool compare_eq = true;

	for (size_t i = 0; i < sizeof(server_secret); i++) {
		if (server_secret[i] != client_secret[i]) {
			compare_eq = false;
		}
	}

	if (!compare_eq) {
		LOG_ERR("Derived keys for server and client are not equal.");
		goto error;
	}

	LOG_INF(APP_SUCCESS_MESSAGE);
	return APP_SUCCESS;

error:
	LOG_INF(APP_ERROR_MESSAGE);
	return APP_ERROR;
}
