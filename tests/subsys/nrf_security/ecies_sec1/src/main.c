/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <zephyr/kernel.h>
#include <zephyr/ztest.h>
#include <stdio.h>
#include <psa/crypto.h>
#include <psa/crypto_extra.h>
#include <cracen/mem_helpers.h>

#define ED25519_KEY_PAIR_SIZE		(32u)
#define ECIES_SEC1_TEST_CIPHERTEXT_SIZE	(PSA_EXPORT_PUBLIC_KEY_MAX_SIZE)
#define ECIES_SEC1_TEST_SHARED_KEY_SIZE	(16u)

/* RFC8410, example of ED25519 private key */
static const uint8_t ed25519_key[ED25519_KEY_PAIR_SIZE] = {
	0xD4, 0xEE, 0x72, 0xDB, 0xF9, 0x13, 0x58, 0x4A,
	0xD5, 0xB6, 0xD8, 0xF1, 0xF7, 0x69, 0xF8, 0xAD,
	0x3A, 0xFE, 0x7C, 0x28, 0xCB, 0xF1, 0xD4, 0xFB,
	0xE0, 0x97, 0xA8, 0x8F, 0x44, 0x75, 0x58, 0x42};

static uint8_t pub_key[PSA_EXPORT_PUBLIC_KEY_OUTPUT_SIZE(
				PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY),
				PSA_BYTES_TO_BITS(sizeof(ed25519_key)))];
static size_t pub_key_len;

static uint8_t ciphertext[ECIES_SEC1_TEST_CIPHERTEXT_SIZE];
static size_t ciphertext_size;

static psa_key_id_t key_pair_id;
static psa_key_id_t pub_key_id;
static psa_key_id_t shared_key_id;

void crypto_init(void)
{
	psa_status_t status;

	/* Initialize PSA Crypto */
	status = psa_crypto_init();
	zassert_equal(status, PSA_SUCCESS, "psa_crypto_init failed! Err: %d", status);
}

void import_keypair(void)
{
	psa_status_t status;
	psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;

	psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_DECRYPT | PSA_KEY_USAGE_EXPORT);
	psa_set_key_lifetime(&key_attributes, PSA_KEY_LIFETIME_VOLATILE);

	// psa_set_key_algorithm(&key_attributes, PSA_ALG_ECIES_SEC1); /* Note: this algorithm is not supported */
	psa_set_key_algorithm(&key_attributes, PSA_ALG_PURE_EDDSA);

	psa_set_key_type(&key_attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));

	status = psa_import_key(&key_attributes, ed25519_key, sizeof(ed25519_key), &key_pair_id);
	zassert_equal(status, PSA_SUCCESS, "psa_import_key (key pair) failed! Err: %d", status);

	psa_reset_key_attributes(&key_attributes);
}

void prepare_public_key()
{
	psa_status_t status;
	psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;

	status = psa_export_public_key(key_pair_id, pub_key, sizeof(pub_key), &pub_key_len);
	zassert_equal(status, PSA_SUCCESS, "psa_export_public_key failed! Err: %d", status);

	psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_ENCRYPT);
	psa_set_key_lifetime(&key_attributes, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_algorithm(&key_attributes, PSA_ALG_PURE_EDDSA);
	psa_set_key_type(&key_attributes, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_MONTGOMERY));

	status = psa_import_key(&key_attributes, pub_key, pub_key_len, &pub_key_id);
	zassert_equal(status, PSA_SUCCESS, "psa_import_key (public key) failed! Err: %d", status);

	psa_reset_key_attributes(&key_attributes);
}

void test_encapsulate_decapsulate()
{
	psa_status_t status;
	psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;
	uint8_t shared_key_1[ECIES_SEC1_TEST_SHARED_KEY_SIZE];
	size_t shared_key_1_size;
	uint8_t shared_key_2[ECIES_SEC1_TEST_SHARED_KEY_SIZE];
	size_t shared_key_2_size;

	status = psa_export_public_key(key_pair_id, pub_key, sizeof(pub_key), &pub_key_len);
	zassert_equal(status, PSA_SUCCESS, "psa_export_public_key failed! Err: %d", status);

	psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_EXPORT);
	psa_set_key_lifetime(&key_attributes, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_algorithm(&key_attributes, PSA_ALG_CCM);
	psa_set_key_type(&key_attributes, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&key_attributes, 0);

	/* TODO: make use of PSA_ALG_ECIES_SEC1 */
	status = psa_encapsulate(pub_key_id, PSA_ALG_ML_KEM, &key_attributes, &shared_key_id,
				 ciphertext, sizeof(ciphertext), &ciphertext_size);
	zassert_equal(status, PSA_SUCCESS, "psa_encapsulate failed! Err: %d", status);

	status = psa_export_key(shared_key_id, shared_key_1, sizeof(shared_key_1), &shared_key_1_size);
	zassert_equal(status, PSA_SUCCESS, "psa_export_key (shared key 1) failed! Err: %d", status);

	zassert_equal(shared_key_1_size, ECIES_SEC1_TEST_SHARED_KEY_SIZE,
		      "Size of calculated shared secret 1 is wrong. Expected %d, got %d",
		      ECIES_SEC1_TEST_SHARED_KEY_SIZE, shared_key_1_size);

	/* Destroy shared key to be able to reuse its ID handle */
	status = psa_destroy_key(shared_key_id);
	zassert_equal(status, PSA_SUCCESS,
		      "psa_destroy_key (shared key 1) failed! Err: %d", status);

	/* TODO: make use of PSA_ALG_ECIES_SEC1 */
	status = psa_decapsulate(key_pair_id, PSA_ALG_ML_KEM, ciphertext, ciphertext_size,
				 &key_attributes, &shared_key_id);
	zassert_equal(status, PSA_SUCCESS, "psa_decapsulate failed! Err: %d", status);

	status = psa_export_key(shared_key_id, shared_key_2,
				sizeof(shared_key_2), &shared_key_2_size);
	zassert_equal(status, PSA_SUCCESS, "psa_export_key (shared key 2) failed! Err: %d", status);

	psa_reset_key_attributes(&key_attributes);

	zassert_equal(shared_key_1_size, shared_key_2_size,
		      "Sizes of calculated shared secrets mismatch. Expected %d, got %d",
		      shared_key_1_size, shared_key_2_size);

	if (constant_memcmp(shared_key_1, shared_key_2, shared_key_1_size) != 0) {
		zassert_false(true, "Shared secret values mismatch");
	}
}

void crypto_finish()
{
	psa_status_t status;

	status = psa_destroy_key(key_pair_id);
	zassert_equal(status, PSA_SUCCESS, "psa_destroy_key (key_pair_id) failed! Err: %d", status);

	status = psa_destroy_key(pub_key_id);
	zassert_equal(status, PSA_SUCCESS, "psa_destroy_key (pub_key_id) failed! Err: %d", status);

	status = psa_destroy_key(shared_key_id);
	zassert_equal(status, PSA_SUCCESS,
		      "psa_destroy_key (shared_key_id) failed! Err: %d", status);
}

void test_main(void)
{
	crypto_init();
	import_keypair();
	prepare_public_key();

	test_encapsulate_decapsulate();

	crypto_finish();
	zassert_true(true, "");
}
