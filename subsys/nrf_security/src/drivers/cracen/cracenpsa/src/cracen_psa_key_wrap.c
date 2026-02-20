/*
 * Copyright (c) 2026 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <cracen_psa_key_wrap.h>
#include <cracen_psa_primitives.h>

#include <psa/crypto.h>
#include <psa/crypto_extra.h>
#include <psa/crypto_values.h>

#include <cracen/cracen_kmu.h>
#include <internal/key_wrap/cracen_key_wrap_kw.h>
#include <internal/key_wrap/cracen_key_wrap_kwp.h>

psa_status_t cracen_wrap_key(const psa_key_attributes_t *wrapping_key_attributes,
			     const uint8_t *wrapping_key_data, size_t wrapping_key_size,
			     psa_algorithm_t alg,
			     const psa_key_attributes_t *key_attributes,
			     const uint8_t *key_data, size_t key_size,
			     uint8_t *data, size_t data_size, size_t *data_length)
{
	psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

#if defined(PSA_NEED_CRACEN_KMU_DRIVER)
	uint8_t exported_key[CRACEN_KMU_MAX_KEY_SIZE];
	size_t exported_key_length;

	psa_key_location_t key_location =
		PSA_KEY_LIFETIME_GET_LOCATION(psa_get_key_lifetime(key_attributes));

	if (key_location == PSA_KEY_LOCATION_CRACEN_KMU) {
		status = cracen_export_key(key_attributes, key_data, key_size,
					   exported_key, sizeof(exported_key),
					   &exported_key_length);

		if (status != PSA_SUCCESS) {
			goto exit;
		}
		key_data = exported_key;
		key_size = exported_key_length;
	}
#endif /* PSA_NEED_CRACEN_KMU_DRIVER */

	if (IS_ENABLED(PSA_NEED_CRACEN_AES_KW) && alg == PSA_ALG_KW) {
		status = cracen_key_wrap_kw_wrap(wrapping_key_attributes, wrapping_key_data,
						 wrapping_key_size, key_data, key_size, data,
						 data_size, data_length);

	} else if (IS_ENABLED(CONFIG_PSA_NEED_CRACEN_AES_KWP) && alg == PSA_ALG_KWP) {
		status = cracen_key_wrap_kwp_wrap(wrapping_key_attributes, wrapping_key_data,
						  wrapping_key_size, key_data, key_size, data,
						  data_size, data_length);
	} else {
		status = PSA_ERROR_NOT_SUPPORTED;
	}

exit:
#if defined(PSA_NEED_CRACEN_KMU_DRIVER)
	safe_memzero(exported_key, sizeof(exported_key));
#endif /* PSA_NEED_CRACEN_KMU_DRIVER */

	return status;
}

psa_status_t cracen_unwrap_key(const psa_key_attributes_t *attributes,
			       const psa_key_attributes_t *wrapping_key_attributes,
			       const uint8_t *wrapping_key_data, size_t wrapping_key_size,
			       psa_algorithm_t alg,
			       const uint8_t *data, size_t data_length,
			       uint8_t *key, size_t key_size, size_t *key_length)
{
	psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

#if defined(PSA_NEED_CRACEN_KMU_DRIVER)
	uint8_t *key_represent_buf = key;
	size_t key_represent_size = key_size;
	size_t *key_represent_length = key_length;
	size_t key_bits;
	uint8_t unwrapped_key[CRACEN_KMU_MAX_KEY_SIZE];
	size_t unwrapped_key_length;

	psa_key_location_t key_location =
		PSA_KEY_LIFETIME_GET_LOCATION(psa_get_key_lifetime(attributes));

	if (key_location == PSA_KEY_LOCATION_CRACEN_KMU) {
		key = unwrapped_key;
		key_size = sizeof(unwrapped_key);
		key_length = &unwrapped_key_length;
	}
#endif /* PSA_NEED_CRACEN_KMU_DRIVER */

	if (IS_ENABLED(PSA_NEED_CRACEN_AES_KW) && alg == PSA_ALG_KW) {
		status = cracen_key_wrap_kw_unwrap(wrapping_key_attributes, wrapping_key_data,
						   wrapping_key_size, data, data_length, key,
						   key_size, key_length);

	} else if (IS_ENABLED(CONFIG_PSA_NEED_CRACEN_AES_KWP) && alg == PSA_ALG_KWP) {
		status = cracen_key_wrap_kwp_unwrap(wrapping_key_attributes, wrapping_key_data,
						    wrapping_key_size, data, data_length, key,
						    key_size, key_length);
	} else {
		status = PSA_ERROR_NOT_SUPPORTED;
	}

#if defined(PSA_NEED_CRACEN_KMU_DRIVER)
	if (key_location == PSA_KEY_LOCATION_CRACEN_KMU) {
		status = cracen_import_key(attributes, key, *key_length, key_represent_buf,
					   key_represent_size, key_represent_length,
					   &key_bits);
		if (status == PSA_SUCCESS) {
			/** Keeping key length equal to the actual key size
			 *  since Oberon expects this number to be equal to
			 *  the one stored in key attributes.
			 */
			*key_represent_length = PSA_BITS_TO_BYTES(key_bits);
		}
	}
	safe_memzero(unwrapped_key, sizeof(unwrapped_key));
#endif /* PSA_NEED_CRACEN_KMU_DRIVER */

	return status;
}
