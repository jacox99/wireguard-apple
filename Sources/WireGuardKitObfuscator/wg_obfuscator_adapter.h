/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2018-2024 WireGuard LLC. All Rights Reserved.
 *
 * Adapter for wg-obfuscator library to integrate with WireGuard Apple.
 * Wraps the upstream obfuscation functions without modifying upstream code.
 */

#ifndef WG_OBFUSCATOR_ADAPTER_H
#define WG_OBFUSCATOR_ADAPTER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Error codes */
typedef enum {
    WG_OBFS_SUCCESS = 0,
    WG_OBFS_ERROR_INVALID_KEY = -1,
    WG_OBFS_ERROR_INIT_FAILED = -2,
    WG_OBFS_ERROR_NULL_HANDLE = -3,
    WG_OBFS_ERROR_NULL_BUFFER = -4,
    WG_OBFS_ERROR_BUFFER_TOO_SMALL = -5,
    WG_OBFS_ERROR_INVALID_LENGTH = -6,
} wg_obfs_error_t;

/* Masking types */
typedef enum {
    WG_OBFS_MASKING_NONE = 0,  /* No protocol masking, just XOR obfuscation */
    WG_OBFS_MASKING_AUTO = 1,  /* Auto-detect from peer (not implemented yet) */
    WG_OBFS_MASKING_STUN = 2,  /* Mask as STUN protocol */
} wg_obfs_masking_t;

/* Opaque handle for obfuscator state */
typedef struct wg_obfs_context wg_obfs_handle_t;

/**
 * Initialize an obfuscator instance.
 *
 * @param key               The XOR key for obfuscation (null-terminated string).
 * @param key_length        Length of the key in bytes.
 * @param masking           Type of protocol masking to apply.
 * @param max_dummy_length  Maximum length of dummy data to add to packets (0-1024).
 *
 * @return Handle to the obfuscator instance, or NULL on error.
 */
wg_obfs_handle_t *wg_obfs_init(
    const char *key,
    size_t key_length,
    wg_obfs_masking_t masking,
    uint16_t max_dummy_length
);

/**
 * Obfuscate an outgoing packet.
 *
 * The output buffer must be at least (input_len + max_dummy_length + 4) bytes
 * to accommodate potential dummy data expansion.
 *
 * @param handle        Obfuscator handle from wg_obfs_init().
 * @param input         Input packet data to obfuscate.
 * @param input_len     Length of input data.
 * @param output        Output buffer for obfuscated data.
 * @param output_size   Size of output buffer.
 *
 * @return Length of obfuscated data on success, or negative error code on failure.
 */
int wg_obfs_encode(
    wg_obfs_handle_t *handle,
    const uint8_t *input,
    size_t input_len,
    uint8_t *output,
    size_t output_size
);

/**
 * De-obfuscate an incoming packet.
 *
 * De-obfuscation is performed in-place on the buffer.
 *
 * @param handle        Obfuscator handle from wg_obfs_init().
 * @param data          Buffer containing obfuscated data (modified in-place).
 * @param data_len      Length of data in buffer.
 *
 * @return Length of de-obfuscated data on success, or negative error code on failure.
 */
int wg_obfs_decode(
    wg_obfs_handle_t *handle,
    uint8_t *data,
    size_t data_len
);

/**
 * Check if a packet appears to be obfuscated.
 *
 * @param data      Packet data to check.
 * @param data_len  Length of packet data.
 *
 * @return 1 if the packet appears obfuscated, 0 otherwise.
 */
int wg_obfs_is_obfuscated(
    const uint8_t *data,
    size_t data_len
);

/**
 * Get the obfuscator version string.
 *
 * @return Version string (static, do not free).
 */
const char *wg_obfs_version(void);

/**
 * Free an obfuscator instance.
 *
 * @param handle    Obfuscator handle to free.
 */
void wg_obfs_free(wg_obfs_handle_t *handle);

#ifdef __cplusplus
}
#endif

#endif /* WG_OBFUSCATOR_ADAPTER_H */
