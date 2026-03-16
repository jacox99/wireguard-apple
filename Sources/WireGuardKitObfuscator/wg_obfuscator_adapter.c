/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2018-2024 WireGuard LLC. All Rights Reserved.
 *
 * Adapter implementation for wg-obfuscator library.
 * Wraps upstream obfuscation functions without modifying upstream code.
 */

#include "wg_obfuscator_adapter.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Include upstream headers - main header for constants, obfuscation for functions */
#include "wg-obfuscator/wg-obfuscator.h"
#include "wg-obfuscator/obfuscation.h"

/* Opaque context structure */
struct wg_obfs_context {
    char *key;
    size_t key_length;
    wg_obfs_masking_t masking;
    uint16_t max_dummy_length;
};

/* Version string */
static const char *obfs_version = "1.0.0-apple";

wg_obfs_handle_t *wg_obfs_init(
    const char *key,
    size_t key_length,
    wg_obfs_masking_t masking,
    uint16_t max_dummy_length
) {
    /* Validate key */
    if (key == NULL || key_length == 0) {
        return NULL;
    }
    if (key_length > 255) {
        return NULL;
    }

    /* Validate max_dummy_length */
    if (max_dummy_length > 1024) {
        max_dummy_length = 1024;
    }

    /* Allocate context */
    wg_obfs_handle_t *ctx = (wg_obfs_handle_t *)calloc(1, sizeof(wg_obfs_handle_t));
    if (ctx == NULL) {
        return NULL;
    }

    /* Copy key */
    ctx->key = (char *)malloc(key_length + 1);
    if (ctx->key == NULL) {
        free(ctx);
        return NULL;
    }
    memcpy(ctx->key, key, key_length);
    ctx->key[key_length] = '\0';
    ctx->key_length = key_length;

    ctx->masking = masking;
    ctx->max_dummy_length = max_dummy_length;

    /* Seed random number generator */
    static int seeded = 0;
    if (!seeded) {
        srand((unsigned int)time(NULL));
        seeded = 1;
    }

    return ctx;
}

int wg_obfs_encode(
    wg_obfs_handle_t *handle,
    const uint8_t *input,
    size_t input_len,
    uint8_t *output,
    size_t output_size
) {
    /* Validate parameters */
    if (handle == NULL) {
        return WG_OBFS_ERROR_NULL_HANDLE;
    }
    if (input == NULL || output == NULL) {
        return WG_OBFS_ERROR_NULL_BUFFER;
    }
    if (input_len < 4) {
        /* WireGuard packets are at least 4 bytes (for type detection) */
        return WG_OBFS_ERROR_BUFFER_TOO_SMALL;
    }

    /* Calculate maximum possible output size */
    size_t max_output_len = input_len + handle->max_dummy_length + 4;
    if (output_size < max_output_len) {
        return WG_OBFS_ERROR_BUFFER_TOO_SMALL;
    }

    /* Copy input to output buffer (encode works in-place) */
    memcpy(output, input, input_len);

    /* Call upstream encode function */
    /* Note: The upstream encode function may add dummy data, so the output
     * length may be greater than input_len */
    int result = encode(
        output,
        (int)input_len,
        handle->key,
        (int)handle->key_length,
        OBFUSCATION_VERSION,
        (int)handle->max_dummy_length
    );

    return result;
}

int wg_obfs_decode(
    wg_obfs_handle_t *handle,
    uint8_t *data,
    size_t data_len
) {
    /* Validate parameters */
    if (handle == NULL) {
        return WG_OBFS_ERROR_NULL_HANDLE;
    }
    if (data == NULL) {
        return WG_OBFS_ERROR_NULL_BUFFER;
    }
    if (data_len < 4) {
        return WG_OBFS_ERROR_BUFFER_TOO_SMALL;
    }

    /* Call upstream decode function (works in-place) */
    uint8_t version = 0;
    int result = decode(
        data,
        (int)data_len,
        handle->key,
        (int)handle->key_length,
        &version
    );

    return result;
}

int wg_obfs_is_obfuscated(
    const uint8_t *data,
    size_t data_len
) {
    if (data == NULL || data_len < 4) {
        return 0;
    }

    /* Use upstream is_obfuscated function */
    return (int)is_obfuscated((uint8_t *)data);
}

const char *wg_obfs_version(void) {
    return obfs_version;
}

void wg_obfs_free(wg_obfs_handle_t *handle) {
    if (handle == NULL) {
        return;
    }

    if (handle->key != NULL) {
        /* Zero out key before freeing for security */
        memset(handle->key, 0, handle->key_length);
        free(handle->key);
    }

    memset(handle, 0, sizeof(wg_obfs_handle_t));
    free(handle);
}
