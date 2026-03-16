/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2018-2024 WireGuard LLC. All Rights Reserved.
 *
 * Go bridge for wg-obfuscator C adapter.
 */

package main

/*
#cgo CFLAGS: -I${SRCDIR}/../WireGuardKitObfuscator
#cgo CFLAGS: -I${SRCDIR}/../WireGuardKitObfuscator/wg-obfuscator

// Include headers for type definitions and memory functions
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include "wg_obfuscator_adapter.h"
*/
import "C"

import (
	"unsafe"
)

// ObfuscatorHandle wraps the C obfuscator handle
type ObfuscatorHandle struct {
	handle *C.wg_obfs_handle_t
}

// ObfuscatorMaskingType maps to the C masking type enum
type ObfuscatorMaskingType int

const (
	ObfuscatorMaskingNone ObfuscatorMaskingType = iota
	ObfuscatorMaskingAuto
	ObfuscatorMaskingSTUN
)

// NewObfuscator creates a new obfuscator instance
func NewObfuscator(key string, masking ObfuscatorMaskingType, maxDummyLength uint16) (*ObfuscatorHandle, error) {
	keyPtr := C.CString(key)
	defer C.free(unsafe.Pointer(keyPtr))

	handle := C.wg_obfs_init(
		keyPtr,
		C.size_t(len(key)),
		C.wg_obfs_masking_t(masking),
		C.uint16_t(maxDummyLength),
	)

	if handle == nil {
		return nil, ErrObfuscatorInitFailed
	}

	return &ObfuscatorHandle{handle: handle}, nil
}

// Encode obfuscates the input data
func (o *ObfuscatorHandle) Encode(input []byte) ([]byte, error) {
	if o.handle == nil {
		return nil, ErrObfuscatorInvalidHandle
	}

	// Allocate output buffer (may be larger due to dummy data)
	maxOutputLen := len(input) + 1024 + 4
	output := make([]byte, maxOutputLen)

	result := C.wg_obfs_encode(
		o.handle,
		(*C.uint8_t)(unsafe.Pointer(&input[0])),
		C.size_t(len(input)),
		(*C.uint8_t)(unsafe.Pointer(&output[0])),
		C.size_t(len(output)),
	)

	if result < 0 {
		return nil, obfuscatorError(result)
	}

	return output[:result], nil
}

// Decode de-obfuscates the data in place
func (o *ObfuscatorHandle) Decode(data []byte) (int, error) {
	if o.handle == nil {
		return 0, ErrObfuscatorInvalidHandle
	}

	result := C.wg_obfs_decode(
		o.handle,
		(*C.uint8_t)(unsafe.Pointer(&data[0])),
		C.size_t(len(data)),
	)

	if result < 0 {
		return 0, obfuscatorError(result)
	}

	return int(result), nil
}

// IsObfuscated checks if data appears to be obfuscated
func IsObfuscated(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	return C.wg_obfs_is_obfuscated(
		(*C.uint8_t)(unsafe.Pointer(&data[0])),
		C.size_t(len(data)),
	) != 0
}

// Close frees the obfuscator resources
func (o *ObfuscatorHandle) Close() {
	if o.handle != nil {
		C.wg_obfs_free(o.handle)
		o.handle = nil
	}
}

// ObfuscatorVersion returns the obfuscator version string
func ObfuscatorVersion() string {
	return C.GoString(C.wg_obfs_version())
}

// Error types for obfuscator
var (
	ErrObfuscatorInitFailed    = &ObfuscatorError{Code: -1, Message: "obfuscator initialization failed"}
	ErrObfuscatorInvalidHandle = &ObfuscatorError{Code: -2, Message: "invalid obfuscator handle"}
	ErrObfuscatorNullBuffer    = &ObfuscatorError{Code: -3, Message: "null buffer"}
	ErrObfuscatorBufferTooSmall = &ObfuscatorError{Code: -4, Message: "buffer too small"}
)

// ObfuscatorError represents an obfuscator error
type ObfuscatorError struct {
	Code    int
	Message string
}

func (e *ObfuscatorError) Error() string {
	return e.Message
}

func obfuscatorError(code C.int) error {
	switch code {
	case C.WG_OBFS_ERROR_INVALID_KEY:
		return &ObfuscatorError{Code: int(code), Message: "invalid key"}
	case C.WG_OBFS_ERROR_INIT_FAILED:
		return &ObfuscatorError{Code: int(code), Message: "initialization failed"}
	case C.WG_OBFS_ERROR_NULL_HANDLE:
		return &ObfuscatorError{Code: int(code), Message: "null handle"}
	case C.WG_OBFS_ERROR_NULL_BUFFER:
		return &ObfuscatorError{Code: int(code), Message: "null buffer"}
	case C.WG_OBFS_ERROR_BUFFER_TOO_SMALL:
		return &ObfuscatorError{Code: int(code), Message: "buffer too small"}
	default:
		return &ObfuscatorError{Code: int(code), Message: "unknown error"}
	}
}
