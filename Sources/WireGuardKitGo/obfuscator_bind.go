/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2018-2024 WireGuard LLC. All Rights Reserved.
 *
 * Obfuscating bind wrapper for WireGuard connections.
 */

package main

import (
	"net/netip"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
)

// ObfuscatorBind wraps a conn.Bind to apply obfuscation to packets
type ObfuscatorBind struct {
	inner      conn.Bind
	obfuscator *ObfuscatorHandle
	mu         sync.RWMutex
}

// NewObfuscatorBind creates a new obfuscating bind wrapper
func NewObfuscatorBind(inner conn.Bind, obfuscator *ObfuscatorHandle) *ObfuscatorBind {
	return &ObfuscatorBind{
		inner:      inner,
		obfuscator: obfuscator,
	}
}

// Open implements conn.Bind
func (b *ObfuscatorBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	// Open the inner bind
	fns, actualPort, err := b.inner.Open(port)
	if err != nil {
		return nil, 0, err
	}

	// Wrap each receive function to de-obfuscate incoming packets
	wrappedFns := make([]conn.ReceiveFunc, len(fns))
	for i, fn := range fns {
		wrappedFns[i] = b.wrapReceiveFunc(fn)
	}

	return wrappedFns, actualPort, nil
}

// wrapReceiveFunc wraps a receive function to de-obfuscate packets
func (b *ObfuscatorBind) wrapReceiveFunc(fn conn.ReceiveFunc) conn.ReceiveFunc {
	return func(buf []byte) (int, conn.Endpoint, error) {
		// Receive packet from inner bind
		n, ep, err := fn(buf)
		if err != nil {
			return n, ep, err
		}

		// De-obfuscate if packet is large enough
		if n < 4 {
			return n, ep, nil
		}

		b.mu.RLock()
		obfs := b.obfuscator
		b.mu.RUnlock()

		if obfs == nil {
			return n, ep, nil
		}

		// Check if packet is obfuscated
		if IsObfuscated(buf[:n]) {
			// De-obfuscate in place
			newLen, decodeErr := obfs.Decode(buf[:n])
			if decodeErr != nil {
				// Log error but continue - might be a non-obfuscated packet
				return n, ep, nil
			}
			return newLen, ep, nil
		}

		return n, ep, nil
	}
}

// Close implements conn.Bind
func (b *ObfuscatorBind) Close() error {
	return b.inner.Close()
}

// SetMark implements conn.Bind
func (b *ObfuscatorBind) SetMark(mark uint32) error {
	return b.inner.SetMark(mark)
}

// Send implements conn.Bind
func (b *ObfuscatorBind) Send(buf []byte, ep conn.Endpoint) error {
	b.mu.RLock()
	obfs := b.obfuscator
	b.mu.RUnlock()

	// If no obfuscator or packet too small, send directly
	if obfs == nil || len(buf) < 4 {
		return b.inner.Send(buf, ep)
	}

	// Obfuscate the packet
	obfuscated, err := obfs.Encode(buf)
	if err != nil {
		// On error, send original packet
		return b.inner.Send(buf, ep)
	}

	return b.inner.Send(obfuscated, ep)
}

// ParseEndpoint implements conn.Bind
func (b *ObfuscatorBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	return b.inner.ParseEndpoint(s)
}

// SetObfuscator updates the obfuscator instance (thread-safe)
func (b *ObfuscatorBind) SetObfuscator(obfs *ObfuscatorHandle) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Close old obfuscator if exists
	if b.obfuscator != nil {
		b.obfuscator.Close()
	}

	b.obfuscator = obfs
}

// ClearObfuscator removes the obfuscator (thread-safe)
func (b *ObfuscatorBind) ClearObfuscator() {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.obfuscator != nil {
		b.obfuscator.Close()
		b.obfuscator = nil
	}
}

// Make sure ObfuscatorBind implements conn.Bind
var _ conn.Bind = (*ObfuscatorBind)(nil)

// ParseAddrPort is a helper to parse endpoint addresses
func ParseAddrPort(s string) (netip.AddrPort, error) {
	return netip.ParseAddrPort(s)
}
