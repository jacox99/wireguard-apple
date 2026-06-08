package main

import (
	"bytes"
	"encoding/binary"
	"testing"

	"golang.zx2c4.com/wireguard/conn"
)

func TestObfuscatingBindConfigureMaxDummy(t *testing.T) {
	bind := newObfuscatingBind(conn.NewStdNetBind())
	err := bind.Configure("endpoint=127.0.0.1:51820\nkey=test-key\nmasking=STUN\nmax_dummy=99\n\n")
	if err != nil {
		t.Fatalf("Configure failed: %v", err)
	}

	peer, ok := bind.peers["127.0.0.1:51820"]
	if !ok {
		t.Fatal("missing configured peer")
	}
	if peer.masking != obfuscationMaskingStun {
		t.Fatalf("masking = %q, want %q", peer.masking, obfuscationMaskingStun)
	}
	if peer.maxDataDummyLen != 99 {
		t.Fatalf("maxDataDummyLen = %d, want 99", peer.maxDataDummyLen)
	}
}

func TestObfuscatingBindConfigureRejectsInvalidMaxDummy(t *testing.T) {
	bind := newObfuscatingBind(conn.NewStdNetBind())
	err := bind.Configure("endpoint=127.0.0.1:51820\nkey=test-key\nmax_dummy=1025\n\n")
	if err == nil {
		t.Fatal("Configure succeeded with invalid max_dummy")
	}
}

func TestObfuscationRoundTripWithDisabledDummy(t *testing.T) {
	peer := obfuscationPeer{
		key:             []byte("test-key"),
		maxDataDummyLen: 0,
	}
	packet := make([]byte, 32)
	binary.LittleEndian.PutUint32(packet[:4], 4)
	copy(packet[4:], []byte("payload"))

	encoded, err := peer.encodeOutbound(packet)
	if err != nil {
		t.Fatalf("encodeOutbound failed: %v", err)
	}
	if bytes.Equal(encoded, packet) {
		t.Fatal("encoded packet was unchanged")
	}

	decodedLength, drop := peer.decodeInbound(encoded)
	if drop {
		t.Fatal("decodeInbound dropped encoded packet")
	}
	if decodedLength != len(packet) {
		t.Fatalf("decodedLength = %d, want %d", decodedLength, len(packet))
	}
	if !bytes.Equal(encoded[:decodedLength], packet) {
		t.Fatalf("decoded packet mismatch: got %x want %x", encoded[:decodedLength], packet)
	}
}
