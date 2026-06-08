package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"strings"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
)

const (
	obfuscationMaxKeyLength         = 255
	obfuscationMaxPacketLength      = 1024
	obfuscationMaxHandshakeDummyLen = 512
	obfuscationDefaultDataDummyLen  = 4
	obfuscationStunHeaderLen        = 20
	obfuscationStunAttrHeaderLen    = 4
	obfuscationStunDataOffset       = obfuscationStunHeaderLen + obfuscationStunAttrHeaderLen
)

const (
	obfuscationStunBindingRequest  = 0x0001
	obfuscationStunBindingResponse = 0x0101
	obfuscationStunDataIndication  = 0x0115
	obfuscationStunAttrData        = 0x0013
	obfuscationStunMagicCookie     = 0x2112A442
)

type obfuscationMasking string

const (
	obfuscationMaskingNone obfuscationMasking = "none"
	obfuscationMaskingAuto obfuscationMasking = "auto"
	obfuscationMaskingStun obfuscationMasking = "stun"
)

type obfuscationPeer struct {
	key             []byte
	masking         obfuscationMasking
	maxDataDummyLen int
}

type obfuscatingBind struct {
	inner conn.Bind
	mu    sync.RWMutex
	peers map[string]obfuscationPeer
}

func newObfuscatingBind(inner conn.Bind) *obfuscatingBind {
	return &obfuscatingBind{
		inner: inner,
		peers: make(map[string]obfuscationPeer),
	}
}

func (bind *obfuscatingBind) Configure(settings string) error {
	peers := make(map[string]obfuscationPeer)
	var endpoint string
	var key []byte
	masking := obfuscationMaskingNone
	maxDataDummyLen := obfuscationDefaultDataDummyLen

	flush := func() error {
		if endpoint == "" && len(key) == 0 && masking == obfuscationMaskingNone && maxDataDummyLen == obfuscationDefaultDataDummyLen {
			return nil
		}
		if endpoint == "" {
			return errors.New("missing endpoint")
		}
		parsedEndpoint, err := bind.inner.ParseEndpoint(endpoint)
		if err != nil {
			return fmt.Errorf("invalid endpoint %q: %w", endpoint, err)
		}
		if len(key) == 0 {
			return fmt.Errorf("missing key for endpoint %q", endpoint)
		}
		peers[parsedEndpoint.DstToString()] = obfuscationPeer{
			key:             append([]byte(nil), key...),
			masking:         masking,
			maxDataDummyLen: maxDataDummyLen,
		}
		endpoint = ""
		key = nil
		masking = obfuscationMaskingNone
		maxDataDummyLen = obfuscationDefaultDataDummyLen
		return nil
	}

	for _, line := range strings.Split(settings, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			if err := flush(); err != nil {
				return err
			}
			continue
		}

		name, value, ok := strings.Cut(line, "=")
		if !ok {
			return fmt.Errorf("invalid line %q", line)
		}
		name = strings.TrimSpace(strings.ToLower(name))
		value = strings.TrimSpace(value)

		switch name {
		case "endpoint":
			endpoint = value
		case "key":
			if value == "" {
				return errors.New("empty key")
			}
			if len([]byte(value)) > obfuscationMaxKeyLength {
				return fmt.Errorf("key length %d exceeds %d", len([]byte(value)), obfuscationMaxKeyLength)
			}
			key = []byte(value)
		case "masking":
			nextMasking := obfuscationMasking(strings.ToLower(value))
			if nextMasking != obfuscationMaskingNone && nextMasking != obfuscationMaskingAuto && nextMasking != obfuscationMaskingStun {
				return fmt.Errorf("invalid masking %q", value)
			}
			masking = nextMasking
		case "max_dummy", "max-dummy":
			nextMaxDataDummyLen, err := strconv.Atoi(value)
			if err != nil || nextMaxDataDummyLen < 0 || nextMaxDataDummyLen > obfuscationMaxPacketLength {
				return fmt.Errorf("invalid max dummy %q", value)
			}
			maxDataDummyLen = nextMaxDataDummyLen
		default:
			return fmt.Errorf("unknown key %q", name)
		}
	}
	if err := flush(); err != nil {
		return err
	}

	bind.mu.Lock()
	bind.peers = peers
	bind.mu.Unlock()
	return nil
}

func (bind *obfuscatingBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actualPort, err := bind.inner.Open(port)
	if err != nil {
		return nil, 0, err
	}

	wrapped := make([]conn.ReceiveFunc, 0, len(fns))
	for _, fn := range fns {
		receive := fn
		wrapped = append(wrapped, func(buffer []byte) (int, conn.Endpoint, error) {
			for {
				n, endpoint, err := receive(buffer)
				if err != nil {
					return n, endpoint, err
				}

				peer, ok := bind.peerForEndpoint(endpoint)
				if !ok {
					return n, endpoint, nil
				}

				decoded, drop := peer.decodeInbound(buffer[:n])
				if drop {
					continue
				}
				return decoded, endpoint, nil
			}
		})
	}
	return wrapped, actualPort, nil
}

func (bind *obfuscatingBind) Close() error {
	return bind.inner.Close()
}

func (bind *obfuscatingBind) SetMark(mark uint32) error {
	return bind.inner.SetMark(mark)
}

func (bind *obfuscatingBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	return bind.inner.ParseEndpoint(s)
}

func (bind *obfuscatingBind) Send(packet []byte, endpoint conn.Endpoint) error {
	peer, ok := bind.peerForEndpoint(endpoint)
	if !ok || len(packet) < 4 {
		return bind.inner.Send(packet, endpoint)
	}

	if peer.masking == obfuscationMaskingStun && isWireGuardHandshake(packet) {
		_ = bind.inner.Send(obfuscationStunBindingRequestPacket(), endpoint)
	}

	out, err := peer.encodeOutbound(packet)
	if err != nil {
		return err
	}
	if peer.masking == obfuscationMaskingStun {
		out = obfuscationStunWrapData(out)
	}
	return bind.inner.Send(out, endpoint)
}

func (bind *obfuscatingBind) peerForEndpoint(endpoint conn.Endpoint) (obfuscationPeer, bool) {
	bind.mu.RLock()
	defer bind.mu.RUnlock()

	peer, ok := bind.peers[endpoint.DstToString()]
	return peer, ok
}

func (peer obfuscationPeer) decodeInbound(packet []byte) (int, bool) {
	if len(packet) < 4 {
		return len(packet), false
	}

	if isStunPacket(packet) {
		if !isStunDataIndication(packet) {
			return 0, true
		}
		dataLength, ok := stunDataLength(packet)
		if !ok {
			return 0, true
		}
		copy(packet, packet[obfuscationStunDataOffset:obfuscationStunDataOffset+dataLength])
		packet = packet[:dataLength]
	}

	if len(packet) < 4 || !isObfuscatedPacket(packet) {
		return len(packet), false
	}

	xorObfuscationKey(peer.key, packet)
	if !isObfuscatedPacket(packet) {
		return len(packet), false
	}

	dummyLength := int(binary.LittleEndian.Uint16(packet[2:4]))
	if dummyLength > len(packet)-4 {
		return 0, true
	}
	payloadLength := len(packet) - dummyLength
	packet[0] ^= packet[1]
	packet[1] = 0
	packet[2] = 0
	packet[3] = 0
	return payloadLength, false
}

func (peer obfuscationPeer) encodeOutbound(packet []byte) ([]byte, error) {
	out := make([]byte, len(packet), len(packet)+obfuscationMaxHandshakeDummyLen)
	copy(out, packet)

	dummyLength, err := peer.obfuscationDummyLength(packet)
	if err != nil {
		return nil, err
	}
	if dummyLength > 0 {
		out = append(out, make([]byte, dummyLength)...)
		for i := len(packet); i < len(out); i++ {
			out[i] = 0xff
		}
	}

	randomByte, err := obfuscationRandomByte()
	if err != nil {
		return nil, err
	}
	out[0] ^= randomByte
	out[1] = randomByte
	binary.LittleEndian.PutUint16(out[2:4], uint16(dummyLength))
	xorObfuscationKey(peer.key, out)
	return out, nil
}

func (peer obfuscationPeer) obfuscationDummyLength(packet []byte) (int, error) {
	maxDummy := peer.maxDataDummyLen
	if isWireGuardHandshake(packet) {
		maxDummy = obfuscationMaxHandshakeDummyLen
	}
	if len(packet) >= obfuscationMaxPacketLength || maxDummy == 0 {
		return 0, nil
	}
	remaining := obfuscationMaxPacketLength - len(packet)
	if remaining < maxDummy {
		maxDummy = remaining
	}
	if maxDummy <= 0 {
		return 0, nil
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(maxDummy)))
	if err != nil {
		return 0, err
	}
	return int(n.Int64()), nil
}

func obfuscationRandomByte() (byte, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(255))
	if err != nil {
		return 0, err
	}
	return byte(n.Int64() + 1), nil
}

func xorObfuscationKey(key []byte, packet []byte) {
	if len(key) == 0 {
		return
	}

	var crc byte
	for i := range packet {
		value := key[i%len(key)] + byte(len(packet)) + byte(len(key))
		for j := 0; j < 8; j++ {
			sum := (crc ^ value) & 0x01
			crc >>= 1
			if sum != 0 {
				crc ^= 0x8c
			}
			value >>= 1
		}
		packet[i] ^= crc
	}
}

func isObfuscatedPacket(packet []byte) bool {
	if len(packet) < 4 {
		return false
	}
	packetType := binary.LittleEndian.Uint32(packet[:4])
	return packetType < 1 || packetType > 4
}

func isWireGuardHandshake(packet []byte) bool {
	if len(packet) < 4 {
		return false
	}
	packetType := binary.LittleEndian.Uint32(packet[:4])
	return packetType == 1 || packetType == 2
}

func isStunPacket(packet []byte) bool {
	return len(packet) >= obfuscationStunHeaderLen && binary.BigEndian.Uint32(packet[4:8]) == obfuscationStunMagicCookie
}

func isStunDataIndication(packet []byte) bool {
	if len(packet) < obfuscationStunDataOffset {
		return false
	}
	if binary.BigEndian.Uint16(packet[0:2]) != obfuscationStunDataIndication {
		return false
	}
	return binary.BigEndian.Uint16(packet[20:22]) == obfuscationStunAttrData
}

func stunDataLength(packet []byte) (int, bool) {
	messageLength := int(binary.BigEndian.Uint16(packet[2:4]))
	if messageLength < obfuscationStunAttrHeaderLen || obfuscationStunHeaderLen+messageLength > len(packet) {
		return 0, false
	}
	dataLength := int(binary.BigEndian.Uint16(packet[22:24]))
	if dataLength > messageLength-obfuscationStunAttrHeaderLen || obfuscationStunDataOffset+dataLength > len(packet) {
		return 0, false
	}
	return dataLength, true
}

func obfuscationStunBindingRequestPacket() []byte {
	packet := make([]byte, obfuscationStunHeaderLen)
	binary.BigEndian.PutUint16(packet[0:2], obfuscationStunBindingRequest)
	binary.BigEndian.PutUint32(packet[4:8], obfuscationStunMagicCookie)
	_, _ = io.ReadFull(rand.Reader, packet[8:20])
	return packet
}

func obfuscationStunWrapData(packet []byte) []byte {
	out := make([]byte, obfuscationStunDataOffset+len(packet))
	binary.BigEndian.PutUint16(out[0:2], obfuscationStunDataIndication)
	binary.BigEndian.PutUint16(out[2:4], uint16(obfuscationStunAttrHeaderLen+len(packet)))
	binary.BigEndian.PutUint32(out[4:8], obfuscationStunMagicCookie)
	_, _ = io.ReadFull(rand.Reader, out[8:20])
	binary.BigEndian.PutUint16(out[20:22], obfuscationStunAttrData)
	binary.BigEndian.PutUint16(out[22:24], uint16(len(packet)))
	copy(out[obfuscationStunDataOffset:], packet)
	return out
}
