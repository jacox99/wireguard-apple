package main

import (
	"net/netip"
	"reflect"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// Test validates the TCP FFI interface by doing the following:
//  1. Setting up two (`a` and `b`) WireGuard devices, both being replace_peers
//  2. a listening socket is created using the virtual networking stack directly
//     on the `b` device
//  3. using the FFI interface with `a` device to connect to said listening socket
//  4. using the FFI interface with `a` device, send data to `b` listener
//  5. using the FFI interface with `a` device, receive the same data back
//
// Ultimately, this tests the same interface that will be used by the main app to
// negotiate ephemeral peers with relays.
func TestInTunnelTCP(t *testing.T) {
	goroutineLeakCheck(t)

	// 1. Setting up WireGuard devices
	aIp := netip.AddrFrom4([4]byte{1, 2, 3, 4})
	bIp := netip.AddrFrom4([4]byte{1, 2, 3, 5})

	a, _, _ := netstack.CreateNetTUN([]netip.Addr{aIp}, []netip.Addr{}, 1280)
	b, bNet, _ := netstack.CreateNetTUN([]netip.Addr{bIp}, []netip.Addr{}, 1280)

	configs, endpointConfigs := genConfigs(t)
	aConfig := configs[0] + endpointConfigs[0]
	bConfig := configs[1] + endpointConfigs[1]

	tunnel := wgTurnOnIANFromExistingTunnel(a, aConfig, aIp, nil)

	bDev := device.NewDevice(b, conn.NewStdNetBind(), device.NewLogger(device.LogLevelSilent, ""))

	bDev.IpcSet(bConfig)
	bDev.Up()

	listenAddrString := "1.2.3.5:9090"
	listenAddr := netip.MustParseAddrPort(listenAddrString)

	// 2. set up a listener socket for `b` device
	listener, err := bNet.ListenTCPAddrPort(listenAddr)
	if err != nil {
		t.Fatalf("Failed to start listening for a connection")
	}

	// Listener will accept a single connection, read 1024 bytes from it, and
	// send the same data back.
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			listener.Close()
		}
		readBuffer := make([]byte, 1024)
		bytesRead, _ := connection.Read(readBuffer)
		_, _ = connection.Write(readBuffer[:bytesRead])
	}()

	// 3. Connect to listener through `a` device.
	tcpClient := wgOpenInTunnelTCP(tunnel, cstring(listenAddrString), 5)
	if tcpClient < 0 {
		t.Fatalf("Expected non-zero tcpClient value, got %v", tcpClient)
	}

	sendSlice := make([]byte, 1024)
	for i := range sendSlice {
		sendSlice[i] = byte(i % 256)
	}
	// 4. Send data through the TCP socket
	result := wgSendInTunnelTCP(tunnel, tcpClient, unsafe.SliceData(sendSlice), int32(len(sendSlice)))
	if result < 0 {
		t.Fatalf("Failed to send in tunnel TCP data: %d", result)
	}

	// 5. Receive data through the TCP socket
	recvSlice := make([]byte, 1024)
	result = wgRecvInTunnelTCP(tunnel, tcpClient, unsafe.SliceData(recvSlice), int32(len(recvSlice)))
	if result < 0 {
		t.Fatalf("Failed to receive in tunnel TCP data")
	}
	if int(result) != len(sendSlice) {
		t.Fatalf("Expected to receive %v bytes, instead got %v", len(sendSlice), result)
	}

	assert.Equal(t, sendSlice, recvSlice)

	wgCloseInTunnelTCP(tunnel, tcpClient)
	bDev.Close()
	wgTurnOff(tunnel)
}

// Tests that a WireGuard device can  be shut down whilst a TCP connection is being made.
// This is here because there were deadlocks.
func TestInTunnelTCPShutdown(t *testing.T) {
	aIp := netip.AddrFrom4([4]byte{1, 2, 3, 4})
	a, _, _ := netstack.CreateNetTUN([]netip.Addr{aIp}, []netip.Addr{}, 1280)

	configs, endpointConfigs := genConfigs(t)
	aConfig := configs[0] + endpointConfigs[0]


	tunnel := wgTurnOnIANFromExistingTunnel(a, aConfig, aIp, nil)

	remoteAddr := "1.2.3.5:9090"
	// Opening connections that go nowhere must not block the shutdown of a tunnel
	for i := 0; i < 10; i += 1 {
		_ = wgOpenInTunnelTCP(tunnel, cstring(remoteAddr), 5)
	}

	wgTurnOff(tunnel)
}

func TestChunkIterator_EmptySlice(t *testing.T) {
	data := []byte{}
	nextChunk := chunkIterator(data, 10)

	chunk := nextChunk()
	if chunk != nil {
		t.Errorf("Expected nil for empty slice, got %v", chunk)
	}
}

func TestChunkIterator_MultipleChunks(t *testing.T) {
	data := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	nextChunk := chunkIterator(data, 3)

	// First chunk
	chunk := nextChunk()
	expected := []byte{1, 2, 3}
	if !reflect.DeepEqual(chunk, expected) {
		t.Errorf("Chunk 1: Expected %v, got %v", expected, chunk)
	}

	// Second chunk
	chunk = nextChunk()
	expected = []byte{4, 5, 6}
	if !reflect.DeepEqual(chunk, expected) {
		t.Errorf("Chunk 2: Expected %v, got %v", expected, chunk)
	}

	// Third chunk
	chunk = nextChunk()
	expected = []byte{7, 8, 9}
	if !reflect.DeepEqual(chunk, expected) {
		t.Errorf("Chunk 3: Expected %v, got %v", expected, chunk)
	}

	// Fourth chunk (partial)
	chunk = nextChunk()
	expected = []byte{10}
	if !reflect.DeepEqual(chunk, expected) {
		t.Errorf("Chunk 4: Expected %v, got %v", expected, chunk)
	}

	// No more chunks
	chunk = nextChunk()
	if chunk != nil {
		t.Errorf("Expected nil after exhausting chunks, got %v", chunk)
	}
}


func TestChunkIterator_SliceValidity(t *testing.T) {
	// Test that returned slices are valid views into the original data
	data := []byte{1, 2, 3, 4, 5, 6}
	nextChunk := chunkIterator(data, 2)

	chunk1 := nextChunk()
	chunk2 := nextChunk()
	chunk3 := nextChunk()

	// Modify the original data
	data[1] = 99
	data[3] = 88
	data[5] = 77

	// Chunks should reflect the changes (they're slices of the original)
	if chunk1[1] != 99 {
		t.Errorf("Expected chunk1[1] to be 99, got %d", chunk1[1])
	}
	if chunk2[1] != 88 {
		t.Errorf("Expected chunk2[1] to be 88, got %d", chunk2[1])
	}
	if chunk3[1] != 77 {
		t.Errorf("Expected chunk3[1] to be 77, got %d", chunk3[1])
	}
}
