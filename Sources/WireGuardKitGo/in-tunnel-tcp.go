package main

import "C"

import (
	"context"
	"net"
	"net/netip"
	"time"
	"unsafe"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

// Opens a TCP connection to the specified address as though it was bound to the tunnel.
// This function returns a socket handle immediately, and it can be used immediately after,
// but the socket may not be connected immediately. When writing or reading from the socket,
// the calls will wait until the socket connection is established or it times out.
//
//export wgOpenInTunnelTCP
func wgOpenInTunnelTCP(tunnelHandle int32, address *C.char, timeout uint64) int32 {
	tun := tunnels.Get(tunnelHandle)
	if tun == nil {
		return errNoSuchTunnel
	}
	if tun.VirtualNet == nil {
		return errNoTunnelVirtualInterface
	}

	netAddr, err := netip.ParseAddrPort(C.GoString(address))
	if err != nil {
		return errBadIPString
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)

	connectTcpSocket := func(ctx context.Context, vnet *netstack.Net) (net.Conn, error) {
		connection, err := vnet.DialContextTCPAddrPort(ctx, netAddr)
		cancel()
		return connection, err
	}

	return tun.AddSocket(ctx, connectTcpSocket)
}

//export wgCloseInTunnelTCP
func wgCloseInTunnelTCP(tunnelHandle int32, socketHandle int32) bool {
	tun := tunnels.Get(tunnelHandle)
	if tun == nil {
		return false
	}

	return tun.RemoveAndCloseSocket(socketHandle)
}

// chunkIterator returns a closure that returns successive chunks of the given
// slice. Each call to the returned function returns the next chunk of size
// chunkSize. The last chunk will have a size between 1 and maximum chunk size.
// When no more data remains, the closure returns nil.
func chunkIterator(data []byte, chunkSize int) func() []byte {
	offset := 0
	return func() []byte {
		if offset >= len(data) {
			return nil
		}
		end := offset + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunk := data[offset:end]
		offset = end
		return chunk
	}
}

// Sends the data array into the TCP socket in a blocking fashion. The data
// pointer should point to at least `dataLen` bytes for the entirety of this
// call. This function is technically threadsafe, but multiple calls will not
// have a defined order, which can lead to unordered writes.
//
//export wgSendInTunnelTCP
func wgSendInTunnelTCP(tunnelHandle int32, socketHandle int32, data *byte, dataLen int32) int32 {
	tun := tunnels.Get(tunnelHandle)
	if tun == nil {
		return errNoSuchTunnel
	}

	socket, err, ok := tun.GetSocket(socketHandle)
	if !ok {
		return errTCPNoSocket
	}
	if err != nil {
		tun.logger.Errorf("Failed to open TCP socket: %s", err)
		tun.RemoveAndCloseSocket(socketHandle)
		return errTCPNoSocket
	}

	originalBuffer := unsafe.Slice(data, dataLen)
	totalBytesWritten := 0

	nextChunk := chunkIterator(originalBuffer, 1000)
	for chunk := nextChunk(); chunk != nil; chunk = nextChunk() {
		n, err := socket.Write(chunk)
		if err != nil {
			tun.logger.Errorf("TCP Failed to write to TCP connection: %v", err)
			return errTCPWrite
		}

		totalBytesWritten += n
	}

	if totalBytesWritten != int(dataLen) {
		tun.logger.Errorf("TCP Expected to write %v bytes, instead wrote %v", dataLen, totalBytesWritten)
		return errTCPWrite
	}

	return int32(totalBytesWritten)
}

// Blocking call to receive bytes into the buffer from a TCP connection. The
// `data` pointer should point to at least `dataLen` bytes, and be valid until
// this call returns.
//
//export wgRecvInTunnelTCP
func wgRecvInTunnelTCP(tunnelHandle int32, socketHandle int32, data *byte, dataLen int32) int32 {
	tun := tunnels.Get(tunnelHandle)
	if tun == nil {
		return errNoSuchTunnel
	}

	socket, err, ok := tun.GetSocket(socketHandle)
	if !ok {
		return errTCPNoSocket
	}

	if err != nil {
		tun.logger.Errorf("Failed to open TCP socket: %s", err)
		tun.RemoveAndCloseSocket(socketHandle)
		return errTCPNoSocket
	}

	byteBuffer := unsafe.Slice(data, dataLen)

	n, err := socket.Read(byteBuffer)
	if err != nil {
		tun.logger.Errorf("Failed to read from TCP connection: %v", err)
		return errTCPRead
	}

	return int32(n)
}
