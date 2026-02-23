// tx_std.go — Standard synchronous data transfer. Implements send (Conn.Write with
// non-blocking deadline support and Go-to-WSA error mapping), recv (Conn.Read with
// MSG_PEEK support via a per-socket peek buffer, non-blocking mode, and error
// mapping), sendto (PacketConn.WriteTo for UDP datagrams), and recvfrom
// (PacketConn.ReadFrom with source address output into a sockaddr_in struct).
package winsock

import (
	"net"
	"net/netip"
	"time"
	"unsafe"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

// MSG_PEEK flag value (winsock2.h)
const MSG_PEEK = 0x2

// synthesizeIPv4Header creates a basic 20-byte IPv4 header for raw sockets.
func synthesizeIPv4Header(src, dst netip.Addr, payloadLen int) []byte {
	hdr := make([]byte, 20)
	hdr[0] = 0x45 // Version 4, IHL 5
	hdr[1] = 0x00 // DSCP
	totalLen := 20 + payloadLen
	hdr[2] = byte(totalLen >> 8)
	hdr[3] = byte(totalLen)
	// ID, Flags, Frag Offset = 0
	hdr[8] = 64 // TTL
	hdr[9] = 1  // Protocol ICMP

	if src.IsValid() && src.Is4() {
		srcBytes := src.As4()
		copy(hdr[12:16], srcBytes[:])
	}
	if dst.IsValid() && dst.Is4() {
		dstBytes := dst.As4()
		copy(hdr[16:20], dstBytes[:])
	}

	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(hdr[i])<<8 | uint32(hdr[i+1])
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	checksum := ^uint16(sum)
	hdr[10] = byte(checksum >> 8)
	hdr[11] = byte(checksum)

	return hdr
}

// goSend sends data on a connected socket.
func GoSend(s uint64, buf unsafe.Pointer, len int32, flags int32) int32 {
	LogCall("Send", s, buf, len, flags)
	st, ok := registry.Get(s)
	if !ok {
		setLastError(WSAENOTSOCK)
		return -1
	}
	if !isConnected(st) {
		setLastError(WSAENOTCONN)
		return -1
	}

	data := unsafe.Slice((*byte)(buf), int(len))

	if st.IsNonBlocking {
		st.Conn.SetWriteDeadline(time.Now().Add(time.Nanosecond))
	} else {
		st.Conn.SetWriteDeadline(time.Time{})
	}

	n, err := st.Conn.Write(data)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() && st.IsNonBlocking {
			setLastError(WSAEWOULDBLOCK)
		} else {
			setLastError(mapError(err))
		}
		return -1
	}

	return int32(n)
}

// goRecv receives data from a connected socket.
// Supports MSG_PEEK: data is returned but not removed from the receive buffer.
func GoRecv(s uint64, buf unsafe.Pointer, len int32, flags int32) int32 {
	LogCall("Recv", s, buf, len, flags)
	st, ok := registry.Get(s)
	if !ok {
		setLastError(WSAENOTSOCK)
		return -1
	}
	if !isConnected(st) {
		setLastError(WSAENOTCONN)
		return -1
	}

	data := unsafe.Slice((*byte)(buf), int(len))
	peek := (flags & MSG_PEEK) != 0

	// First, serve from peek buffer if available
	n := 0
	if pLen := builtins_len(st.PeekBuf); pLen > 0 {
		n = copy(data, st.PeekBuf)
		if !peek {
			// Consume from peek buffer
			st.PeekBuf = st.PeekBuf[n:]
			if builtins_len(st.PeekBuf) == 0 {
				st.PeekBuf = nil
			}
		}
		if n >= int(len) {
			return int32(n)
		}
		if peek {
			// For peek we only return what we have without blocking for more
			return int32(n)
		}
		// We consumed the peek buffer but still have room — continue reading
		data = data[n:]
	}

	if st.IsNonBlocking {
		st.Conn.SetReadDeadline(time.Now().Add(time.Nanosecond))
	} else {
		st.Conn.SetReadDeadline(time.Time{})
	}

	var rn int
	var err error
	if st.Type == TypeRaw {
		icmpData := make([]byte, int(len))
		rn, err = st.Conn.Read(icmpData)
		if err == nil && rn > 0 {
			var srcIP netip.Addr
			if raddr := st.Conn.RemoteAddr(); raddr != nil {
				if pingAddr, ok := raddr.(*netstack.PingAddr); ok {
					srcIP = pingAddr.Addr()
				}
			}
			hdr := synthesizeIPv4Header(srcIP, netip.MustParseAddr("0.0.0.0"), rn)
			copied := copy(data, hdr)
			copied += copy(data[copied:], icmpData[:rn])
			rn = copied
		}
	} else {
		rn, err = st.Conn.Read(data)
	}

	if rn > 0 {
		if peek {
			// Save read data back into peek buffer for future reads
			st.PeekBuf = append(st.PeekBuf, data[:rn]...)
		}
		n += rn
	}

	if err != nil && n == 0 {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() && st.IsNonBlocking {
			setLastError(WSAEWOULDBLOCK)
		} else {
			setLastError(mapError(err))
		}
		return -1
	}

	return int32(n)
}

// builtins_len avoids shadowing the built-in len
func builtins_len(b []byte) int { return len(b) }

// isConnected checks if the socket is connected to a remote address.
func isConnected(st *SocketState) bool {
	if st.Conn == nil {
		return false
	}
	raddr := st.Conn.RemoteAddr()
	if raddr == nil {
		return false
	}
	if pingAddr, ok := raddr.(*netstack.PingAddr); ok {
		return pingAddr.Addr().IsValid()
	}
	return true
}

// goSendto sends data to a specific destination using datagram sockets.
func GoSendto(s uint64, buf unsafe.Pointer, len int32, flags int32, to unsafe.Pointer, tolen int32) int32 {
	LogCall("Sendto", s, buf, len, flags, to, tolen)
	st, ok := registry.Get(s)
	if !ok {
		setLastError(WSAENOTSOCK)
		return -1
	}

	data := unsafe.Slice((*byte)(buf), int(len))

	var udpAddr *net.UDPAddr
	var pingAddr net.Addr
	if to != nil {
		addr, err := parseSockAddrIn(to)
		if err != nil {
			setLastError(WSAEINVAL)
			return -1
		}
		if st.Type == TypeRaw {
			host, _, _ := net.SplitHostPort(addr)
			netipAddr, _ := netip.ParseAddr(host)
			pingAddr = netstack.PingAddrFromAddr(netipAddr)
		} else {
			udpAddr, _ = net.ResolveUDPAddr("udp", addr)
		}
	} else if !isConnected(st) {
		// If not connected and 'to' is nil, it's an error
		setLastError(WSAEDESTADDRREQ)
		return -1
	}

	if st.Conn == nil {
		if st.Type == TypeUDP {
			stack, err := GetStack()
			if err != nil {
				setLastError(WSAEHOSTUNREACH)
				return -1
			}
			// Implicit bind to 0.0.0.0:0 (any port, IPv4)
			conn, err := stack.ListenUDP(&net.UDPAddr{
				IP:   net.IPv4zero,
				Port: 0,
			})
			if err != nil {
				setLastError(mapError(err))
				return -1
			}
			st.Conn = conn
		} else if st.Type == TypeRaw {
			stack, err := GetStack()
			if err != nil {
				setLastError(WSAEHOSTUNREACH)
				return -1
			}
			conn, err := stack.ListenPing(netstack.PingAddrFromAddr(netip.MustParseAddr("0.0.0.0")))
			if err != nil {
				setLastError(mapError(err))
				return -1
			}
			st.Conn = conn
		} else {
			setLastError(WSAENOTCONN)
			return -1
		}
	}

	pConn, ok := st.Conn.(net.PacketConn)
	if !ok {
		// If it's a TCP conn or listener, fail
		setLastError(WSAEINVAL)
		return -1
	}

	if st.IsNonBlocking {
		st.Conn.SetWriteDeadline(time.Now().Add(time.Nanosecond))
	} else {
		st.Conn.SetWriteDeadline(time.Time{})
	}

	var n int
	var err error

	// If the socket is connected, 'to' is ignored and it acts like send()
	if isConnected(st) {
		n, err = st.Conn.Write(data)
	} else {
		if st.Type == TypeRaw {
			n, err = pConn.WriteTo(data, pingAddr)
		} else {
			n, err = pConn.WriteTo(data, udpAddr)
		}
	}

	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() && st.IsNonBlocking {
			setLastError(WSAEWOULDBLOCK)
		} else {
			setLastError(mapError(err))
		}
		return -1
	}

	return int32(n)
}

// goRecvfrom receives a datagram and stores the source address.
func GoRecvfrom(s uint64, buf unsafe.Pointer, len int32, flags int32, from unsafe.Pointer, fromlen *int32) int32 {
	LogCall("Recvfrom", s, buf, len, flags, from, fromlen)
	st, ok := registry.Get(s)
	if !ok {
		setLastError(WSAENOTSOCK)
		return -1
	}

	if st.Conn == nil {
		setLastError(WSAEINVAL)
		return -1
	}

	pConn, ok := st.Conn.(net.PacketConn)
	if !ok {
		setLastError(WSAEINVAL)
		return -1
	}

	data := unsafe.Slice((*byte)(buf), int(len))

	if st.IsNonBlocking {
		st.Conn.SetReadDeadline(time.Now().Add(time.Nanosecond))
	} else {
		st.Conn.SetReadDeadline(time.Time{})
	}

	var n int
	var raddr net.Addr
	var err error

	if st.Type == TypeRaw {
		icmpData := make([]byte, int(len))
		if isConnected(st) {
			n, err = st.Conn.Read(icmpData)
			raddr = st.Conn.RemoteAddr()
		} else {
			n, raddr, err = pConn.ReadFrom(icmpData)
		}

		if err == nil && n > 0 {
			var srcIP netip.Addr
			if pingAddr, ok := raddr.(*netstack.PingAddr); ok {
				srcIP = pingAddr.Addr()
			}

			hdr := synthesizeIPv4Header(srcIP, netip.MustParseAddr("0.0.0.0"), n)

			copied := copy(data, hdr)
			copied += copy(data[copied:], icmpData[:n])
			n = copied
		}
	} else {
		if isConnected(st) {
			n, err = st.Conn.Read(data)
			raddr = st.Conn.RemoteAddr()
		} else {
			n, raddr, err = pConn.ReadFrom(data)
		}
	}

	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() && st.IsNonBlocking {
			setLastError(WSAEWOULDBLOCK)
		} else {
			setLastError(mapError(err))
		}
		return -1
	}

	if from != nil && fromlen != nil && *fromlen >= 16 {
		sa := (*struct {
			Family uint16
			Port   uint16
			Addr   [4]byte
			Zero   [8]byte
		})(from)
		sa.Family = 2

		if st.Type == TypeRaw {
			if pingAddr, ok := raddr.(*netstack.PingAddr); ok {
				sa.Port = 0
				addr4 := pingAddr.Addr().As4()
				copy(sa.Addr[:], addr4[:])
			}
		} else {
			if udpPeer, ok := raddr.(*net.UDPAddr); ok {
				sa.Port = uint16(udpPeer.Port>>8) | uint16(udpPeer.Port&0xFF)<<8
				copy(sa.Addr[:], udpPeer.IP.To4())
			}
		}
		*fromlen = 16
	}

	return int32(n)
}
