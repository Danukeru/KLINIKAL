// conf_ctl.go — Socket configuration and I/O control. Implements setsockopt and
// getsockopt with a dispatch table that stores options per-socket and applies them
// to live connections (SO_KEEPALIVE, SO_LINGER, SO_RCVTIMEO, SO_SNDTIMEO,
// SO_RCVBUF, SO_SNDBUF, TCP_NODELAY, SO_REUSEADDR, SO_ERROR, SO_TYPE). Also
// implements ioctlsocket (FIONBIO, FIONREAD, SIOCATMARK), WSAIoctl
// (SIO_GET_EXTENSION_FUNCTION_POINTER, SIO_KEEPALIVE_VALS), and WSANSPIoctl.

package winsock

import (
	"encoding/binary"
	"net"
	"time"
	"unsafe"

	"gvisor.dev/gvisor/pkg/tcpip"
)

// IOCTL command constants
const (
	FIONBIO    = 0x8004667e
	FIONREAD   = 0x4004667f
	SIOCATMARK = 0x40047307
)

// SIO constants for WSAIoctl
const (
	SIO_GET_EXTENSION_FUNCTION_POINTER = 0xC8000006
	SIO_KEEPALIVE_VALS                 = 0x98000004
)

var (
	AcceptExPtr  uintptr
	ConnectExPtr uintptr

	WSAID_ACCEPTEX  = [16]byte{0xb5, 0x36, 0x7d, 0xb5, 0x9d, 0xd5, 0x11, 0xd0, 0x8f, 0x78, 0x00, 0xc0, 0x4f, 0xd9, 0x33, 0x8d}
	WSAID_CONNECTEX = [16]byte{0x25, 0xa2, 0x07, 0xb9, 0xdd, 0xf3, 0x46, 0x60, 0x8e, 0xe9, 0x76, 0xe5, 0x8c, 0x74, 0x06, 0x3e}
)

// Socket option level constants
const (
	SOL_SOCKET  = 0xFFFF
	IPPROTO_IP  = 0
	IPPROTO_TCP = 6
)

// Socket option name constants (SOL_SOCKET level)
const (
	SO_REUSEADDR = 0x0004
	SO_KEEPALIVE = 0x0008
	SO_BROADCAST = 0x0020
	SO_LINGER    = 0x0080
	SO_SNDBUF    = 0x1001
	SO_RCVBUF    = 0x1002
	SO_SNDTIMEO  = 0x1005
	SO_RCVTIMEO  = 0x1006
	SO_ERROR     = 0x1007
	SO_TYPE      = 0x1008
)

// Socket option name constants (IPPROTO_IP level)
const (
	IP_TOS = 3
)

// Socket option name constants (IPPROTO_TCP level)
const (
	TCP_NODELAY = 0x0001
	TCP_MAXSEG  = 0x0002
)

// C-compatible linger struct
type lingerOpt struct {
	Onoff  uint16
	Linger uint16
}

// GoSetsockopt stores the option and applies it to the underlying connection where possible.
func GoSetsockopt(s uint64, level int32, optname int32, optval unsafe.Pointer, optlen int32) int32 {
	LogCall("Setsockopt", s, level, optname, optval, optlen)

	st, ok := registry.Get(s)
	if !ok {
		setLastError(WSAENOTSOCK)
		return -1
	}
	if optval == nil || optlen <= 0 {
		setLastError(WSAEFAULT)
		return -1
	}

	// Store raw option bytes
	raw := make([]byte, int(optlen))
	copy(raw, unsafe.Slice((*byte)(optval), int(optlen)))
	st.Options[OptKey(level, optname)] = raw

	// Apply the option to the live connection if applicable
	applySockOpt(st, level, optname, raw)

	return 0
}

// GoGetsockopt retrieves a stored socket option value.
func GoGetsockopt(s uint64, level int32, optname int32, optval unsafe.Pointer, optlen *int32) int32 {
	LogCall("Getsockopt", s, level, optname, optval, optlen)

	st, ok := registry.Get(s)
	if !ok {
		setLastError(WSAENOTSOCK)
		return -1
	}
	if optval == nil || optlen == nil {
		setLastError(WSAEFAULT)
		return -1
	}

	// Handle special computed options first
	switch {
	case level == SOL_SOCKET && optname == SO_ERROR:
		// Return and clear the last error
		errCode := st.LastErrorCode
		st.LastErrorCode = 0
		if *optlen >= 4 {
			*(*int32)(optval) = errCode
			*optlen = 4
		}
		return 0

	case level == SOL_SOCKET && optname == SO_TYPE:
		if *optlen >= 4 {
			sockType := int32(1) // SOCK_STREAM
			if st.Type == TypeUDP {
				sockType = 2 // SOCK_DGRAM
			}
			*(*int32)(optval) = sockType
			*optlen = 4
		}
		return 0
	}

	// Look up stored option
	raw, exists := st.Options[OptKey(level, optname)]
	if !exists {
		// Return zero-filled default
		n := int(*optlen)
		if n > 0 {
			out := unsafe.Slice((*byte)(optval), n)
			for i := range out {
				out[i] = 0
			}
		}
		return 0
	}

	n := int(*optlen)
	if n > len(raw) {
		n = len(raw)
	}
	copy(unsafe.Slice((*byte)(optval), n), raw[:n])
	*optlen = int32(n)
	return 0
}

// applySockOpt applies an option value to the live Go connection/listener.
func applySockOpt(st *SocketState, level, optname int32, val []byte) {
	switch level {
	case SOL_SOCKET:
		applySolSocketOpt(st, optname, val)
	case IPPROTO_IP:
		applyIPOpt(st, optname, val)
	case IPPROTO_TCP:
		applyTCPOpt(st, optname, val)
	}
}

func applySolSocketOpt(st *SocketState, optname int32, val []byte) {
	switch optname {
	case SO_KEEPALIVE:
		if len(val) >= 4 && st.Conn != nil {
			enable := binary.LittleEndian.Uint32(val) != 0
			if tc, ok := st.Conn.(*net.TCPConn); ok {
				tc.SetKeepAlive(enable)
			}
		}

	case SO_LINGER:
		if len(val) >= 4 && st.Conn != nil {
			lo := (*lingerOpt)(unsafe.Pointer(&val[0]))
			if tc, ok := st.Conn.(*net.TCPConn); ok {
				if lo.Onoff != 0 {
					tc.SetLinger(int(lo.Linger))
				} else {
					tc.SetLinger(-1) // disable linger
				}
			}
		}

	case SO_RCVTIMEO:
		if len(val) >= 4 && st.Conn != nil {
			// DWORD milliseconds on Windows
			ms := binary.LittleEndian.Uint32(val)
			if ms > 0 {
				st.Conn.SetReadDeadline(time.Now().Add(time.Duration(ms) * time.Millisecond))
			} else {
				st.Conn.SetReadDeadline(time.Time{}) // no deadline
			}
		}

	case SO_SNDTIMEO:
		if len(val) >= 4 && st.Conn != nil {
			ms := binary.LittleEndian.Uint32(val)
			if ms > 0 {
				st.Conn.SetWriteDeadline(time.Now().Add(time.Duration(ms) * time.Millisecond))
			} else {
				st.Conn.SetWriteDeadline(time.Time{})
			}
		}

	case SO_RCVBUF:
		if len(val) >= 4 && st.Conn != nil {
			size := int(binary.LittleEndian.Uint32(val))
			if tc, ok := st.Conn.(*net.TCPConn); ok {
				tc.SetReadBuffer(size)
			} else if uc, ok := st.Conn.(*net.UDPConn); ok {
				uc.SetReadBuffer(size)
			}
		}

	case SO_SNDBUF:
		if len(val) >= 4 && st.Conn != nil {
			size := int(binary.LittleEndian.Uint32(val))
			if tc, ok := st.Conn.(*net.TCPConn); ok {
				tc.SetWriteBuffer(size)
			} else if uc, ok := st.Conn.(*net.UDPConn); ok {
				uc.SetWriteBuffer(size)
			}
		}

	case SO_REUSEADDR:
		// Stored for use at listen() time via net.ListenConfig.Control
		// No runtime action needed — applied in GoListen

	case SO_BROADCAST:
		if len(val) >= 4 && st.Endpoint != nil {
			enable := binary.LittleEndian.Uint32(val) != 0
			st.Endpoint.SocketOptions().SetBroadcast(enable)
		}
	}
}

func applyIPOpt(st *SocketState, optname int32, val []byte) {
	switch optname {
	case IP_TOS:
		if len(val) >= 4 && st.Endpoint != nil {
			tos := int(binary.LittleEndian.Uint32(val))
			st.Endpoint.SetSockOptInt(tcpip.IPv4TOSOption, tos)
		}
	}
}

func applyTCPOpt(st *SocketState, optname int32, val []byte) {
	switch optname {
	case TCP_NODELAY:
		if len(val) >= 4 && st.Conn != nil {
			enable := binary.LittleEndian.Uint32(val) != 0
			if tc, ok := st.Conn.(*net.TCPConn); ok {
				tc.SetNoDelay(enable)
			}
		}
	case TCP_MAXSEG:
		if len(val) >= 4 && st.Endpoint != nil {
			mss := int(binary.LittleEndian.Uint32(val))
			st.Endpoint.SetSockOptInt(tcpip.MaxSegOption, mss)
		}
	}
}

// goIoctlsocket controls the I/O mode of a socket.
func GoIoctlsocket(s uint64, cmd int32, argp *uint32) int32 {
	LogCall("Ioctlsocket", s, cmd, argp)

	st, ok := registry.Get(s)
	if !ok {
		setLastError(WSAENOTSOCK)
		return -1
	}

	switch uint32(cmd) {
	case FIONBIO:
		if argp == nil {
			setLastError(WSAEFAULT)
			return -1
		}
		st.IsNonBlocking = (*argp != 0)
		return 0

	case FIONREAD:
		// Return bytes available to read
		if argp == nil {
			setLastError(WSAEFAULT)
			return -1
		}
		// We can't directly query Go net.Conn for available bytes without reading.
		// Return 0 (no data known to be available) — caller should use select/poll.
		*argp = 0
		return 0

	case SIOCATMARK:
		// OOB mark check — no OOB support in Go net, always return 0 (not at mark)
		if argp == nil {
			setLastError(WSAEFAULT)
			return -1
		}
		*argp = 0
		return 0
	}

	return 0
}

// goWSAIoctl controls the I/O mode of a socket (extended).
func GoWSAIoctl(s uint64, dwIoControlCode uint32, lpvInBuffer unsafe.Pointer, cbInBuffer uint32, lpvOutBuffer unsafe.Pointer, cbOutBuffer uint32, lpcbBytesReturned *uint32, lpOverlapped unsafe.Pointer, lpCompletionRoutine unsafe.Pointer) int32 {
	LogCall("WSAIoctl", s, dwIoControlCode, lpvInBuffer, cbInBuffer, lpvOutBuffer, cbOutBuffer, lpcbBytesReturned, lpOverlapped, lpCompletionRoutine)

	_, ok := registry.Get(s)
	if !ok {
		setLastError(WSAENOTSOCK)
		return -1
	}

	switch dwIoControlCode {
	case SIO_GET_EXTENSION_FUNCTION_POINTER:
		if lpvInBuffer == nil || cbInBuffer < 16 || lpvOutBuffer == nil || cbOutBuffer < uint32(unsafe.Sizeof(uintptr(0))) {
			setLastError(WSAEFAULT)
			return -1
		}
		guid := *(*[16]byte)(lpvInBuffer)
		var ptr uintptr
		if guid == WSAID_ACCEPTEX {
			ptr = AcceptExPtr
		} else if guid == WSAID_CONNECTEX {
			ptr = ConnectExPtr
		}

		if ptr != 0 {
			*(*uintptr)(lpvOutBuffer) = ptr
			if lpcbBytesReturned != nil {
				*lpcbBytesReturned = uint32(unsafe.Sizeof(uintptr(0)))
			}
			return 0
		}

		setLastError(WSAEINVAL)
		return -1

	case SIO_KEEPALIVE_VALS:
		// tcp_keepalive struct: { onoff uint32, keepalivetime uint32, keepaliveinterval uint32 }
		// Accept the call but we can't apply it through Go's net API granularly.
		if lpcbBytesReturned != nil {
			*lpcbBytesReturned = 0
		}
		return 0

	case FIONBIO:
		// Non-blocking toggle via WSAIoctl
		if lpvInBuffer != nil && cbInBuffer >= 4 {
			val := *(*uint32)(lpvInBuffer)
			st, _ := registry.Get(s)
			st.IsNonBlocking = (val != 0)
		}
		if lpcbBytesReturned != nil {
			*lpcbBytesReturned = 0
		}
		return 0
	}

	// Unknown IOCTL — succeed silently
	if lpcbBytesReturned != nil {
		*lpcbBytesReturned = 0
	}
	return 0
}

// goWSANSPIoctl performs I/O control for a namespace provider.
func GoWSANSPIoctl(hLookup unsafe.Pointer, dwControlCode uint32, lpvInBuffer unsafe.Pointer, cbInBuffer uint32, lpvOutBuffer unsafe.Pointer, cbOutBuffer uint32, lpcbBytesReturned *uint32, lpCompletion unsafe.Pointer) int32 {
	LogCall("WSANSPIoctl", hLookup, dwControlCode, lpvInBuffer, cbInBuffer, lpvOutBuffer, cbOutBuffer, lpcbBytesReturned, lpCompletion)
	setLastError(WSAEOPNOTSUPP)
	return -1
}
