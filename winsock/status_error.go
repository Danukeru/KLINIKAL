// status_error.go — Error handling, address queries, and overlapped result retrieval.
// Maintains a global lastError (atomic int32) with WSAGetLastError/WSASetLastError.
// Provides mapError to translate Go net.Error to WSA error codes. Implements
// getsockname (returns local address from Conn or Listener), getpeername (returns
// remote address from Conn), and WSAGetOverlappedResult (retrieves completion state
// from the overlapped tracking map, optionally blocking on the associated event).
package winsock

import (
	"errors"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"unsafe"
)

var lastError int32

const (
	WSAEFAULT          = 10014
	WSAEINVAL          = 10022
	WSAEWOULDBLOCK     = 10035
	WSAEINPROGRESS     = 10036
	WSAENOTSOCK        = 10038
	WSAEDESTADDRREQ    = 10039
	WSAEMSGSIZE        = 10040
	WSAEOPNOTSUPP      = 10045
	WSAEPROTONOSUPPORT = 10043
	WSAEAFNOSUPPORT    = 10047
	WSAECONNRESET      = 10054
	WSAENOBUFS         = 10055
	WSAENOTCONN        = 10057
	WSAETIMEDOUT       = 10060
	WSAECONNREFUSED    = 10061
	WSAEHOSTUNREACH    = 10065
	WSA_IO_PENDING     = 997
	WSA_IO_INCOMPLETE  = 996

	// INVALID_SOCKET = (SOCKET)(~0). The C.uint cast at the cgo boundary
	// truncates to 0xFFFFFFFF — the correct Win32 value.
	INVALID_SOCKET = ^uint64(0)
)

func setLastError(errCode int32) {
	atomic.StoreInt32(&lastError, errCode)
}

// goWSAGetLastError returns the error status for the last operation.
func GoWSAGetLastError() int32 {
	LogCall("WSAGetLastError")
	return atomic.LoadInt32(&lastError)
}

// goWSASetLastError sets the error code that can be retrieved by WSAGetLastError.
func GoWSASetLastError(iError int32) {
	LogCall("WSASetLastError", iError)
	setLastError(iError)
}

// helper to map net.Error to WSA codes
func mapError(err error) int32 {
	if err == nil {
		return 0
	}

	// Check for timeout first
	if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
		return WSAETIMEDOUT
	}

	// Check for specific error conditions via error unwrapping and string matching
	errStr := err.Error()

	switch {
	case errors.Is(err, net.ErrClosed):
		return WSAENOTSOCK

	case strings.Contains(errStr, "connection refused"):
		return WSAECONNREFUSED

	case strings.Contains(errStr, "connection reset"):
		return WSAECONNRESET

	case strings.Contains(errStr, "host is unreachable"),
		strings.Contains(errStr, "no route to host"):
		return WSAEHOSTUNREACH

	case strings.Contains(errStr, "network is unreachable"):
		return WSAEHOSTUNREACH

	case strings.Contains(errStr, "address already in use"):
		return 10048 // WSAEADDRINUSE

	case strings.Contains(errStr, "address not available"):
		return 10049 // WSAEADDRNOTAVAIL

	case strings.Contains(errStr, "message too long"):
		return WSAEMSGSIZE

	case strings.Contains(errStr, "broken pipe"):
		return WSAECONNRESET

	case strings.Contains(errStr, "protocol not supported"):
		return WSAEPROTONOSUPPORT

	case strings.Contains(errStr, "operation not supported"):
		return WSAEOPNOTSUPP

	case strings.Contains(errStr, "i/o timeout"):
		return WSAETIMEDOUT

	case strings.Contains(errStr, "would block"):
		return WSAEWOULDBLOCK
	}

	return 10001 // Generic WSA error
}

// goGetsockname retrieves the local name for a socket.
func GoGetsockname(s uint64, name unsafe.Pointer, namelen *int32) int32 {
	LogCall("Getsockname", s, name, namelen)
	st, ok := registry.Get(s)
	if !ok {
		setLastError(WSAENOTSOCK)
		return -1
	}

	if name == nil || namelen == nil || *namelen < 16 {
		setLastError(WSAEFAULT)
		return -1
	}

	var addr net.Addr
	if st.Conn != nil {
		addr = st.Conn.LocalAddr()
	} else if st.Listener != nil {
		addr = st.Listener.Addr()
	} else if st.BoundAddr != "" {
		// Socket is bound but not yet listening/connected
		host, portStr, err := net.SplitHostPort(st.BoundAddr)
		if err == nil {
			sa := (*struct {
				Family uint16
				Port   uint16
				Addr   [4]byte
				Zero   [8]byte
			})(name)
			sa.Family = 2
			ip := net.ParseIP(host)
			if ip != nil {
				if ip4 := ip.To4(); ip4 != nil {
					copy(sa.Addr[:], ip4)
				}
			}
			p, _ := strconv.Atoi(portStr)
			sa.Port = uint16(p>>8) | uint16(p&0xFF)<<8
			*namelen = 16
		}
		return 0
	} else {
		return 0
	}

	sa := (*struct {
		Family uint16
		Port   uint16
		Addr   [4]byte
		Zero   [8]byte
	})(name)
	sa.Family = 2

	switch a := addr.(type) {
	case *net.TCPAddr:
		sa.Port = uint16(a.Port>>8) | uint16(a.Port&0xFF)<<8
		if ip4 := a.IP.To4(); ip4 != nil {
			copy(sa.Addr[:], ip4)
		}
	case *net.UDPAddr:
		sa.Port = uint16(a.Port>>8) | uint16(a.Port&0xFF)<<8
		if ip4 := a.IP.To4(); ip4 != nil {
			copy(sa.Addr[:], ip4)
		}
	default:
		host, portStr, _ := net.SplitHostPort(addr.String())
		ip := net.ParseIP(host)
		if ip != nil {
			if ip4 := ip.To4(); ip4 != nil {
				copy(sa.Addr[:], ip4)
			}
		}
		if portStr != "" {
			p, _ := strconv.Atoi(portStr)
			sa.Port = uint16(p>>8) | uint16(p&0xFF)<<8
		}
	}

	*namelen = 16
	return 0
}

// goGetpeername retrieves the address of the peer to which a socket is connected.
func GoGetpeername(s uint64, name unsafe.Pointer, namelen *int32) int32 {
	LogCall("Getpeername", s, name, namelen)
	st, ok := registry.Get(s)
	if !ok || st.Conn == nil {
		setLastError(WSAENOTSOCK)
		return -1
	}

	if name == nil || namelen == nil || *namelen < 16 {
		setLastError(WSAEFAULT)
		return -1
	}

	raddr := st.Conn.RemoteAddr()
	if raddr == nil {
		setLastError(WSAENOTCONN)
		return -1
	}

	sa := (*struct {
		Family uint16
		Port   uint16
		Addr   [4]byte
		Zero   [8]byte
	})(name)
	sa.Family = 2

	switch a := raddr.(type) {
	case *net.TCPAddr:
		sa.Port = uint16(a.Port>>8) | uint16(a.Port&0xFF)<<8
		if ip4 := a.IP.To4(); ip4 != nil {
			copy(sa.Addr[:], ip4)
		}
	case *net.UDPAddr:
		sa.Port = uint16(a.Port>>8) | uint16(a.Port&0xFF)<<8
		if ip4 := a.IP.To4(); ip4 != nil {
			copy(sa.Addr[:], ip4)
		}
	default:
		// For PingAddr or unknown types, try to extract from String()
		host, portStr, err := net.SplitHostPort(raddr.String())
		if err != nil {
			// PingAddr has no port
			host = raddr.String()
		}
		ip := net.ParseIP(host)
		if ip != nil {
			if ip4 := ip.To4(); ip4 != nil {
				copy(sa.Addr[:], ip4)
			}
		}
		if portStr != "" {
			p, _ := strconv.Atoi(portStr)
			sa.Port = uint16(p>>8) | uint16(p&0xFF)<<8
		}
	}

	*namelen = 16
	return 0
}

// GoWSAGetOverlappedResult retrieves the results of an overlapped operation.
// Returns TRUE (1) if the operation completed successfully, FALSE (0) otherwise.
func GoWSAGetOverlappedResult(s uint64, lpOverlapped unsafe.Pointer, lpcbTransfer *uint32, fWait int32, lpdwFlags *uint32) int32 {
	LogCall("WSAGetOverlappedResult", s, lpOverlapped, lpcbTransfer, fWait, lpdwFlags)

	if lpOverlapped == nil {
		setLastError(WSAEINVAL)
		return 0
	}

	ovKey := uintptr(lpOverlapped)
	ov := (*struct {
		Internal     uintptr
		InternalHigh uintptr
		Offset       uint32
		OffsetHigh   uint32
		HEvent       unsafe.Pointer
	})(lpOverlapped)

	// If fWait is TRUE and there's an event, wait on it
	if fWait != 0 && ov.HEvent != nil {
		handle := uintptr(ov.HEvent)
		if c, ok := registry.GetEvent(handle); ok {
			<-c // block until signaled
		}
	}

	// Check for completed result in the tracking map
	result, ok := registry.GetOverlappedResult(ovKey)
	if !ok {
		// No result found — the operation may have completed synchronously already
		// Treat as success with 0 bytes (backward compat with the old stub)
		if lpcbTransfer != nil {
			*lpcbTransfer = 0
		}
		return 1
	}

	if lpcbTransfer != nil {
		*lpcbTransfer = result.BytesTransferred
	}
	if lpdwFlags != nil {
		*lpdwFlags = result.Flags
	}

	if !result.Complete {
		setLastError(WSA_IO_INCOMPLETE)
		return 0
	}

	if result.Error != 0 {
		setLastError(result.Error)
		return 0
	}

	return 1 // TRUE — success
}
