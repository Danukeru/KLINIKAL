// errors.go — Error handling: a process-global last-error (errno) store
// plus mapError, which translates gVisor/netstack errors to the Linux
// errno values an application expects. getpeername/getsockname are here
// too (they read Conn/Listener addresses).
package linuxsock

import (
	"errors"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"unsafe"
)

// lastError holds the errno of the most recent failed operation
// (thread-local would be more faithful; the loader reads it immediately
// after the failing call returns, which bounds the race).
var lastError int32

// Error model: every failing operation returns -1 and records one of these
// Linux errno values as the last error, exactly like the kernel socket calls
// this module stands in for.
const (
	EPERM           = 1
	ENOENT          = 2
	EINTR           = 4
	EIO             = 5
	EBADF           = 9
	EAGAIN          = 11
	EWOULDBLOCK     = EAGAIN
	EACCES          = 13
	EFAULT          = 14
	EBUSY           = 16
	EEXIST          = 17
	EINVAL          = 22
	ENFILE          = 23
	EMFILE          = 24
	ENODEV          = 19
	ENOSYS          = 38
	ENOTSOCK        = 88
	EDESTADDRREQ    = 89
	EMSGSIZE        = 90
	EPROTOTYPE      = 91
	ENOPROTOOPT     = 92
	EPROTONOSUPPORT = 93
	ESOCKTNOSUPPORT = 94
	EOPNOTSUPP      = 95
	EPFNOSUPPORT    = 96
	EAFNOSUPPORT    = 97
	EADDRINUSE      = 98
	EADDRNOTAVAIL   = 99
	ENETDOWN        = 100
	ENETUNREACH     = 101
	ENETRESET       = 102
	ECONNABORTED    = 103
	ECONNRESET      = 104
	ENOBUFS         = 105
	EISCONN         = 106
	ENOTCONN        = 107
	ESHUTDOWN       = 108
	ETOOMANYREFS    = 109
	ETIMEDOUT       = 110
	ECONNREFUSED    = 111
	EHOSTDOWN       = 112
	EHOSTUNREACH    = 113
	EALREADY        = 114
	EINPROGRESS     = 115
)

// setLastError records the errno for the next GetLastError() read.
func setLastError(errCode int32) {
	atomic.StoreInt32(&lastError, errCode)
}

// GetLastError returns the errno recorded by the last failed operation.
func GetLastError() int32 {
	LogCall("GetLastError")
	return atomic.LoadInt32(&lastError)
}


// mapError translates a Go/netstack error to a Linux errno.
func mapError(err error) int32 {
	if err == nil {
		return 0
	}

	// Check for timeout first
	if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
		return ETIMEDOUT
	}

	// Check for specific error conditions via error unwrapping and string matching
	errStr := err.Error()

	switch {
	case errors.Is(err, net.ErrClosed):
		return ENOTSOCK

	case strings.Contains(errStr, "connection refused"),
		strings.Contains(errStr, "connection was refused"):
		return ECONNREFUSED

	case strings.Contains(errStr, "connection reset"):
		return ECONNRESET

	case strings.Contains(errStr, "host is unreachable"),
		strings.Contains(errStr, "no route to host"):
		return EHOSTUNREACH

	case strings.Contains(errStr, "network is unreachable"):
		return EHOSTUNREACH

	case strings.Contains(errStr, "address already in use"):
		return 10048 // EADDRINUSE

	case strings.Contains(errStr, "address not available"):
		return 10049 // EADDRNOTAVAIL

	case strings.Contains(errStr, "message too long"):
		return EMSGSIZE

	case strings.Contains(errStr, "broken pipe"):
		return ECONNRESET

	case strings.Contains(errStr, "protocol not supported"):
		return EPROTONOSUPPORT

	case strings.Contains(errStr, "operation not supported"):
		return EOPNOTSUPP

	case strings.Contains(errStr, "i/o timeout"):
		return ETIMEDOUT

	case strings.Contains(errStr, "would block"):
		return EAGAIN
	}

	return EIO
}

// goGetsockname retrieves the local name for a socket.
func Getsockname(fd int32, name unsafe.Pointer, namelen *int32) int32 {
	LogCall("Getsockname", fd, name, namelen)
	st, ok := registry.Get(uint64(fd))
	if !ok {
		setLastError(ENOTSOCK)
		return -1
	}

	if name == nil || namelen == nil || *namelen < 16 {
		setLastError(EFAULT)
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
func Getpeername(fd int32, name unsafe.Pointer, namelen *int32) int32 {
	LogCall("Getpeername", fd, name, namelen)
	st, ok := registry.Get(uint64(fd))
	if !ok || st.Conn == nil {
		setLastError(ENOTSOCK)
		return -1
	}

	if name == nil || namelen == nil || *namelen < 16 {
		setLastError(EFAULT)
		return -1
	}

	raddr := st.Conn.RemoteAddr()
	if raddr == nil {
		setLastError(ENOTCONN)
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