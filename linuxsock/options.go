// Socket configuration and I/O control: setsockopt/getsockopt with a dispatch
// table that stores options per-socket and applies them to live connections
// (SO_KEEPALIVE, SO_LINGER, SO_RCVTIMEO, SO_SNDTIMEO, SO_RCVBUF, SO_SNDBUF,
// TCP_NODELAY, SO_REUSEADDR, SO_ERROR, SO_TYPE), and ioctl (FIONBIO,
// FIONREAD, SIOCATMARK). All level/optname/request numbers are the Linux
// values — no translation happens on the C side.
package linuxsock

import (
	"encoding/binary"
	"net"
	"time"
	"unsafe"

	"gvisor.dev/gvisor/pkg/tcpip"
)

// ioctl request numbers (Linux)
const (
	FIONBIO    = 0x5421
	FIONREAD   = 0x541B
	SIOCATMARK = 0x8905
)


// Socket option levels (Linux)
const (
	SOL_SOCKET  = 1
	IPPROTO_IP  = 0
	IPPROTO_TCP = 6
)

// Socket option names at SOL_SOCKET level (Linux values)
const (
	SO_TYPE      = 3
	SO_ERROR     = 4
	SO_REUSEADDR = 2
	SO_KEEPALIVE = 9
	SO_BROADCAST = 6
	SO_LINGER    = 13
	SO_SNDBUF    = 8
	SO_RCVBUF    = 7
	SO_SNDTIMEO  = 21
	SO_RCVTIMEO  = 20
)

// IP_TOS at IPPROTO_IP level
const IP_TOS = 1

// TCP options at IPPROTO_TCP level
const (
	TCP_NODELAY = 1
	TCP_MAXSEG  = 2
)

// struct linger { int l_onoff; int l_linger; } (Linux)
type lingerOpt struct {
	Onoff  int32
	Linger int32
}

// Setsockopt stores the option and applies it to the underlying connection where possible.
func Setsockopt(fd int32, level int32, optname int32, optval unsafe.Pointer, optlen int32) int32 {
	LogCall("Setsockopt", fd, level, optname, optval, optlen)

	st, ok := registry.Get(uint64(fd))
	if !ok {
		setLastError(ENOTSOCK)
		return -1
	}
	if optval == nil || optlen <= 0 {
		setLastError(EFAULT)
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

// Getsockopt retrieves a stored socket option value.
func Getsockopt(fd int32, level int32, optname int32, optval unsafe.Pointer, optlen *int32) int32 {
	LogCall("Getsockopt", fd, level, optname, optval, optlen)

	st, ok := registry.Get(uint64(fd))
	if !ok {
		setLastError(ENOTSOCK)
		return -1
	}
	if optval == nil || optlen == nil {
		setLastError(EFAULT)
		return -1
	}

	// Handle special computed options first
	switch {
	case level == SOL_SOCKET && optname == SO_ERROR:
		// Return and clear the last error
		errCode := st.LastErrorCode
		st.LastErrorCode = 0
		if st.DialDone != nil {
			select {
			case <-st.DialDone:
				if st.DialErr != nil {
					errCode = mapError(st.DialErr)
				}
			default:
				errCode = EINPROGRESS
			}
		}
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

// SOL_SOCKET options: what the stack can honor is applied to the
// gVisor endpoint or recorded on the state (timeouts, non-blocking);
// the rest is accepted-and-ignored like a permissive kernel would.
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
		if len(val) >= 8 && st.Conn != nil {
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
		// glibc passes struct timeval {long sec; long usec}. A
		// milliseconds-DWORD parse would silently misread tv_sec
		// as ms (a historical KLINIKAL bug).
		if len(val) >= 2*int(unsafe.Sizeof(int64(0))) {
			sec := int64(binary.LittleEndian.Uint64(val[0:8]))
			usec := int64(binary.LittleEndian.Uint64(val[8:16]))
			d := time.Duration(sec)*time.Second + time.Duration(usec)*time.Microsecond
			st.RcvTimeout = d
			if st.Conn != nil {
				if d > 0 {
					st.Conn.SetReadDeadline(time.Now().Add(d))
				} else {
					st.Conn.SetReadDeadline(time.Time{}) // no deadline
				}
			}
		}

	case SO_SNDTIMEO:
		if len(val) >= 2*int(unsafe.Sizeof(int64(0))) {
			sec := int64(binary.LittleEndian.Uint64(val[0:8]))
			usec := int64(binary.LittleEndian.Uint64(val[8:16]))
			d := time.Duration(sec)*time.Second + time.Duration(usec)*time.Microsecond
			st.SndTimeout = d
			if st.Conn != nil {
				if d > 0 {
					st.Conn.SetWriteDeadline(time.Now().Add(d))
				} else {
					st.Conn.SetWriteDeadline(time.Time{})
				}
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
		// No runtime action needed — applied in Listen

	case SO_BROADCAST:
		if len(val) >= 4 && st.Endpoint != nil {
			enable := binary.LittleEndian.Uint32(val) != 0
			st.Endpoint.SocketOptions().SetBroadcast(enable)
		}
	}
}

// IPPROTO_TCP/IP options that map onto gVisor endpoint options.
func applyIPOpt(st *SocketState, optname int32, val []byte) {
	switch optname {
	case IP_TOS:
		if len(val) >= 4 && st.Endpoint != nil {
			tos := int(binary.LittleEndian.Uint32(val))
			st.Endpoint.SetSockOptInt(tcpip.IPv4TOSOption, tos)
		}
	}
}

// TCP_NODELAY and friends via tcpip endpoint options.
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
func Ioctl(fd int32, cmd uint64, argp *uint32) int32 {
	LogCall("Ioctl", fd, cmd, argp)

	st, ok := registry.Get(uint64(fd))
	if !ok {
		setLastError(ENOTSOCK)
		return -1
	}

	switch cmd {
	case FIONBIO:
		if argp == nil {
			setLastError(EFAULT)
			return -1
		}
		st.IsNonBlocking = (*argp != 0)
		return 0

	case FIONREAD:
		// Return bytes available to read
		if argp == nil {
			setLastError(EFAULT)
			return -1
		}
		// We can't query a Go net.Conn for buffered bytes without reading.
		// Report at least the bytes parked by MSG_PEEK / readiness probes;
		// callers otherwise use select/poll for availability.
		if builtins_len(st.PeekBuf) > 0 {
			*argp = uint32(builtins_len(st.PeekBuf))
		} else {
			*argp = 0
		}
		return 0

	case SIOCATMARK:
		// OOB mark check — no OOB support in Go net, always return 0 (not at mark)
		if argp == nil {
			setLastError(EFAULT)
			return -1
		}
		*argp = 0
		return 0
	}

	return 0
}


