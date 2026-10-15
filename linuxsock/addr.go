// addr_res.go — Address resolution and conversion functions. Implements inet_addr,
// inet_ntoa, inet_pton, inet_ntop and their wide-char variants (InetPtonW, InetNtopW),
// sockaddr structs and human-readable address strings. Also provides gethostname
// and GetHostNameW for local hostname retrieval.

package linuxsock

import (
	"net"
	"unicode/utf16"
	"unsafe"
)

// goStringFromPtr converts a null-terminated C string to a Go string.
func goStringFromPtr(ptr *byte) string {
	if ptr == nil {
		return ""
	}
	var n int
	for p := ptr; *p != 0; p = (*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(p)) + 1)) {
		n++
	}
	return string(unsafe.Slice(ptr, n))
}

// goStringFromWPtr converts a null-terminated UTF-16 C string to a Go string.
func goStringFromWPtr(ptr *uint16) string {
	if ptr == nil {
		return ""
	}
	var n int
	for p := ptr; *p != 0; p = (*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(p)) + 2)) {
		n++
	}
	return string(utf16.Decode(unsafe.Slice(ptr, n)))
}




// staticInetNtoa is the scratch buffer inet_ntop returns a pointer into.
// One shared buffer: two threads calling inet_ntop concurrently can race
// on the result bytes (callers copy immediately; acceptable for now).
var staticInetNtoa [16]byte // Thread-safety simplified for now






// --- inet_pton / inet_ntop (modern address conversion, IPv4 + IPv6) ---

// Linux address families, as seen in sockaddr.sa_family.
const (
	AF_INET  = 2
	AF_INET6 = 10
)

// GoInet_pton converts a text address to binary form.
// Returns 1 on success, 0 if the string is not a valid address, -1 on error.
func GoInet_pton(family int32, src *byte, dst unsafe.Pointer) int32 {
	LogCall("inet_pton", family, src, dst)
	if src == nil || dst == nil {
		setLastError(EFAULT)
		return -1
	}

	s := goStringFromPtr(src)
	ip := net.ParseIP(s)
	if ip == nil {
		return 0 // not a valid address
	}

	switch family {
	case AF_INET:
		ip4 := ip.To4()
		if ip4 == nil {
			return 0
		}
		out := (*[4]byte)(dst)
		copy(out[:], ip4)
		return 1
	case AF_INET6:
		ip6 := ip.To16()
		if ip6 == nil {
			return 0
		}
		out := (*[16]byte)(dst)
		copy(out[:], ip6)
		return 1
	default:
		setLastError(EFAULT)
		return -1
	}
}

// GoInet_ntop converts a binary address to text form.
// Returns a pointer to the destination string on success, nil on error.
func GoInet_ntop(family int32, src unsafe.Pointer, dst *byte, size int32) *byte {
	LogCall("inet_ntop", family, src, dst, size)
	if src == nil || dst == nil {
		setLastError(EFAULT)
		return nil
	}

	var ip net.IP
	switch family {
	case AF_INET:
		b := (*[4]byte)(src)
		ip = net.IPv4(b[0], b[1], b[2], b[3])
	case AF_INET6:
		b := (*[16]byte)(src)
		ip = make(net.IP, 16)
		copy(ip, b[:])
	default:
		setLastError(EFAULT)
		return nil
	}

	s := ip.String()
	if int32(len(s)+1) > size {
		setLastError(ENOBUFS)
		return nil
	}

	out := unsafe.Slice(dst, size)
	copy(out, s)
	out[len(s)] = 0
	return dst
}

// GoInetPtonW is the wide-char variant of inet_pton.
func GoInetPtonW(family int32, src *uint16, dst unsafe.Pointer) int32 {
	LogCall("InetPtonW", family, src, dst)
	if src == nil || dst == nil {
		setLastError(EFAULT)
		return -1
	}

	s := goStringFromWPtr(src)
	ip := net.ParseIP(s)
	if ip == nil {
		return 0
	}

	switch family {
	case AF_INET:
		ip4 := ip.To4()
		if ip4 == nil {
			return 0
		}
		out := (*[4]byte)(dst)
		copy(out[:], ip4)
		return 1
	case AF_INET6:
		ip6 := ip.To16()
		if ip6 == nil {
			return 0
		}
		out := (*[16]byte)(dst)
		copy(out[:], ip6)
		return 1
	default:
		setLastError(EFAULT)
		return -1
	}
}

// GoInetNtopW is the wide-char variant of inet_ntop.
func GoInetNtopW(family int32, src unsafe.Pointer, dst *uint16, size int32) *uint16 {
	LogCall("InetNtopW", family, src, dst, size)
	if src == nil || dst == nil {
		setLastError(EFAULT)
		return nil
	}

	var ip net.IP
	switch family {
	case AF_INET:
		b := (*[4]byte)(src)
		ip = net.IPv4(b[0], b[1], b[2], b[3])
	case AF_INET6:
		b := (*[16]byte)(src)
		ip = make(net.IP, 16)
		copy(ip, b[:])
	default:
		setLastError(EFAULT)
		return nil
	}

	s := ip.String()
	u16 := utf16.Encode([]rune(s))
	if int32(len(u16)+1) > size {
		setLastError(ENOBUFS)
		return nil
	}

	out := unsafe.Slice(dst, size)
	copy(out, u16)
	out[len(u16)] = 0
	return dst
}
