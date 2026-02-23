// addr_res.go — Address resolution and conversion functions. Implements inet_addr,
// inet_ntoa, inet_pton, inet_ntop and their wide-char variants (InetPtonW, InetNtopW),
// plus WSAAddressToStringA/W and WSAStringToAddressA/W for converting between
// sockaddr structs and human-readable address strings. Also provides gethostname
// and GetHostNameW for local hostname retrieval.

package winsock

import (
	"encoding/binary"
	"net"
	"os"
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

// goGethostname retrieves the standard host name for the local computer.
func GoGethostname(name *byte, namelen int32) int32 {
	LogCall("Gethostname", name, namelen)
	hn, err := os.Hostname()
	if err != nil {
		return -1 // SOCKET_ERROR
	}
	if int32(len(hn)+1) > namelen {
		return -1 // WSAEFAULT
	}
	// Copy including null terminator
	dest := unsafe.Slice(name, namelen)
	copy(dest, hn)
	dest[len(hn)] = 0
	return 0
}

// goGetHostNameW retrieves the standard host name for the local computer as a Unicode string.
func GoGetHostNameW(name *uint16, namelen int32) int32 {
	LogCall("GetHostNameW", name, namelen)
	hn, err := os.Hostname()
	if err != nil {
		return -1
	}
	u16 := utf16.Encode([]rune(hn))
	if int32(len(u16)+1) > namelen {
		return -1
	}
	dest := unsafe.Slice(name, namelen)
	copy(dest, u16)
	dest[len(u16)] = 0
	return 0
}

// goInet_addr converts a string containing an IPv4 address into a proper address (network order).
func GoInet_addr(cp *byte) uint32 {
	LogCall("Inet_addr", cp)
	s := goStringFromPtr(cp)
	ip := net.ParseIP(s).To4()
	if ip == nil {
		return 0xFFFFFFFF // INADDR_NONE
	}
	// Return as uint32 in network byte order
	return binary.BigEndian.Uint32(ip)
}

var staticInetNtoa [16]byte // Thread-safety simplified for now

// goInet_ntoa converts an IPv4 internet network address into an ASCII string in dotted-decimal format.
func GoInet_ntoa(in uint32) *byte {
	LogCall("Inet_ntoa", in)
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, in)
	s := ip.String()
	copy(staticInetNtoa[:], s)
	staticInetNtoa[len(s)] = 0
	return &staticInetNtoa[0]
}

// goWSAAddressToStringA converts a network address into a human-readable string. (ANSI)
func GoWSAAddressToStringA(lpsaAddress unsafe.Pointer, dwAddressLength uint32, lpProtocolInfo unsafe.Pointer, lpszAddressString *byte, lpdwAddressStringLength *uint32) int32 {
	LogCall("WSAAddressToStringA", lpsaAddress, dwAddressLength, lpProtocolInfo, lpszAddressString, lpdwAddressStringLength)
	// Phase 1: Simple AF_INET support
	// lpsaAddress is likely a *sockaddr_in
	if lpsaAddress == nil || lpdwAddressStringLength == nil {
		return -1
	}

	// AF_INET is usually 2
	family := *(*uint16)(lpsaAddress)
	if family == 2 {
		// sockaddr_in: sin_family(2), sin_port(2), sin_addr(4)
		addrPtr := (*[4]byte)(unsafe.Pointer(uintptr(lpsaAddress) + 4))
		ip := net.IPv4(addrPtr[0], addrPtr[1], addrPtr[2], addrPtr[3])
		s := ip.String()

		if uint32(len(s)+1) > *lpdwAddressStringLength {
			*lpdwAddressStringLength = uint32(len(s) + 1)
			return -1 // WSAEFAULT
		}

		dest := unsafe.Slice(lpszAddressString, *lpdwAddressStringLength)
		copy(dest, s)
		dest[len(s)] = 0
		*lpdwAddressStringLength = uint32(len(s) + 1)
		return 0
	}

	return -1 // Unsupported family
}

// goWSAAddressToStringW converts a network address into a human-readable string. (Unicode)
func GoWSAAddressToStringW(lpsaAddress unsafe.Pointer, dwAddressLength uint32, lpProtocolInfo unsafe.Pointer, lpszAddressString *uint16, lpdwAddressStringLength *uint32) int32 {
	LogCall("WSAAddressToStringW", lpsaAddress, dwAddressLength, lpProtocolInfo, lpszAddressString, lpdwAddressStringLength)
	if lpsaAddress == nil || lpdwAddressStringLength == nil {
		return -1
	}

	family := *(*uint16)(lpsaAddress)
	if family == 2 {
		addrPtr := (*[4]byte)(unsafe.Pointer(uintptr(lpsaAddress) + 4))
		ip := net.IPv4(addrPtr[0], addrPtr[1], addrPtr[2], addrPtr[3])
		s := ip.String()
		u16 := utf16.Encode([]rune(s))

		if uint32(len(u16)+1) > *lpdwAddressStringLength {
			*lpdwAddressStringLength = uint32(len(u16) + 1)
			return -1
		}

		dest := unsafe.Slice(lpszAddressString, *lpdwAddressStringLength)
		copy(dest, u16)
		dest[len(u16)] = 0
		*lpdwAddressStringLength = uint32(len(u16) + 1)
		return 0
	}

	return -1
}

// goWSAStringToAddressA converts a human-readable address string into a network address. (ANSI)
func GoWSAStringToAddressA(AddressString *byte, AddressFamily int32, lpProtocolInfo unsafe.Pointer, lpAddress unsafe.Pointer, lpAddressLength *int32) int32 {
	LogCall("WSAStringToAddressA", AddressString, AddressFamily, lpProtocolInfo, lpAddress, lpAddressLength)
	if AddressString == nil || lpAddress == nil || lpAddressLength == nil {
		return -1
	}

	s := goStringFromPtr(AddressString)
	ip := net.ParseIP(s).To4()
	if ip == nil {
		return -1 // WSAEINVAL
	}

	// Assume AF_INET (2)
	if *lpAddressLength < 16 { // sizeof(sockaddr_in)
		*lpAddressLength = 16
		return -1
	}

	// Fill sockaddr_in
	sa := (*struct {
		Family uint16
		Port   uint16
		Addr   [4]byte
		Zero   [8]byte
	})(lpAddress)

	sa.Family = 2
	sa.Port = 0
	copy(sa.Addr[:], ip)
	*lpAddressLength = 16
	return 0
}

// goWSAStringToAddressW converts a human-readable address string into a network address. (Unicode)
func GoWSAStringToAddressW(AddressString *uint16, AddressFamily int32, lpProtocolInfo unsafe.Pointer, lpAddress unsafe.Pointer, lpAddressLength *int32) int32 {
	LogCall("WSAStringToAddressW", AddressString, AddressFamily, lpProtocolInfo, lpAddress, lpAddressLength)
	if AddressString == nil || lpAddress == nil || lpAddressLength == nil {
		return -1
	}

	s := goStringFromWPtr(AddressString)
	ip := net.ParseIP(s).To4()
	if ip == nil {
		return -1
	}

	if *lpAddressLength < 16 {
		*lpAddressLength = 16
		return -1
	}

	sa := (*struct {
		Family uint16
		Port   uint16
		Addr   [4]byte
		Zero   [8]byte
	})(lpAddress)

	sa.Family = 2
	sa.Port = 0
	copy(sa.Addr[:], ip)
	*lpAddressLength = 16
	return 0
}

// --- inet_pton / inet_ntop (modern address conversion, IPv4 + IPv6) ---

const (
	AF_INET  = 2
	AF_INET6 = 23
)

// GoInet_pton converts a text address to binary form.
// Returns 1 on success, 0 if the string is not a valid address, -1 on error.
func GoInet_pton(family int32, src *byte, dst unsafe.Pointer) int32 {
	LogCall("inet_pton", family, src, dst)
	if src == nil || dst == nil {
		setLastError(WSAEFAULT)
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
		setLastError(WSAEFAULT)
		return -1
	}
}

// GoInet_ntop converts a binary address to text form.
// Returns a pointer to the destination string on success, nil on error.
func GoInet_ntop(family int32, src unsafe.Pointer, dst *byte, size int32) *byte {
	LogCall("inet_ntop", family, src, dst, size)
	if src == nil || dst == nil {
		setLastError(WSAEFAULT)
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
		setLastError(WSAEFAULT)
		return nil
	}

	s := ip.String()
	if int32(len(s)+1) > size {
		setLastError(WSAENOBUFS)
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
		setLastError(WSAEFAULT)
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
		setLastError(WSAEFAULT)
		return -1
	}
}

// GoInetNtopW is the wide-char variant of inet_ntop.
func GoInetNtopW(family int32, src unsafe.Pointer, dst *uint16, size int32) *uint16 {
	LogCall("InetNtopW", family, src, dst, size)
	if src == nil || dst == nil {
		setLastError(WSAEFAULT)
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
		setLastError(WSAEFAULT)
		return nil
	}

	s := ip.String()
	u16 := utf16.Encode([]rune(s))
	if int32(len(u16)+1) > size {
		setLastError(WSAENOBUFS)
		return nil
	}

	out := unsafe.Slice(dst, size)
	copy(out, u16)
	out[len(u16)] = 0
	return dst
}
