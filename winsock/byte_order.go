// byte_order.go — Host/network byte order conversion functions. Implements htonl,
// htons, ntohl, ntohs and their 64-bit (htonll/ntohll) and floating-point
// (htond/htonf/ntohd/ntohf) variants, as well as the WSA-prefixed socket-bound
// wrappers (WSAHtonl, WSAHtons, WSANtohl, WSANtohs). Detects host endianness
// at init and conditionally swaps bytes.
package winsock

import (
	"math"
	"math/bits"
	"unsafe"
)

var isLittleEndian bool

func init() {
	var i uint16 = 1
	isLittleEndian = *(*byte)(unsafe.Pointer(&i)) == 1
}

// goHtonl converts a u_long from host to TCP/IP network byte order.
func GoHtonl(hostlong uint32) uint32 {
	LogCall("Htonl", hostlong)
	if isLittleEndian {
		return bits.ReverseBytes32(hostlong)
	}
	return hostlong
}

// goHtons converts a u_short from host to TCP/IP network byte order.
func GoHtons(hostshort uint16) uint16 {
	LogCall("Htons", hostshort)
	if isLittleEndian {
		return bits.ReverseBytes16(hostshort)
	}
	return hostshort
}

// goNtohl converts a u_long from TCP/IP network order to host byte order.
func GoNtohl(netlong uint32) uint32 {
	LogCall("Ntohl", netlong)
	if isLittleEndian {
		return bits.ReverseBytes32(netlong)
	}
	return netlong
}

// goNtohs converts a u_short from TCP/IP network order to host byte order.
func GoNtohs(netshort uint16) uint16 {
	LogCall("Ntohs", netshort)
	if isLittleEndian {
		return bits.ReverseBytes16(netshort)
	}
	return netshort
}

// goHtonll converts a 64-bit int from host to TCP/IP network byte order.
func GoHtonll(hostlonglong uint64) uint64 {
	LogCall("Htonll", hostlonglong)
	if isLittleEndian {
		return bits.ReverseBytes64(hostlonglong)
	}
	return hostlonglong
}

// goNtohll converts a 64-bit int from TCP/IP network order to host byte order.
func GoNtohll(netlonglong uint64) uint64 {
	LogCall("Ntohll", netlonglong)
	if isLittleEndian {
		return bits.ReverseBytes64(netlonglong)
	}
	return netlonglong
}

// goHtond converts a double from host to TCP/IP network byte order.
func GoHtond(hostdouble float64) float64 {
	LogCall("Htond", hostdouble)
	if isLittleEndian {
		b := math.Float64bits(hostdouble)
		return math.Float64frombits(bits.ReverseBytes64(b))
	}
	return hostdouble
}

// goNtohd converts a double from TCP/IP network order to host byte order.
func GoNtohd(netdouble float64) float64 {
	LogCall("Ntohd", netdouble)
	if isLittleEndian {
		b := math.Float64bits(netdouble)
		return math.Float64frombits(bits.ReverseBytes64(b))
	}
	return netdouble
}

// goHtonf converts a float from host to TCP/IP network byte order.
func GoHtonf(hostfloat float32) float32 {
	LogCall("Htonf", hostfloat)
	if isLittleEndian {
		b := math.Float32bits(hostfloat)
		return math.Float32frombits(bits.ReverseBytes32(b))
	}
	return hostfloat
}

// goNtohf converts a float from TCP/IP network order to host byte order.
func GoNtohf(netfloat float32) float32 {
	LogCall("Ntohf", netfloat)
	if isLittleEndian {
		b := math.Float32bits(netfloat)
		return math.Float32frombits(bits.ReverseBytes32(b))
	}
	return netfloat
}

// goWSAHtonl converts a u_long from host to TCP/IP network byte order for a specific socket.
func GoWSAHtonl(s uint64, hostlong uint32, lpnetlong *uint32) int32 {
	LogCall("WSAHtonl", s, hostlong, lpnetlong)
	if lpnetlong == nil {
		return -1 // WSAEFAULT
	}
	*lpnetlong = GoHtonl(hostlong)
	return 0
}

// goWSAHtons converts a u_short from host to TCP/IP network byte order for a specific socket.
func GoWSAHtons(s uint64, hostshort uint16, lpnetshort *uint16) int32 {
	LogCall("WSAHtons", s, hostshort, lpnetshort)
	if lpnetshort == nil {
		return -1 // WSAEFAULT
	}
	*lpnetshort = GoHtons(hostshort)
	return 0
}

// goWSANtohl converts a u_long from TCP/IP network order to host byte order for a specific socket.
func GoWSANtohl(s uint64, netlong uint32, lphostlong *uint32) int32 {
	LogCall("WSANtohl", s, netlong, lphostlong)
	if lphostlong == nil {
		return -1 // WSAEFAULT
	}
	*lphostlong = GoNtohl(netlong)
	return 0
}

// goWSANtohs converts a u_short from TCP/IP network order to host byte order for a specific socket.
func GoWSANtohs(s uint64, netshort uint16, lphostshort *uint16) int32 {
	LogCall("WSANtohs", s, netshort, lphostshort)
	if lphostshort == nil {
		return -1 // WSAEFAULT
	}
	*lphostshort = GoNtohs(netshort)
	return 0
}
