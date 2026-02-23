// sock_mgmt.go — Socket creation and destruction. Implements socket (creates a
// SocketState with address family, protocol, and options map, registers it in the
// registry), WSASocketA/W (delegates to socket), closesocket (closes the underlying
// Conn/Listener and unregisters the handle), and WSADuplicateSocketA/W (returns
// WSAEOPNOTSUPP — socket duplication across processes is not supported in the bridge).
package winsock

import (
	"unsafe"
)

// goSocket creates a socket that is bound to a specific transport service provider.
func GoSocket(af int32, typ int32, protocol int32) uint64 {
	LogCall("Socket", af, typ, protocol)
	st := &SocketState{
		Type:          TypeTCP,
		AddressFamily: af,
		Protocol:      protocol,
		Options:       make(map[int32][]byte),
	}
	if typ == 2 { // SOCK_DGRAM
		st.Type = TypeUDP
	} else if typ == 3 { // SOCK_RAW
		st.Type = TypeRaw
	}

	handle := registry.Register(st)
	return handle
}

// goWSASocketA creates a socket and associates it with a protocol. (ANSI)
func GoWSASocketA(af int32, typ int32, protocol int32, lpProtocolInfo unsafe.Pointer, g uint32, dwFlags uint32) uint64 {
	LogCall("WSASocketA", af, typ, protocol, lpProtocolInfo, g, dwFlags)
	// Phase 2: Simple handle registration
	return GoSocket(af, typ, protocol)
}

// goWSASocketW creates a socket and associates it with a protocol. (Unicode)
func GoWSASocketW(af int32, typ int32, protocol int32, lpProtocolInfo unsafe.Pointer, g uint32, dwFlags uint32) uint64 {
	LogCall("WSASocketW", af, typ, protocol, lpProtocolInfo, g, dwFlags)
	// Phase 2: Simple handle registration
	return GoSocket(af, typ, protocol)
}

// goClosesocket closes an existing socket.
func GoClosesocket(s uint64) int32 {
	LogCall("Closesocket", s)
	st, ok := registry.Get(s)
	if !ok {
		return -1 // WSAENOTSOCK
	}
	
	if st.Conn != nil {
		st.Conn.Close()
	}
	if st.Listener != nil {
		st.Listener.Close()
	}
	
	registry.Unregister(s)
	return 0
}

// GoWSADuplicateSocketA — socket duplication is not supported in this bridge.
func GoWSADuplicateSocketA(s uint64, dwProcessId uint32, lpProtocolInfo unsafe.Pointer) int32 {
	LogCall("WSADuplicateSocketA", s, dwProcessId, lpProtocolInfo)
	setLastError(WSAEOPNOTSUPP)
	return -1
}

// GoWSADuplicateSocketW — socket duplication is not supported in this bridge.
func GoWSADuplicateSocketW(s uint64, dwProcessId uint32, lpProtocolInfo unsafe.Pointer) int32 {
	LogCall("WSADuplicateSocketW", s, dwProcessId, lpProtocolInfo)
	setLastError(WSAEOPNOTSUPP)
	return -1
}
