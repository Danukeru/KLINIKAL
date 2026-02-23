// conn_extd.go — Extended WSA connection APIs. Implements WSAAccept (delegates to
// GoAccept), WSAConnect (delegates to GoConnect, ignoring QOS), WSAConnectByNameA/W
// (resolves node+service strings and dials via netstack with optional timeout),
// and WSAConnectByList (returns WSAEOPNOTSUPP).
package winsock

import (
	"context"
	"net"
	"time"
	"unsafe"
)

// GoWSAAccept permits an incoming connection attempt on a socket. (Extended)
// Delegates to GoAccept; the condition function (lpfnCondition) is ignored.
func GoWSAAccept(s uint64, addr unsafe.Pointer, addrlen *int32, lpfnCondition unsafe.Pointer, dwCallbackData uint32) uint64 {
	LogCall("WSAAccept", s, addr, addrlen, lpfnCondition, dwCallbackData)
	// Delegate to the basic accept — condition function is not supported in this bridge
	return GoAccept(s, addr, addrlen)
}

// GoWSAConnect establishes a connection to another socket application. (Extended)
// Delegates to GoConnect; QOS and caller/callee data are ignored.
func GoWSAConnect(s uint64, name unsafe.Pointer, namelen int32, lpCallerData unsafe.Pointer, lpCalleeData unsafe.Pointer, lpSQOS unsafe.Pointer, lpGQOS unsafe.Pointer) int32 {
	LogCall("WSAConnect", s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS)
	// Delegate to basic connect — QOS/caller/callee data ignored
	return GoConnect(s, name, namelen)
}

type socketAddress struct {
	lpSockaddr      unsafe.Pointer
	iSockaddrLength int32
}

type socketAddressList struct {
	iAddressCount int32
	// Address array follows
}

// GoWSAConnectByList establishes a connection to one of a collection of endpoints.
func GoWSAConnectByList(s uint64, SocketAddressList unsafe.Pointer, LocalAddressLength *uint32, LocalAddress unsafe.Pointer, RemoteAddressLength *uint32, RemoteAddress unsafe.Pointer, timeout unsafe.Pointer, Reserved unsafe.Pointer) int32 {
	LogCall("WSAConnectByList", s, SocketAddressList, LocalAddressLength, LocalAddress, RemoteAddressLength, RemoteAddress, timeout, Reserved)

	st, ok := registry.Get(s)
	if !ok {
		setLastError(WSAENOTSOCK)
		return -1
	}

	if SocketAddressList == nil {
		setLastError(WSAEFAULT)
		return -1
	}

	list := (*socketAddressList)(SocketAddressList)
	count := int(list.iAddressCount)
	if count <= 0 {
		setLastError(WSAEINVAL)
		return -1
	}

	// The Address array starts immediately after iAddressCount
	addrArrayPtr := unsafe.Pointer(uintptr(SocketAddressList) + unsafe.Sizeof(int32(0)))
	// Align to pointer size (SOCKET_ADDRESS contains a pointer)
	align := unsafe.Alignof(unsafe.Pointer(nil))
	addrArrayPtr = unsafe.Pointer((uintptr(addrArrayPtr) + align - 1) &^ (align - 1))

	addresses := unsafe.Slice((*socketAddress)(addrArrayPtr), count)

	stack, err := GetStack()
	if err != nil {
		setLastError(WSAEHOSTUNREACH)
		return -1
	}

	// Setup context with optional timeout
	ctx := context.Background()
	if timeout != nil {
		tv := (*struct {
			Sec  int32
			Usec int32
		})(timeout)
		timeoutDuration := time.Duration(tv.Sec)*time.Second + time.Duration(tv.Usec)*time.Microsecond
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeoutDuration)
		defer cancel()
	}

	var lastErr error
	var connectedConn net.Conn
	var connectedAddr unsafe.Pointer
	var connectedAddrLen int32

	// Try sequentially
	for i := 0; i < count; i++ {
		sa := addresses[i]
		if sa.lpSockaddr == nil || sa.iSockaddrLength < 16 {
			continue
		}

		addrStr, err := parseSockAddrIn(sa.lpSockaddr)
		if err != nil {
			continue
		}

		conn, err := stack.DialContext(ctx, "tcp", addrStr)
		if err == nil {
			connectedConn = conn
			connectedAddr = sa.lpSockaddr
			connectedAddrLen = sa.iSockaddrLength
			break
		}
		lastErr = err
	}

	if connectedConn == nil {
		if lastErr != nil {
			setLastError(mapError(lastErr))
		} else {
			setLastError(WSAECONNREFUSED)
		}
		return -1
	}

	st.Conn = connectedConn

	// Fill local address if requested
	if LocalAddress != nil && LocalAddressLength != nil && *LocalAddressLength >= 16 {
		if tcpAddr, ok := connectedConn.LocalAddr().(*net.TCPAddr); ok {
			fillSockAddrIn(LocalAddress, tcpAddr.IP, tcpAddr.Port)
			*LocalAddressLength = 16
		}
	}

	// Fill remote address if requested
	if RemoteAddress != nil && RemoteAddressLength != nil && *RemoteAddressLength >= uint32(connectedAddrLen) {
		// Copy the connected address to RemoteAddress
		copy(unsafe.Slice((*byte)(RemoteAddress), connectedAddrLen), unsafe.Slice((*byte)(connectedAddr), connectedAddrLen))
		*RemoteAddressLength = uint32(connectedAddrLen)
	}

	return 1 // TRUE
}

// wsaConnectByName is the shared implementation for WSAConnectByNameA/W.
func wsaConnectByName(s uint64, node string, service string, LocalAddressLength *uint32, LocalAddress unsafe.Pointer, RemoteAddressLength *uint32, RemoteAddress unsafe.Pointer, timeout unsafe.Pointer) int32 {
	st, ok := registry.Get(s)
	if !ok {
		setLastError(WSAENOTSOCK)
		return -1
	}

	addr := net.JoinHostPort(node, service)

	stack, err := GetStack()
	if err != nil {
		setLastError(WSAEHOSTUNREACH)
		return -1
	}

	// Setup context with optional timeout
	ctx := context.Background()
	if timeout != nil {
		tv := (*struct {
			Sec  int32
			Usec int32
		})(timeout)
		timeoutDuration := time.Duration(tv.Sec)*time.Second + time.Duration(tv.Usec)*time.Microsecond
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeoutDuration)
		defer cancel()
	}

	conn, err := stack.DialContext(ctx, "tcp", addr)
	if err != nil {
		setLastError(mapError(err))
		return -1
	}
	st.Conn = conn

	// Fill local address if requested
	if LocalAddress != nil && LocalAddressLength != nil && *LocalAddressLength >= 16 {
		if tcpAddr, ok := conn.LocalAddr().(*net.TCPAddr); ok {
			fillSockAddrIn(LocalAddress, tcpAddr.IP, tcpAddr.Port)
			*LocalAddressLength = 16
		}
	}

	// Fill remote address if requested
	if RemoteAddress != nil && RemoteAddressLength != nil && *RemoteAddressLength >= 16 {
		if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
			fillSockAddrIn(RemoteAddress, tcpAddr.IP, tcpAddr.Port)
			*RemoteAddressLength = 16
		}
	}

	return 1 // TRUE
}

// fillSockAddrIn writes an IPv4 address + port into a sockaddr_in buffer.
func fillSockAddrIn(sa unsafe.Pointer, ip net.IP, port int) {
	addr := (*struct {
		Family uint16
		Port   uint16
		Addr   [4]byte
		Zero   [8]byte
	})(sa)
	addr.Family = 2 // AF_INET
	addr.Port = uint16(port>>8) | uint16(port&0xFF)<<8
	ip4 := ip.To4()
	if ip4 != nil {
		copy(addr.Addr[:], ip4)
	}
}

// GoWSAConnectByNameA establishes a connection to a specified host and port. (ANSI)
func GoWSAConnectByNameA(s uint64, nodename *byte, servicename *byte, LocalAddressLength *uint32, LocalAddress unsafe.Pointer, RemoteAddressLength *uint32, RemoteAddress unsafe.Pointer, timeout unsafe.Pointer, Reserved unsafe.Pointer) int32 {
	LogCall("WSAConnectByNameA", s, nodename, servicename, LocalAddressLength, LocalAddress, RemoteAddressLength, RemoteAddress, timeout, Reserved)
	node := goStringFromPtr(nodename)
	service := goStringFromPtr(servicename)
	return wsaConnectByName(s, node, service, LocalAddressLength, LocalAddress, RemoteAddressLength, RemoteAddress, timeout)
}

// GoWSAConnectByNameW establishes a connection to a specified host and port. (Unicode)
func GoWSAConnectByNameW(s uint64, nodename *uint16, servicename *uint16, LocalAddressLength *uint32, LocalAddress unsafe.Pointer, RemoteAddressLength *uint32, RemoteAddress unsafe.Pointer, timeout unsafe.Pointer, Reserved unsafe.Pointer) int32 {
	LogCall("WSAConnectByNameW", s, nodename, servicename, LocalAddressLength, LocalAddress, RemoteAddressLength, RemoteAddress, timeout, Reserved)
	node := goStringFromWPtr(nodename)
	service := goStringFromWPtr(servicename)
	return wsaConnectByName(s, node, service, LocalAddressLength, LocalAddress, RemoteAddressLength, RemoteAddress, timeout)
}

// GoAcceptEx is the Go implementation of AcceptEx.
func GoAcceptEx(sListenSocket uint64, sAcceptSocket uint64, lpOutputBuffer unsafe.Pointer, dwReceiveDataLength uint32, dwLocalAddressLength uint32, dwRemoteAddressLength uint32, lpdwBytesReceived *uint32, lpOverlapped unsafe.Pointer) int32 {
	LogCall("AcceptEx", sListenSocket, sAcceptSocket, lpOutputBuffer, dwReceiveDataLength, dwLocalAddressLength, dwRemoteAddressLength, lpdwBytesReceived, lpOverlapped)
	setLastError(WSAEOPNOTSUPP)
	return 0 // FALSE
}

// GoConnectEx is the Go implementation of ConnectEx.
func GoConnectEx(s uint64, name unsafe.Pointer, namelen int32, lpSendBuffer unsafe.Pointer, dwSendDataLength uint32, lpdwBytesSent *uint32, lpOverlapped unsafe.Pointer) int32 {
	LogCall("ConnectEx", s, name, namelen, lpSendBuffer, dwSendDataLength, lpdwBytesSent, lpOverlapped)
	setLastError(WSAEOPNOTSUPP)
	return 0 // FALSE
}
