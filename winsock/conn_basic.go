// conn_basic.go — Core connection lifecycle functions. Implements bind (stores
// local address), listen (opens a net.Listener with optional SO_REUSEADDR via
// ListenConfig), accept (accepts incoming connections and registers new socket
// handles), connect (dials TCP or UDP and applies pre-set socket options), and
// shutdown (half-close via CloseRead/CloseWrite). Also provides the parseSockAddrIn
// helper for converting C sockaddr_in structs to Go "ip:port" strings.
package winsock

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"unsafe"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

// helper to parse sockaddr_in to "ip:port"
func parseSockAddrIn(name unsafe.Pointer) (string, error) {
	if name == nil {
		return "", fmt.Errorf("NULL pointer")
	}
	// sin_family(2), sin_port(2), sin_addr(4)
	family := *(*uint16)(name)
	if family != 2 {
		return "", fmt.Errorf("Unsupported AF: %d", family)
	}

	portBytes := (*[2]byte)(unsafe.Pointer(uintptr(name) + 2))
	// In-network order (BigEndian)
	port := uint16(portBytes[0])<<8 | uint16(portBytes[1])

	addrBytes := (*[4]byte)(unsafe.Pointer(uintptr(name) + 4))
	ip := net.IPv4(addrBytes[0], addrBytes[1], addrBytes[2], addrBytes[3])

	return net.JoinHostPort(ip.String(), strconv.Itoa(int(port))), nil
}

// goBind associates a local address with a socket.
func GoBind(s uint64, name unsafe.Pointer, namelen int32) int32 {
	LogCall("Bind", s, name, namelen)
	st, ok := registry.Get(s)
	if !ok {
		setLastError(WSAENOTSOCK)
		return -1
	}

	if st.BoundAddr != "" {
		setLastError(WSAEINVAL)
		return -1
	}

	addr, err := parseSockAddrIn(name)
	if err != nil {
		setLastError(WSAEINVAL)
		return -1
	}

	st.BoundAddr = addr

	if st.Type == TypeUDP {
		stack, err := GetStack()
		if err != nil {
			setLastError(WSAEHOSTUNREACH)
			return -1
		}
		udpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			setLastError(WSAEINVAL)
			return -1
		}
		if st.Conn != nil {
			st.Conn.Close()
		}
		conn, err := stack.ListenUDP(udpAddr)
		if err != nil {
			setLastError(mapError(err))
			return -1
		}
		st.Conn = conn
		UpdateWaiterQueue(st)
	} else if st.Type == TypeRaw {
		stack, err := GetStack()
		if err != nil {
			setLastError(WSAEHOSTUNREACH)
			return -1
		}
		if st.Protocol != 1 { // IPPROTO_ICMP
			setLastError(WSAEPROTONOSUPPORT)
			return -1
		}
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			setLastError(WSAEINVAL)
			return -1
		}
		netipAddr, err := netip.ParseAddr(host)
		if err != nil {
			setLastError(WSAEINVAL)
			return -1
		}
		pingAddr := netstack.PingAddrFromAddr(netipAddr)
		if st.Conn != nil {
			st.Conn.Close()
		}
		conn, err := stack.ListenPing(pingAddr)
		if err != nil {
			setLastError(mapError(err))
			return -1
		}
		st.Conn = conn
		UpdateWaiterQueue(st)
	}

	return 0
}

// goListen places a socket in a state where it is listening for incoming connections.
func GoListen(s uint64, backlog int32) int32 {
	LogCall("Listen", s, backlog)
	st, ok := registry.Get(s)
	if !ok {
		setLastError(WSAENOTSOCK)
		return -1
	}

	addr := st.BoundAddr
	if addr == "" {
		addr = ":0"
	}

	stack, err := GetStack()
	if err != nil {
		setLastError(WSAEHOSTUNREACH)
		return -1
	}

	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		setLastError(WSAEINVAL)
		return -1
	}

	ln, err := stack.ListenTCP(tcpAddr)
	if err != nil {
		setLastError(mapError(err))
		return -1
	}
	st.Listener = ln
	UpdateWaiterQueue(st)

	return 0
}

// goAccept permits an incoming connection attempt on a socket.
func GoAccept(s uint64, addr unsafe.Pointer, addrlen *int32) uint64 {
	LogCall("Accept", s, addr, addrlen)
	st, ok := registry.Get(s)
	if !ok || st.Listener == nil {
		setLastError(WSAENOTSOCK)
		return INVALID_SOCKET
	}

	conn, err := st.Listener.Accept()
	if err != nil {
		setLastError(mapError(err))
		return INVALID_SOCKET
	}

	newSt := &SocketState{
		Conn:          conn,
		Type:          st.Type,
		AddressFamily: st.AddressFamily,
		Protocol:      st.Protocol,
		Options:       make(map[int32][]byte),
	}

	newHandle := registry.Register(newSt)
	UpdateWaiterQueue(newSt)

	// Fill addr with peer info if provided
	if addr != nil && addrlen != nil {
		// RemoteAddr() for netstack should work and return a compatible addr type
		raddr := conn.RemoteAddr()
		if tcpAddr, ok := raddr.(*net.TCPAddr); ok {
			sa := (*struct {
				Family uint16
				Port   uint16
				Addr   [4]byte
				Zero   [8]byte
			})(addr)

			sa.Family = 2
			sa.Port = uint16(tcpAddr.Port>>8) | uint16(tcpAddr.Port&0xFF)<<8
			copy(sa.Addr[:], tcpAddr.IP.To4())
			*addrlen = 16
		}
	}

	return newHandle
}

// goConnect establishes a connection to a specified socket.
func GoConnect(s uint64, name unsafe.Pointer, namelen int32) int32 {
	LogCall("Connect", s, name, namelen)
	st, ok := registry.Get(s)
	if !ok {
		setLastError(WSAENOTSOCK)
		return -1
	}

	addr, err := parseSockAddrIn(name)
	if err != nil {
		setLastError(WSAEINVAL)
		return -1
	}

	stack, err := GetStack()
	if err != nil {
		setLastError(WSAEHOSTUNREACH)
		return -1
	}

	if st.Type == TypeUDP {
		raddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			setLastError(WSAEINVAL)
			return -1
		}
		var laddr *net.UDPAddr
		if st.BoundAddr != "" {
			laddr, _ = net.ResolveUDPAddr("udp", st.BoundAddr)
		}

		conn, err := stack.DialUDP(laddr, raddr)
		if err != nil {
			setLastError(mapError(err))
			return -1
		}

		if st.Conn != nil {
			st.Conn.Close()
		}
		st.Conn = conn
		UpdateWaiterQueue(st)
	} else if st.Type == TypeRaw {
		if st.Protocol != 1 { // IPPROTO_ICMP
			setLastError(WSAEPROTONOSUPPORT)
			return -1
		}
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			setLastError(WSAEINVAL)
			return -1
		}
		raddr, err := netip.ParseAddr(host)
		if err != nil {
			setLastError(WSAEINVAL)
			return -1
		}
		var laddr netip.Addr
		if st.BoundAddr != "" {
			lhost, _, _ := net.SplitHostPort(st.BoundAddr)
			laddr, _ = netip.ParseAddr(lhost)
		} else {
			laddr = netip.MustParseAddr("0.0.0.0")
		}

		conn, err := stack.DialPing(netstack.PingAddrFromAddr(laddr), netstack.PingAddrFromAddr(raddr))
		if err != nil {
			setLastError(mapError(err))
			return -1
		}

		if st.Conn != nil {
			st.Conn.Close()
		}
		st.Conn = conn
		UpdateWaiterQueue(st)
	} else {
		conn, err := stack.Dial("tcp", addr)
		if err != nil {
			setLastError(mapError(err))
			return -1
		}
		st.Conn = conn
		UpdateWaiterQueue(st)
	}

	// Apply any pre-set socket options to the new connection
	for key, val := range st.Options {
		level := key >> 16
		opt := key & 0xFFFF
		applySockOpt(st, level, opt, val)
	}

	return 0
}

// goShutdown disables sends, receives, or both on a socket.
func GoShutdown(s uint64, how int32) int32 {
	LogCall("Shutdown", s, how)
	st, ok := registry.Get(s)
	if !ok || st.Conn == nil {
		setLastError(WSAENOTSOCK)
		return -1
	}

	// 0: SD_RECEIVE, 1: SD_SEND, 2: SD_BOTH
	tcpConn, ok := st.Conn.(*net.TCPConn)
	if !ok {
		return 0
	}

	switch how {
	case 0:
		tcpConn.CloseRead()
	case 1:
		tcpConn.CloseWrite()
	case 2:
		tcpConn.CloseRead()
		tcpConn.CloseWrite()
	}

	return 0
}
