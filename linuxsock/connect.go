// socket connection lifecycle: bind (stores local address, opens UDP/ping
// endpoints), listen (opens a net.Listener), accept (accepts incoming
// connections under a loader-reserved fd), connect (dials TCP/UDP/ping,
// with EINPROGRESS semantics for non-blocking sockets), and shutdown
// (half-close via CloseRead/CloseWrite). parseSockAddrIn converts C
// sockaddr_in structs to Go "ip:port" strings.
package linuxsock

import (
	"fmt"
	"os"
	"sync"
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

	portBytes := (*[2]byte)(unsafe.Pointer(uintptr(name) + 2))
	// In-network order (BigEndian)
	port := uint16(portBytes[0])<<8 | uint16(portBytes[1])

	switch family {
	case AF_INET:
		addrBytes := (*[4]byte)(unsafe.Pointer(uintptr(name) + 4))
		ip := net.IPv4(addrBytes[0], addrBytes[1], addrBytes[2], addrBytes[3])
		return net.JoinHostPort(ip.String(), strconv.Itoa(int(port))), nil
	case AF_INET6:
		// dual-stack clients (gRPC among them) hand us AF_INET6 socket
		// addresses, usually v4-mapped (::ffff:a.b.c.d). The embedded
		// stack speaks IPv4, so map those through; true IPv6 passes
		// through and fails routing (EHOSTUNREACH) as expected.
		addrBytes := (*[16]byte)(unsafe.Pointer(uintptr(name) + 8))
		ip := net.IP(addrBytes[:])
		if v4 := ip.To4(); v4 != nil {
			if os.Getenv("KLINIKAL_VERBOSE") != "" {
				fmt.Printf("kl: v6-mapped -> %s\n", v4)
			}
			return net.JoinHostPort(v4.String(), strconv.Itoa(int(port))), nil
		}
		if os.Getenv("KLINIKAL_VERBOSE") != "" {
			fmt.Printf("kl: true v6 -> %s\n", ip)
		}
		return net.JoinHostPort(ip.String(), strconv.Itoa(int(port))), nil
	}
	return "", fmt.Errorf("Unsupported AF: %d", family)
}

// goBind associates a local address with a socket.
func Bind(fd int32, name unsafe.Pointer, namelen int32) int32 {
	LogCall("Bind", fd, name, namelen)
	st, ok := registry.Get(uint64(fd))
	if !ok {
		setLastError(ENOTSOCK)
		return -1
	}

	if st.BoundAddr != "" {
		setLastError(EINVAL)
		return -1
	}

	addr, err := parseSockAddrIn(name)
	if err != nil {
		setLastError(EINVAL)
		return -1
	}

	st.BoundAddr = addr

	if st.Type == TypeUDP {
		stack, err := GetStack()
		if err != nil {
			setLastError(EHOSTUNREACH)
			return -1
		}
		udpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			setLastError(EINVAL)
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
			setLastError(EHOSTUNREACH)
			return -1
		}
		if st.Protocol != 1 { // IPPROTO_ICMP
			setLastError(EPROTONOSUPPORT)
			return -1
		}
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			setLastError(EINVAL)
			return -1
		}
		netipAddr, err := netip.ParseAddr(host)
		if err != nil {
			setLastError(EINVAL)
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
func Listen(fd int32, backlog int32) int32 {
	LogCall("Listen", fd, backlog)
	st, ok := registry.Get(uint64(fd))
	if !ok {
		setLastError(ENOTSOCK)
		return -1
	}

	addr := st.BoundAddr
	if addr == "" {
		addr = ":0"
	}

	stack, err := GetStack()
	if err != nil {
		setLastError(EHOSTUNREACH)
		return -1
	}

	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		setLastError(EINVAL)
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

// Accept accepts an incoming connection and registers it under the newfd
// number the loader has reserved. Non-blocking sockets return EAGAIN when no
// connection is pending.
func Accept(listenfd int32, newfd int32, addr unsafe.Pointer, addrlen *int32) int32 {
	LogCall("Accept", listenfd, newfd, addr, addrlen)
	st, ok := registry.Get(uint64(listenfd))
	if !ok || st.Listener == nil {
		setLastError(ENOTCONN)
		return -1
	}

	if st.IsNonBlocking && !checkReadReady(st) {
		setLastError(EAGAIN)
		return -1
	}

	conn, err := st.Listener.Accept()
	if err != nil {
		setLastError(mapError(err))
		return -1
	}

	newSt := &SocketState{
		Conn:          conn,
		Type:          st.Type,
		AddressFamily: st.AddressFamily,
		Protocol:      st.Protocol,
		Options:       make(map[int32][]byte),
		Refs:          &refcount{n: 1},
		mu:            &sync.Mutex{},
	}
	if !registry.Register(uint64(newfd), newSt) {
		conn.Close()
		setLastError(EBADF)
		return -1
	}
	UpdateWaiterQueue(newSt)

	// Fill addr with peer info if provided
	if addr != nil && addrlen != nil {
		raddr := conn.RemoteAddr()
		if tcpAddr, ok := raddr.(*net.TCPAddr); ok && tcpAddr.IP.To4() != nil {
			sa := (*struct {
				Family uint16
				Port   uint16
				Addr   [4]byte
				Zero   [8]byte
			})(addr)

			sa.Family = uint16(AF_INET)
			sa.Port = uint16(tcpAddr.Port>>8) | uint16(tcpAddr.Port&0xFF)<<8
			copy(sa.Addr[:], tcpAddr.IP.To4())
			*addrlen = 16
		}
	}

	return 0
}

// goConnect establishes a connection to a specified socket.
func Connect(fd int32, name unsafe.Pointer, namelen int32) int32 {
	LogCall("Connect", fd, name, namelen)
	st, ok := registry.Get(uint64(fd))
	if !ok {
		setLastError(ENOTSOCK)
		return -1
	}

	addr, err := parseSockAddrIn(name)
	if err != nil {
		setLastError(EINVAL)
		return -1
	}

	stack, err := GetStack()
	if err != nil {
		setLastError(EHOSTUNREACH)
		return -1
	}

	if st.Type == TypeUDP {
		raddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			setLastError(EINVAL)
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
			setLastError(EPROTONOSUPPORT)
			return -1
		}
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			setLastError(EINVAL)
			return -1
		}
		raddr, err := netip.ParseAddr(host)
		if err != nil {
			setLastError(EINVAL)
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
		if st.IsNonBlocking {
			// EINPROGRESS: dial in the background; writability signals
			// completion and SO_ERROR carries the result.
			st.DialDone = make(chan struct{})
			go func() {
				if VERBOSE {
					fmt.Printf("kl: async dial %s starting\n", addr)
				}
				conn, err := stack.Dial("tcp", addr)
				if VERBOSE {
					fmt.Printf("kl: async dial %s done err=%v\n", addr, err)
				}
				if err == nil {
					if st.Closed != nil && st.Closed.Load() {
						// app closed the fd while we were dialing:
						// discard the connection, do not adopt it
						conn.Close()
					} else {
						if st.Conn != nil {
							st.Conn.Close()
						}
						st.Conn = conn
						UpdateWaiterQueue(st)
					}
				}
				st.DialErr = err
				close(st.DialDone)
			}()
			setLastError(EINPROGRESS)
			return -1
		}
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
func Shutdown(fd int32, how int32) int32 {
	LogCall("Shutdown", fd, how)
	st, ok := registry.Get(uint64(fd))
	if !ok || st.Conn == nil {
		setLastError(ENOTSOCK)
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
