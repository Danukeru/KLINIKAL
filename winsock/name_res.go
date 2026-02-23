// name_res.go — DNS name resolution and host lookup. Implements getaddrinfo
// (resolves hostnames via netstack.LookupContextHost into a C-compatible addrinfo
// linked list with sockaddr_in/sockaddr_in6, supporting AI_PASSIVE, AI_CANONNAME,
// AI_NUMERICHOST, and AI_NUMERICSERV), freeaddrinfo, getnameinfo (reverse DNS
// simulation via numeric output as netstack lacks reverse lookup), gethostbyname
// (netstack.LookupContextHost into a static hostent buffer), and gethostbyaddr
// (unsupported). Also provides wide-char variants: GetAddrInfoW, FreeAddrInfoW,
// and GetNameInfoW.
package winsock

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/net/dns/dnsmessage"
)

// Socket type constants
const (
	SOCK_STREAM = 1
	SOCK_DGRAM  = 2
)

// Protocol constants
const (
	IPPROTO_UDP = 17
)

// AI_* flags for getaddrinfo hints
const (
	AI_PASSIVE     = 0x0001
	AI_CANONNAME   = 0x0002
	AI_NUMERICHOST = 0x0004
	AI_NUMERICSERV = 0x0008
)

// NI_* flags for getnameinfo
const (
	NI_NOFQDN      = 0x01
	NI_NUMERICHOST = 0x02
	NI_NAMEREQD    = 0x04
	NI_NUMERICSERV = 0x08
	NI_DGRAM       = 0x10
)

// EAI_* error codes (Windows values)
const (
	EAI_MEMORY  = 8
	EAI_NONAME  = 11001
	EAI_AGAIN   = 11002
	EAI_FAIL    = 11003
	EAI_SERVICE = 10109
)

// C-compatible struct addrinfo (matches Windows x64 layout)
// Fields: ai_flags, ai_family, ai_socktype, ai_protocol, ai_addrlen, ai_canonname, ai_addr, ai_next
type CAddrInfo struct {
	Flags     int32
	Family    int32
	Socktype  int32
	Protocol  int32
	Addrlen   uintptr        // size_t
	Canonname *byte          // char* (or wchar_t* for W variant)
	Addr      unsafe.Pointer // sockaddr*
	Next      unsafe.Pointer // addrinfo*
}

// C-compatible sockaddr_in (16 bytes)
type CSockaddrIn struct {
	Family uint16
	Port   uint16
	Addr   [4]byte
	Zero   [8]byte
}

// C-compatible sockaddr_in6 (28 bytes)
type CSockaddrIn6 struct {
	Family   uint16
	Port     uint16
	Flowinfo uint32
	Addr     [16]byte
	ScopeID  uint32
}

// C-compatible hostent
type CHostent struct {
	Name     *byte
	Aliases  **byte
	Addrtype int16
	Length   int16
	// Go auto-pads 4 bytes here on x64 (matching C alignment)
	AddrList **byte
}

// --- Memory management for addrinfo chains ---

type addrInfoAlloc struct {
	nodes  []CAddrInfo
	addrs4 []CSockaddrIn
	addrs6 []CSockaddrIn6
	bufs   [][]byte   // canonical name buffers
	wbufs  [][]uint16 // wide string buffers (keep alive for GC)
}

var (
	aiMu     sync.Mutex
	aiAllocs = map[uintptr]*addrInfoAlloc{}
)

// --- Static hostent buffers (overwritten per call, matches Windows behavior) ---

var (
	staticHostent      CHostent
	staticHostName     [256]byte
	staticHostAddrs    [16][4]byte
	staticHostAddrPtrs [17]*byte
	staticHostAliases  [1]*byte
)

// htons16 swaps bytes of a uint16 to network byte order.
func htons16(v uint16) uint16 {
	return (v >> 8) | (v << 8)
}

// lookupPTR performs a reverse DNS lookup using the configured DNS servers over the WireGuard tunnel.
func lookupPTR(ip net.IP) (string, error) {
	stack, err := GetStack()
	if err != nil {
		return "", err
	}
	dnsServers, err := GetDNS()
	if err != nil || len(dnsServers) == 0 {
		return "", fmt.Errorf("no DNS servers configured")
	}

	// Construct PTR query name
	var arpa string
	if ip4 := ip.To4(); ip4 != nil {
		arpa = fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", ip4[3], ip4[2], ip4[1], ip4[0])
	} else if ip6 := ip.To16(); ip6 != nil {
		var sb strings.Builder
		for i := 15; i >= 0; i-- {
			sb.WriteString(fmt.Sprintf("%x.%x.", ip6[i]&0xf, ip6[i]>>4))
		}
		sb.WriteString("ip6.arpa.")
		arpa = sb.String()
	} else {
		return "", fmt.Errorf("invalid IP")
	}

	name, err := dnsmessage.NewName(arpa)
	if err != nil {
		return "", err
	}

	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 1234, // or random
			Response:           false,
			OpCode:             0,
			Authoritative:      false,
			Truncated:          false,
			RecursionDesired:   true,
			RecursionAvailable: false,
			RCode:              dnsmessage.RCodeSuccess,
		},
		Questions: []dnsmessage.Question{
			{
				Name:  name,
				Type:  dnsmessage.TypePTR,
				Class: dnsmessage.ClassINET,
			},
		},
	}

	packed, err := msg.Pack()
	if err != nil {
		return "", err
	}

	// Try each DNS server
	for _, dns := range dnsServers {
		addr := net.JoinHostPort(dns.String(), "53")
		conn, err := stack.DialContext(context.Background(), "udp", addr)
		if err != nil {
			continue
		}

		conn.SetDeadline(time.Now().Add(2 * time.Second))
		_, err = conn.Write(packed)
		if err != nil {
			conn.Close()
			continue
		}

		buf := make([]byte, 512)
		n, err := conn.Read(buf)
		conn.Close()
		if err != nil {
			continue
		}

		var resp dnsmessage.Message
		if err := resp.Unpack(buf[:n]); err != nil {
			continue
		}

		if resp.Header.RCode != dnsmessage.RCodeSuccess {
			continue
		}

		for _, ans := range resp.Answers {
			if ptr, ok := ans.Body.(*dnsmessage.PTRResource); ok {
				return strings.TrimSuffix(ptr.PTR.String(), "."), nil
			}
		}
	}

	return "", fmt.Errorf("PTR record not found")
}

// --- getaddrinfo ---

func GoGetaddrinfo(node *byte, service *byte, hints unsafe.Pointer, res *unsafe.Pointer) int32 {
	LogCall("Getaddrinfo", node, service, hints, res)

	if res == nil {
		return EAI_FAIL
	}
	*res = nil

	// Parse hints
	var hFlags, hFamily, hSocktype, hProtocol int32
	if hints != nil {
		h := (*CAddrInfo)(hints)
		hFlags = h.Flags
		hFamily = h.Family
		hSocktype = h.Socktype
		hProtocol = h.Protocol
	}

	// Parse service → port
	var port int
	if service != nil {
		svc := goStringFromPtr(service)
		if p, err := strconv.Atoi(svc); err == nil {
			port = p
		} else if (hFlags & AI_NUMERICSERV) != 0 {
			return EAI_SERVICE
		} else {
			proto := "tcp"
			if hSocktype == SOCK_DGRAM {
				proto = "udp"
			}
			p, err := net.LookupPort(proto, svc)
			if err != nil {
				return EAI_SERVICE
			}
			port = p
		}
	}

	// Resolve IPs
	var ips []net.IP
	if node == nil {
		if (hFlags & AI_PASSIVE) != 0 {
			if hFamily == 0 || hFamily == AF_INET {
				ips = append(ips, net.IPv4zero)
			}
			if hFamily == 0 || hFamily == AF_INET6 {
				ips = append(ips, net.IPv6zero)
			}
		} else {
			if hFamily == 0 || hFamily == AF_INET {
				ips = append(ips, net.IPv4(127, 0, 0, 1))
			}
			if hFamily == 0 || hFamily == AF_INET6 {
				ips = append(ips, net.IPv6loopback)
			}
		}
	} else {
		nodeName := goStringFromPtr(node)
		ipAddr := net.ParseIP(nodeName)
		if ipAddr != nil {
			ips = append(ips, ipAddr)
		} else if (hFlags & AI_NUMERICHOST) != 0 {
			return EAI_NONAME
		} else {
			stack, err := GetStack()
			if err != nil {
				return EAI_AGAIN
			}
			resolved, err := stack.LookupContextHost(context.Background(), nodeName)
			if err != nil {
				return EAI_NONAME
			}
			for _, r := range resolved {
				if ip := net.ParseIP(r); ip != nil {
					ips = append(ips, ip)
				}
			}
		}
	}

	// Filter by requested family
	if hFamily != 0 {
		filtered := make([]net.IP, 0, len(ips))
		for _, ip := range ips {
			if hFamily == AF_INET && ip.To4() != nil {
				filtered = append(filtered, ip)
			} else if hFamily == AF_INET6 && ip.To4() == nil {
				filtered = append(filtered, ip)
			}
		}
		ips = filtered
	}

	if len(ips) == 0 {
		return EAI_NONAME
	}

	// Determine socktype/protocol pairs
	type stPair struct {
		socktype int32
		protocol int32
	}
	var pairs []stPair
	if hSocktype != 0 {
		p := hProtocol
		if p == 0 {
			if hSocktype == SOCK_STREAM {
				p = IPPROTO_TCP
			} else if hSocktype == SOCK_DGRAM {
				p = IPPROTO_UDP
			}
		}
		pairs = append(pairs, stPair{hSocktype, p})
	} else {
		pairs = append(pairs, stPair{SOCK_STREAM, IPPROTO_TCP})
		pairs = append(pairs, stPair{SOCK_DGRAM, IPPROTO_UDP})
	}

	// Count IPv4 vs IPv6 for pre-allocation
	var n4, n6 int
	for _, ip := range ips {
		if ip.To4() != nil {
			n4++
		} else {
			n6++
		}
	}

	totalNodes := len(ips) * len(pairs)
	alloc := &addrInfoAlloc{
		nodes:  make([]CAddrInfo, totalNodes),
		addrs4: make([]CSockaddrIn, n4*len(pairs)),
		addrs6: make([]CSockaddrIn6, n6*len(pairs)),
	}

	idx, i4, i6 := 0, 0, 0
	netPort := htons16(uint16(port))

	for _, ip := range ips {
		for _, pair := range pairs {
			info := &alloc.nodes[idx]
			info.Flags = hFlags
			info.Socktype = pair.socktype
			info.Protocol = pair.protocol

			if ip.To4() != nil {
				sa := &alloc.addrs4[i4]
				sa.Family = uint16(AF_INET)
				sa.Port = netPort
				copy(sa.Addr[:], ip.To4())
				info.Family = AF_INET
				info.Addr = unsafe.Pointer(sa)
				info.Addrlen = unsafe.Sizeof(CSockaddrIn{})
				i4++
			} else {
				sa := &alloc.addrs6[i6]
				sa.Family = uint16(AF_INET6)
				sa.Port = netPort
				copy(sa.Addr[:], ip.To16())
				info.Family = AF_INET6
				info.Addr = unsafe.Pointer(sa)
				info.Addrlen = unsafe.Sizeof(CSockaddrIn6{})
				i6++
			}

			// Chain to next
			if idx+1 < totalNodes {
				info.Next = unsafe.Pointer(&alloc.nodes[idx+1])
			}

			idx++
		}
	}

	// Handle AI_CANONNAME — set on first result only
	if (hFlags&AI_CANONNAME) != 0 && node != nil {
		nodeName := goStringFromPtr(node)
		cname := nodeName // Use the original hostname as canonical name
		// Removed net.LookupCNAME to avoid DNS leak outside the tunnel
		cname = strings.TrimSuffix(cname, ".")
		buf := make([]byte, len(cname)+1)
		copy(buf, cname)
		buf[len(cname)] = 0
		alloc.nodes[0].Canonname = &buf[0]
		alloc.bufs = append(alloc.bufs, buf)
	}

	// Store allocation and return
	firstPtr := unsafe.Pointer(&alloc.nodes[0])
	aiMu.Lock()
	aiAllocs[uintptr(firstPtr)] = alloc
	aiMu.Unlock()

	*res = firstPtr
	return 0
}

// --- freeaddrinfo ---

func GoFreeaddrinfo(ai unsafe.Pointer) {
	LogCall("Freeaddrinfo", ai)
	if ai == nil {
		return
	}
	aiMu.Lock()
	delete(aiAllocs, uintptr(ai))
	aiMu.Unlock()
}

// --- getnameinfo ---

func GoGetnameinfo(sa unsafe.Pointer, salen int32, host *byte, hostlen uint32, serv *byte, servlen uint32, flags int32) int32 {
	LogCall("Getnameinfo", sa, salen, host, hostlen, serv, servlen, flags)

	if sa == nil {
		return EAI_FAIL
	}

	family := *(*uint16)(sa)
	var ip net.IP
	var port uint16

	switch int32(family) {
	case AF_INET:
		sin := (*CSockaddrIn)(sa)
		ip = net.IPv4(sin.Addr[0], sin.Addr[1], sin.Addr[2], sin.Addr[3])
		port = htons16(sin.Port)
	case AF_INET6:
		sin6 := (*CSockaddrIn6)(sa)
		ip = make(net.IP, 16)
		copy(ip, sin6.Addr[:])
		port = htons16(sin6.Port)
	default:
		return EAI_FAIL
	}

	// Fill host buffer
	if host != nil && hostlen > 0 {
		var hostStr string
		if (flags & NI_NUMERICHOST) != 0 {
			hostStr = ip.String()
		} else {
			// Try reverse DNS lookup
			ptr, err := lookupPTR(ip)
			if err == nil && ptr != "" {
				hostStr = ptr
			} else if (flags & NI_NAMEREQD) == 0 {
				hostStr = ip.String()
			} else {
				return EAI_NONAME // PTR not found and NAMEREQD
			}
		}

		if uint32(len(hostStr)+1) > hostlen {
			return EAI_MEMORY
		}
		out := unsafe.Slice(host, hostlen)
		copy(out, hostStr)
		out[len(hostStr)] = 0
	}

	// Fill service buffer
	if serv != nil && servlen > 0 {
		var svcStr string
		if (flags & NI_NUMERICSERV) != 0 {
			svcStr = strconv.Itoa(int(port))
		} else {
			proto := "tcp"
			if (flags & NI_DGRAM) != 0 {
				proto = "udp"
			}
			found := false
			for i := range servTable {
				if servTable[i].Port == int16(port) && strings.ToLower(servTable[i].Proto) == proto {
					svcStr = servTable[i].Name
					found = true
					break
				}
			}
			if !found {
				svcStr = strconv.Itoa(int(port))
			}
		}
		if uint32(len(svcStr)+1) > servlen {
			return EAI_MEMORY
		}
		out := unsafe.Slice(serv, servlen)
		copy(out, svcStr)
		out[len(svcStr)] = 0
	}

	return 0
}

// --- gethostbyname ---

func GoGethostbyname(name *byte) unsafe.Pointer {
	LogCall("Gethostbyname", name)
	if name == nil {
		setLastError(WSAEINVAL)
		return nil
	}

	hostname := goStringFromPtr(name)

	// Try numeric first
	ip := net.ParseIP(hostname)
	var addrs []net.IP
	if ip != nil {
		if ip.To4() != nil {
			addrs = []net.IP{ip}
		}
	} else {
		stack, err := GetStack()
		if err != nil {
			setLastError(EAI_NONAME)
			return nil
		}
		resolved, err := stack.LookupContextHost(context.Background(), hostname)
		if err != nil {
			setLastError(EAI_NONAME) // WSAHOST_NOT_FOUND
			return nil
		}
		for _, r := range resolved {
			if pip := net.ParseIP(r); pip != nil && pip.To4() != nil {
				addrs = append(addrs, pip)
			}
		}
	}

	if len(addrs) == 0 {
		setLastError(EAI_NONAME)
		return nil
	}

	// Fill static hostent
	copy(staticHostName[:], hostname)
	staticHostName[len(hostname)] = 0
	staticHostent.Name = &staticHostName[0]

	staticHostAliases[0] = nil
	staticHostent.Aliases = &staticHostAliases[0]

	staticHostent.Addrtype = int16(AF_INET)
	staticHostent.Length = 4

	count := len(addrs)
	if count > 16 {
		count = 16
	}
	for i := 0; i < count; i++ {
		copy(staticHostAddrs[i][:], addrs[i].To4())
		staticHostAddrPtrs[i] = &staticHostAddrs[i][0]
	}
	staticHostAddrPtrs[count] = nil
	staticHostent.AddrList = &staticHostAddrPtrs[0]

	return unsafe.Pointer(&staticHostent)
}

// --- gethostbyaddr ---

func GoGethostbyaddr(addr *byte, addrLen int32, addrType int32) unsafe.Pointer {
	LogCall("Gethostbyaddr", addr, addrLen, addrType)
	if addr == nil {
		setLastError(WSAEINVAL)
		return nil
	}

	var ip net.IP
	if addrType == AF_INET && addrLen == 4 {
		ip = net.IPv4(*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(addr)))),
			*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(addr)) + 1)),
			*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(addr)) + 2)),
			*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(addr)) + 3)))
	} else if addrType == AF_INET6 && addrLen == 16 {
		ip = make(net.IP, 16)
		for i := 0; i < 16; i++ {
			ip[i] = *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(addr)) + uintptr(i)))
		}
	} else {
		setLastError(WSAEAFNOSUPPORT)
		return nil
	}

	hostname, err := lookupPTR(ip)
	if err != nil || hostname == "" {
		setLastError(EAI_NONAME)
		return nil
	}

	// Fill static hostent
	copy(staticHostName[:], hostname)
	staticHostName[len(hostname)] = 0
	staticHostent.Name = &staticHostName[0]

	staticHostAliases[0] = nil
	staticHostent.Aliases = &staticHostAliases[0]

	staticHostent.Addrtype = int16(addrType)
	staticHostent.Length = int16(addrLen)

	if addrType == AF_INET {
		copy(staticHostAddrs[0][:], ip.To4())
	} else {
		copy(staticHostAddrs[0][:], ip.To16())
	}
	staticHostAddrPtrs[0] = &staticHostAddrs[0][0]
	staticHostAddrPtrs[1] = nil
	staticHostent.AddrList = &staticHostAddrPtrs[0]

	return unsafe.Pointer(&staticHostent)
}

// --- Wide-char variants ---

// GoGetAddrInfoW is the wide-char variant of getaddrinfo.
func GoGetAddrInfoW(node *uint16, service *uint16, hints unsafe.Pointer, res *unsafe.Pointer) int32 {
	LogCall("GetAddrInfoW", node, service, hints, res)

	// Convert wide strings to Go strings, then call the core resolution logic
	var nodeB, serviceB *byte
	var nodeBuf, serviceBuf []byte

	if node != nil {
		s := goStringFromWPtr(node)
		nodeBuf = append([]byte(s), 0)
		nodeB = &nodeBuf[0]
	}
	if service != nil {
		s := goStringFromWPtr(service)
		serviceBuf = append([]byte(s), 0)
		serviceB = &serviceBuf[0]
	}

	ret := GoGetaddrinfo(nodeB, serviceB, hints, res)
	if ret != 0 {
		return ret
	}

	// Patch canonical name to UTF-16 if AI_CANONNAME was requested
	if *res != nil {
		first := (*CAddrInfo)(*res)
		if first.Canonname != nil {
			canon := goStringFromPtr(first.Canonname)
			u16 := utf16.Encode([]rune(canon))
			wbuf := make([]uint16, len(u16)+1)
			copy(wbuf, u16)
			wbuf[len(u16)] = 0
			first.Canonname = (*byte)(unsafe.Pointer(&wbuf[0]))

			// Keep wbuf alive via the alloc
			aiMu.Lock()
			if a, ok := aiAllocs[uintptr(*res)]; ok {
				a.wbufs = append(a.wbufs, wbuf) // Direct slice reference — GC-safe
			}
			aiMu.Unlock()
		}
	}

	return 0
}

// GoFreeAddrInfoW is the wide-char variant of freeaddrinfo.
func GoFreeAddrInfoW(ai unsafe.Pointer) {
	LogCall("FreeAddrInfoW", ai)
	GoFreeaddrinfo(ai)
}

// GoGetNameInfoW is the wide-char variant of getnameinfo.
func GoGetNameInfoW(sa unsafe.Pointer, salen int32, host *uint16, hostlen uint32, serv *uint16, servlen uint32, flags int32) int32 {
	LogCall("GetNameInfoW", sa, salen, host, hostlen, serv, servlen, flags)

	// Use ANSI variant with temp buffers, then convert to UTF-16
	var hostBuf [256]byte
	var servBuf [64]byte
	var hostP *byte
	var servP *byte
	var hLen, sLen uint32

	if host != nil && hostlen > 0 {
		hostP = &hostBuf[0]
		hLen = 256
	}
	if serv != nil && servlen > 0 {
		servP = &servBuf[0]
		sLen = 64
	}

	ret := GoGetnameinfo(sa, salen, hostP, hLen, servP, sLen, flags)
	if ret != 0 {
		return ret
	}

	// Copy results as UTF-16
	if host != nil && hostlen > 0 {
		s := goStringFromPtr(&hostBuf[0])
		u16 := utf16.Encode([]rune(s))
		if uint32(len(u16)+1) > hostlen {
			return EAI_MEMORY
		}
		out := unsafe.Slice(host, hostlen)
		copy(out, u16)
		out[len(u16)] = 0
	}

	if serv != nil && servlen > 0 {
		s := goStringFromPtr(&servBuf[0])
		u16 := utf16.Encode([]rune(s))
		if uint32(len(u16)+1) > servlen {
			return EAI_MEMORY
		}
		out := unsafe.Slice(serv, servlen)
		copy(out, u16)
		out[len(u16)] = 0
	}

	return 0
}
