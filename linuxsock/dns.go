// DNS and address resolution: getaddrinfo (resolution through the netstack
// DNS context, producing a glibc-layout addrinfo chain), freeaddrinfo, and
// getnameinfo (with reverse-PTR lookup). All struct layouts and EAI/AI/NI
// codes are the Linux/glibc ones.
package linuxsock

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
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
	AI_NUMERICSERV = 0x400
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
// glibc EAI_ error codes
const (
	EAI_BADFLAGS = -1
	EAI_NONAME   = -2
	EAI_AGAIN    = -3
	EAI_FAIL     = -4
	EAI_FAMILY   = -6
	EAI_SOCKTYPE = -8
	EAI_SERVICE  = -8
	EAI_MEMORY   = -10
	EAI_SYSTEM   = -11
	EAI_OVERFLOW = -12
)

// struct addrinfo, glibc x86-64 layout:
// ai_flags/ai_family/ai_socktype/ai_protocol (4x int32), ai_addrlen (socklen_t
// = uint32 + 4 bytes of alignment padding), ai_addr, ai_next, ai_canonname.
type CAddrInfo struct {
	Flags     int32
	Family    int32
	Socktype  int32
	Protocol  int32
	Addrlen   uint32
	_         uint32
	Addr      unsafe.Pointer // sockaddr*
	Next      unsafe.Pointer // addrinfo*
	Canonname *byte          // char*
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

// --- Memory management for addrinfo chains ---

// addrInfoAlloc keeps every piece of memory a returned addrinfo chain
// points into alive on the Go side. freeaddrinfo drops the entry and
// GC reclaims; go_addrinfo_owned consults the map so the C loader can
// tell Go-owned chains from libc ones.
type addrInfoAlloc struct {
	nodes  []CAddrInfo
	addrs4 []CSockaddrIn
	addrs6 []CSockaddrIn6
	bufs   [][]byte   // canonical name buffers
	wbufs  [][]uint16 // wide string buffers (keep alive for GC)
}

// aiAllocs keys the head pointer of each handed-out chain to its
// owner record (ownership predicate; no fixed-size C table).
var (
	aiMu     sync.Mutex
	aiAllocs = map[uintptr]*addrInfoAlloc{}
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

// Getaddrinfo resolves node/service into a glibc-layout addrinfo chain
// (socklen_t addrlen, Linux AF values, negative glibc EAI codes).
// Resolution goes through the tunnel's DNS; a 5s context deadline bounds
// it. Static service/proto names come from services.go without lookup.
func Getaddrinfo(node *byte, service *byte, hints unsafe.Pointer, res *unsafe.Pointer) int32 {
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
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			resolved, err := stack.LookupContextHost(ctx, nodeName)
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
				info.Addrlen = uint32(unsafe.Sizeof(CSockaddrIn{}))
				i4++
			} else {
				sa := &alloc.addrs6[i6]
				sa.Family = uint16(AF_INET6)
				sa.Port = netPort
				copy(sa.Addr[:], ip.To16())
				info.Family = AF_INET6
				info.Addr = unsafe.Pointer(sa)
				info.Addrlen = uint32(unsafe.Sizeof(CSockaddrIn6{}))
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

// AddrinfoOwned reports whether ai is the head of a chain this package
// allocated (the loader asks before deciding free-vs-passthrough).
func AddrinfoOwned(ai unsafe.Pointer) bool {
	aiMu.Lock()
	defer aiMu.Unlock()
	_, ok := aiAllocs[uintptr(ai)]
	return ok
}

// --- freeaddrinfo ---

// Freeaddrinfo releases the Go-side owner for the chain head.
func Freeaddrinfo(ai unsafe.Pointer) {
	LogCall("Freeaddrinfo", ai)
	if ai == nil {
		return
	}
	aiMu.Lock()
	delete(aiAllocs, uintptr(ai))
	aiMu.Unlock()
}

// --- getnameinfo ---

// GoGetnameinfo is the inverse: numeric-by-default formatting of a
// sockaddr into host/service buffers (NI_NAMEREQD would require
// reverse DNS, which is not attempted).
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