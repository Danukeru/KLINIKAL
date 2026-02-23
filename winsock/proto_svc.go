// proto_svc.go — Protocol and service database lookups. Implements getprotobyname
// and getprotobynumber using a static protocol table (icmp, igmp, tcp, udp, ipv6,
// icmpv6) that returns C-compatible PROTOENT structs. Implements getservbyname
// (with net.LookupPort fallback) and getservbyport using a static service table
// of 16 common entries (http, https, ssh, smtp, dns, etc.) returning SERVENT
// structs. Also stubs WSAEnumProtocolsA/W.
package winsock

import (
"net"
"strings"
"unsafe"
)

// --- Protocol Database ---

type protoEntry struct {
Name    string
Aliases []string
Number  int16
}

var protoTable = []protoEntry{
{"icmp", []string{"ICMP"}, 1},
{"igmp", []string{"IGMP"}, 2},
{"tcp", []string{"TCP"}, 6},
{"udp", []string{"UDP"}, 17},
{"ipv6", []string{"IPv6"}, 41},
{"icmpv6", []string{"ICMPv6"}, 58},
}

// C-compatible protoent struct layout (matches exports.go typedef)
type cProtoent struct {
Name    *byte
Aliases **byte
Proto   int16
}

// Static buffers for the returned protoent (not thread-safe, matches Windows behavior)
var (
staticProtoent      cProtoent
staticProtoName     [64]byte
staticProtoAlias    [64]byte
staticProtoAliasPtr [2]*byte
)

func fillProtoent(e *protoEntry) unsafe.Pointer {
copy(staticProtoName[:], e.Name)
staticProtoName[len(e.Name)] = 0
staticProtoent.Name = &staticProtoName[0]

if len(e.Aliases) > 0 {
copy(staticProtoAlias[:], e.Aliases[0])
staticProtoAlias[len(e.Aliases[0])] = 0
staticProtoAliasPtr[0] = &staticProtoAlias[0]
} else {
staticProtoAliasPtr[0] = nil
}
staticProtoAliasPtr[1] = nil
staticProtoent.Aliases = &staticProtoAliasPtr[0]

staticProtoent.Proto = e.Number
return unsafe.Pointer(&staticProtoent)
}

func GoGetprotobyname(name *byte) unsafe.Pointer {
LogCall("Getprotobyname", name)
if name == nil {
return nil
}
search := strings.ToLower(goStringFromPtr(name))
for i := range protoTable {
if strings.ToLower(protoTable[i].Name) == search {
return fillProtoent(&protoTable[i])
}
for _, alias := range protoTable[i].Aliases {
if strings.ToLower(alias) == search {
return fillProtoent(&protoTable[i])
}
}
}
return nil
}

func GoGetprotobynumber(proto int32) unsafe.Pointer {
LogCall("Getprotobynumber", proto)
for i := range protoTable {
if int32(protoTable[i].Number) == proto {
return fillProtoent(&protoTable[i])
}
}
return nil
}

// --- Service Database ---

type servEntry struct {
Name    string
Aliases []string
Port    int16
Proto   string
}

var servTable = []servEntry{
{"echo", nil, 7, "tcp"},
{"echo", nil, 7, "udp"},
{"ftp-data", nil, 20, "tcp"},
{"ftp", nil, 21, "tcp"},
{"ssh", nil, 22, "tcp"},
{"telnet", nil, 23, "tcp"},
{"smtp", []string{"mail"}, 25, "tcp"},
{"domain", []string{"dns"}, 53, "tcp"},
{"domain", []string{"dns"}, 53, "udp"},
{"http", []string{"www"}, 80, "tcp"},
{"pop3", nil, 110, "tcp"},
{"imap", nil, 143, "tcp"},
{"https", nil, 443, "tcp"},
{"smtps", nil, 465, "tcp"},
{"imaps", nil, 993, "tcp"},
{"pop3s", nil, 995, "tcp"},
}

// C-compatible servent struct layout (matches exports.go typedef)
type cServent struct {
Name    *byte
Aliases **byte
Port    int16 // network byte order
Proto   *byte
}

var (
staticServent      cServent
staticServName     [64]byte
staticServAlias    [64]byte
staticServAliasPtr [2]*byte
staticServProto    [16]byte
)

func fillServent(e *servEntry) unsafe.Pointer {
copy(staticServName[:], e.Name)
staticServName[len(e.Name)] = 0
staticServent.Name = &staticServName[0]

if len(e.Aliases) > 0 {
copy(staticServAlias[:], e.Aliases[0])
staticServAlias[len(e.Aliases[0])] = 0
staticServAliasPtr[0] = &staticServAlias[0]
} else {
staticServAliasPtr[0] = nil
}
staticServAliasPtr[1] = nil
staticServent.Aliases = &staticServAliasPtr[0]

// Port in network byte order (big-endian)
p := uint16(e.Port)
staticServent.Port = int16(p<<8 | p>>8)

copy(staticServProto[:], e.Proto)
staticServProto[len(e.Proto)] = 0
staticServent.Proto = &staticServProto[0]

return unsafe.Pointer(&staticServent)
}

func GoGetservbyname(name *byte, proto *byte) unsafe.Pointer {
LogCall("Getservbyname", name, proto)
if name == nil {
return nil
}
search := strings.ToLower(goStringFromPtr(name))
var protoFilter string
if proto != nil {
protoFilter = strings.ToLower(goStringFromPtr(proto))
}

for i := range servTable {
if protoFilter != "" && strings.ToLower(servTable[i].Proto) != protoFilter {
continue
}
if strings.ToLower(servTable[i].Name) == search {
return fillServent(&servTable[i])
}
for _, alias := range servTable[i].Aliases {
if strings.ToLower(alias) == search {
return fillServent(&servTable[i])
}
}
}

// Fallback: try Go's net.LookupPort
netProto := "tcp"
if protoFilter != "" {
netProto = protoFilter
}
port, err := net.LookupPort(netProto, search)
if err == nil {
dynamic := &servEntry{Name: search, Port: int16(port), Proto: netProto}
return fillServent(dynamic)
}

return nil
}

func GoGetservbyport(port int32, proto *byte) unsafe.Pointer {
LogCall("Getservbyport", port, proto)
// port comes in network byte order
p := uint16(port)
hostPort := int16(p<<8 | p>>8)

var protoFilter string
if proto != nil {
protoFilter = strings.ToLower(goStringFromPtr(proto))
}

for i := range servTable {
if protoFilter != "" && strings.ToLower(servTable[i].Proto) != protoFilter {
continue
}
if servTable[i].Port == hostPort {
return fillServent(&servTable[i])
}
}
return nil
}

// WSAEnumProtocolsA retrieves information about available transport protocols. (ANSI)
func GoWSAEnumProtocolsA(lpiProtocols *int32, lpProtocolBuffer unsafe.Pointer, lpdwBufferLength *uint32) int32 {
LogCall("WSAEnumProtocolsA", lpiProtocols, lpProtocolBuffer, lpdwBufferLength)
return 0
}

// WSAEnumProtocolsW retrieves information about available transport protocols. (Unicode)
func GoWSAEnumProtocolsW(lpiProtocols *int32, lpProtocolBuffer unsafe.Pointer, lpdwBufferLength *uint32) int32 {
LogCall("WSAEnumProtocolsW", lpiProtocols, lpProtocolBuffer, lpdwBufferLength)
return 0
}
