// proto_svc.go — Protocol and service database lookups. Implements getprotobyname
// and getprotobynumber using a static protocol table (icmp, igmp, tcp, udp, ipv6,
// icmpv6) that returns C-compatible PROTOENT structs. Implements getservbyname
// (with net.LookupPort fallback) and getservbyport using a static service table
// of 16 common entries (http, https, ssh, smtp, dns, etc.) returning SERVENT
// structs.
package linuxsock

import (
"unsafe"
)

// --- Protocol Database ---

// Static protocol/service tables: getaddrinfo resolves well-known
// names without a lookup, and getprotobyname/getservbyname serve from
// here. Tables mirror /etc/services well-known ports.
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

// fillProtoent writes a protoent in libc layout into the shared
// static buffers (the returned pointer stays valid until the next
// call — same aliasing contract as libc's getprotoent).
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

// fillServent writes a servent in libc layout into shared statics.
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