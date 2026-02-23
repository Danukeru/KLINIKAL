package main

/*

typedef unsigned short WORD;

typedef struct protoent {
    char *p_name;
    char **p_aliases;
    short p_proto;
} PROTOENT;

typedef struct servent {
    char *s_name;
    char **s_aliases;
    short s_port;
    char *s_proto;
} SERVENT;

typedef struct addrinfoa {
    int ai_flags;
    int ai_family;
    int ai_socktype;
    int ai_protocol;
    unsigned long ai_addrlen;
    char *ai_canonname;
    void *ai_addr;
    struct addrinfoa *ai_next;
} ADDRINFOA;

typedef struct hostent {
    char *h_name;
    char **h_aliases;
    short h_addrtype;
    short h_length;
    char **h_addr_list;
} HOSTENT;

*/

import (
	"C"
	"unsafe"

	"klinikal/winsock"
)

// --- Win32 SOCKET = unsigned int (4 bytes) ---

//export go_accept
func go_accept(s C.uint, addr unsafe.Pointer, addrlen *C.int) C.uint {
	return C.uint(winsock.GoAccept(uint64(s), addr, (*int32)(unsafe.Pointer(addrlen))))
}

//export go_bind
func go_bind(s C.uint, name unsafe.Pointer, namelen C.int) C.int {
	return C.int(winsock.GoBind(uint64(s), name, int32(namelen)))
}

//export go_closesocket
func go_closesocket(s C.uint) C.int {
	return C.int(winsock.GoClosesocket(uint64(s)))
}

//export go_connect
func go_connect(s C.uint, name unsafe.Pointer, namelen C.int) C.int {
	return C.int(winsock.GoConnect(uint64(s), name, int32(namelen)))
}

//export go_freeaddrinfo
func go_freeaddrinfo(ai unsafe.Pointer) {
	winsock.GoFreeaddrinfo(ai)
}

//export go_FreeAddrInfoW
func go_FreeAddrInfoW(ai unsafe.Pointer) {
	winsock.GoFreeAddrInfoW(ai)
}

//export go_getaddrinfo
func go_getaddrinfo(node *C.char, service *C.char, hints unsafe.Pointer, res *unsafe.Pointer) C.int {
	return C.int(winsock.GoGetaddrinfo((*byte)(unsafe.Pointer(node)), (*byte)(unsafe.Pointer(service)), hints, res))
}

//export go_GetAddrInfoW
func go_GetAddrInfoW(node *C.ushort, service *C.ushort, hints unsafe.Pointer, res *unsafe.Pointer) C.int {
	return C.int(winsock.GoGetAddrInfoW((*uint16)(unsafe.Pointer(node)), (*uint16)(unsafe.Pointer(service)), hints, res))
}

//export go_gethostbyaddr
func go_gethostbyaddr(addr *C.char, addrLen C.int, addrType C.int) unsafe.Pointer {
	return winsock.GoGethostbyaddr((*byte)(unsafe.Pointer(addr)), int32(addrLen), int32(addrType))
}

//export go_gethostbyname
func go_gethostbyname(name *C.char) unsafe.Pointer {
	return winsock.GoGethostbyname((*byte)(unsafe.Pointer(name)))
}

//export go_GetHostNameW
func go_GetHostNameW(name *C.ushort, namelen C.int) C.int {
	return C.int(winsock.GoGetHostNameW((*uint16)(unsafe.Pointer(name)), int32(namelen)))
}

//export go_gethostname
func go_gethostname(name *C.char, namelen C.int) C.int {
	return C.int(winsock.GoGethostname((*byte)(unsafe.Pointer(name)), int32(namelen)))
}

//export go_getnameinfo
func go_getnameinfo(sa unsafe.Pointer, salen C.int, host *C.char, hostlen C.ulong, serv *C.char, servlen C.ulong, flags C.int) C.int {
	return C.int(winsock.GoGetnameinfo(sa, int32(salen), (*byte)(unsafe.Pointer(host)), uint32(hostlen), (*byte)(unsafe.Pointer(serv)), uint32(servlen), int32(flags)))
}

//export go_GetNameInfoW
func go_GetNameInfoW(sa unsafe.Pointer, salen C.int, host *C.ushort, hostlen C.ulong, serv *C.ushort, servlen C.ulong, flags C.int) C.int {
	return C.int(winsock.GoGetNameInfoW(sa, int32(salen), (*uint16)(unsafe.Pointer(host)), uint32(hostlen), (*uint16)(unsafe.Pointer(serv)), uint32(servlen), int32(flags)))
}

//export go_getpeername
func go_getpeername(s C.uint, name unsafe.Pointer, namelen *C.int) C.int {
	return C.int(winsock.GoGetpeername(uint64(s), name, (*int32)(unsafe.Pointer(namelen))))
}

//export go_getprotobyname
func go_getprotobyname(name *C.char) unsafe.Pointer {
	return unsafe.Pointer(winsock.GoGetprotobyname((*byte)(unsafe.Pointer(name))))
}

//export go_getprotobynumber
func go_getprotobynumber(proto C.int) unsafe.Pointer {
	return unsafe.Pointer(winsock.GoGetprotobynumber(int32(proto)))
}

//export go_getservbyname
func go_getservbyname(name *C.char, proto *C.char) unsafe.Pointer {
	return unsafe.Pointer(winsock.GoGetservbyname((*byte)(unsafe.Pointer(name)), (*byte)(unsafe.Pointer(proto))))
}

//export go_getservbyport
func go_getservbyport(port C.int, proto *C.char) unsafe.Pointer {
	return unsafe.Pointer(winsock.GoGetservbyport(int32(port), (*byte)(unsafe.Pointer(proto))))
}

//export go_getsockname
func go_getsockname(s C.uint, name unsafe.Pointer, namelen *C.int) C.int {
	return C.int(winsock.GoGetsockname(uint64(s), name, (*int32)(unsafe.Pointer(namelen))))
}

//export go_getsockopt
func go_getsockopt(s C.uint, level C.int, optname C.int, optval unsafe.Pointer, optlen *C.int) C.int {
	return C.int(winsock.GoGetsockopt(uint64(s), int32(level), int32(optname), optval, (*int32)(unsafe.Pointer(optlen))))
}

//export go_htond
func go_htond(hostdouble C.double) C.double {
	return C.double(winsock.GoHtond(float64(hostdouble)))
}

//export go_htonf
func go_htonf(hostfloat C.float) C.float {
	return C.float(winsock.GoHtonf(float32(hostfloat)))
}

//export go_htonl
func go_htonl(hostlong C.ulong) C.ulong {
	return C.ulong(winsock.GoHtonl(uint32(hostlong)))
}

//export go_htonll
func go_htonll(hostlonglong C.ulonglong) C.ulonglong {
	return C.ulonglong(winsock.GoHtonll(uint64(hostlonglong)))
}

//export go_htons
func go_htons(hostshort C.ushort) C.ushort {
	return C.ushort(winsock.GoHtons(uint16(hostshort)))
}

//export go_inet_addr
func go_inet_addr(cp *C.char) C.ulong {
	return C.ulong(winsock.GoInet_addr((*byte)(unsafe.Pointer(cp))))
}

//export go_inet_ntoa
func go_inet_ntoa(in C.ulong) *C.char {
	return (*C.char)(unsafe.Pointer(winsock.GoInet_ntoa(uint32(in))))
}

//export go_inet_pton
func go_inet_pton(family C.int, src *C.char, dst unsafe.Pointer) C.int {
	return C.int(winsock.GoInet_pton(int32(family), (*byte)(unsafe.Pointer(src)), dst))
}

//export go_inet_ntop
func go_inet_ntop(family C.int, src unsafe.Pointer, dst *C.char, size C.int) *C.char {
	return (*C.char)(unsafe.Pointer(winsock.GoInet_ntop(int32(family), src, (*byte)(unsafe.Pointer(dst)), int32(size))))
}

//export go_InetPtonW
func go_InetPtonW(family C.int, src *C.ushort, dst unsafe.Pointer) C.int {
	return C.int(winsock.GoInetPtonW(int32(family), (*uint16)(unsafe.Pointer(src)), dst))
}

//export go_InetNtopW
func go_InetNtopW(family C.int, src unsafe.Pointer, dst *C.ushort, size C.int) *C.ushort {
	return (*C.ushort)(unsafe.Pointer(winsock.GoInetNtopW(int32(family), src, (*uint16)(unsafe.Pointer(dst)), int32(size))))
}

//export go_ioctlsocket
func go_ioctlsocket(s C.uint, cmd C.int, argp *C.ulong) C.int {
	return C.int(winsock.GoIoctlsocket(uint64(s), int32(cmd), (*uint32)(unsafe.Pointer(argp))))
}

//export go_listen
func go_listen(s C.uint, backlog C.int) C.int {
	return C.int(winsock.GoListen(uint64(s), int32(backlog)))
}

//export go_ntohd
func go_ntohd(netdouble C.double) C.double {
	return C.double(winsock.GoNtohd(float64(netdouble)))
}

//export go_ntohf
func go_ntohf(netfloat C.float) C.float {
	return C.float(winsock.GoNtohf(float32(netfloat)))
}

//export go_ntohl
func go_ntohl(netlong C.ulong) C.ulong {
	return C.ulong(winsock.GoNtohl(uint32(netlong)))
}

//export go_ntohll
func go_ntohll(netlonglong C.ulonglong) C.ulonglong {
	return C.ulonglong(winsock.GoNtohll(uint64(netlonglong)))
}

//export go_ntohs
func go_ntohs(netshort C.ushort) C.ushort {
	return C.ushort(winsock.GoNtohs(uint16(netshort)))
}

//export go_ProcessSocketNotifications
func go_ProcessSocketNotifications(completionPort unsafe.Pointer, registrationCount C.uint, registrationInfos unsafe.Pointer, timeout C.uint, completionCount C.uint, completionInfos unsafe.Pointer, receivedCount *C.ulong) C.int {
	return C.int(winsock.GoProcessSocketNotifications(completionPort, uint32(registrationCount), registrationInfos, uint32(timeout), uint32(completionCount), completionInfos, (*uint32)(unsafe.Pointer(receivedCount))))
}

//export go_recv
func go_recv(s C.uint, buf unsafe.Pointer, len C.int, flags C.int) C.int {
	return C.int(winsock.GoRecv(uint64(s), buf, int32(len), int32(flags)))
}

//export go_recvfrom
func go_recvfrom(s C.uint, buf unsafe.Pointer, len C.int, flags C.int, from unsafe.Pointer, fromlen *C.int) C.int {
	return C.int(winsock.GoRecvfrom(uint64(s), buf, int32(len), int32(flags), from, (*int32)(unsafe.Pointer(fromlen))))
}

//export go_select_
func go_select_(nfds C.int, readfds unsafe.Pointer, writefds unsafe.Pointer, exceptfds unsafe.Pointer, timeout unsafe.Pointer) C.int {
	return C.int(winsock.GoSelect(int32(nfds), readfds, writefds, exceptfds, timeout))
}

//export go_send
func go_send(s C.uint, buf unsafe.Pointer, len C.int, flags C.int) C.int {
	return C.int(winsock.GoSend(uint64(s), buf, int32(len), int32(flags)))
}

//export go_sendto
func go_sendto(s C.uint, buf unsafe.Pointer, len C.int, flags C.int, to unsafe.Pointer, tolen C.int) C.int {
	return C.int(winsock.GoSendto(uint64(s), buf, int32(len), int32(flags), to, int32(tolen)))
}

//export go_setsockopt
func go_setsockopt(s C.uint, level C.int, optname C.int, optval unsafe.Pointer, optlen C.int) C.int {
	return C.int(winsock.GoSetsockopt(uint64(s), int32(level), int32(optname), optval, int32(optlen)))
}

//export go_shutdown
func go_shutdown(s C.uint, how C.int) C.int {
	return C.int(winsock.GoShutdown(uint64(s), int32(how)))
}

//export go_socket
func go_socket(af C.int, typ C.int, protocol C.int) C.uint {
	return C.uint(winsock.GoSocket(int32(af), int32(typ), int32(protocol)))
}

//export go_SocketNotificationRetrieveEvents
func go_SocketNotificationRetrieveEvents(notificationRegistration unsafe.Pointer, notificationEvents unsafe.Pointer) C.int {
	return C.int(winsock.GoSocketNotificationRetrieveEvents(notificationRegistration, notificationEvents))
}

//export go_WSAAccept
func go_WSAAccept(s C.uint, addr unsafe.Pointer, addrlen *C.int, lpfnCondition unsafe.Pointer, dwCallbackData C.ulong) C.uint {
	return C.uint(winsock.GoWSAAccept(uint64(s), addr, (*int32)(unsafe.Pointer(addrlen)), lpfnCondition, uint32(dwCallbackData)))
}

//export go_WSAAddressToStringA
func go_WSAAddressToStringA(lpsaAddress unsafe.Pointer, dwAddressLength C.ulong, lpProtocolInfo unsafe.Pointer, lpszAddressString *C.char, lpdwAddressStringLength *C.ulong) C.int {
	return C.int(winsock.GoWSAAddressToStringA(lpsaAddress, uint32(dwAddressLength), lpProtocolInfo, (*byte)(unsafe.Pointer(lpszAddressString)), (*uint32)(unsafe.Pointer(lpdwAddressStringLength))))
}

//export go_WSAAddressToStringW
func go_WSAAddressToStringW(lpsaAddress unsafe.Pointer, dwAddressLength C.ulong, lpProtocolInfo unsafe.Pointer, lpszAddressString *C.ushort, lpdwAddressStringLength *C.ulong) C.int {
	return C.int(winsock.GoWSAAddressToStringW(lpsaAddress, uint32(dwAddressLength), lpProtocolInfo, (*uint16)(unsafe.Pointer(lpszAddressString)), (*uint32)(unsafe.Pointer(lpdwAddressStringLength))))
}

//export go_WSAAsyncSelect
func go_WSAAsyncSelect(s C.uint, hWnd unsafe.Pointer, wMsg C.uint, lEvent C.int) C.int {
	return C.int(winsock.GoWSAAsyncSelect(uint64(s), hWnd, uint32(wMsg), int32(lEvent)))
}

//export go_WSACleanup
func go_WSACleanup() C.int {
	return C.int(winsock.GoWSACleanup())
}

//export go_WSACloseEvent
func go_WSACloseEvent(hEvent unsafe.Pointer) C.int {
	return C.int(winsock.GoWSACloseEvent(hEvent))
}

//export go_WSAConnect
func go_WSAConnect(s C.uint, name unsafe.Pointer, namelen C.int, lpCallerData unsafe.Pointer, lpCalleeData unsafe.Pointer, lpSQOS unsafe.Pointer, lpGQOS unsafe.Pointer) C.int {
	return C.int(winsock.GoWSAConnect(uint64(s), name, int32(namelen), lpCallerData, lpCalleeData, lpSQOS, lpGQOS))
}

//export go_WSAConnectByList
func go_WSAConnectByList(s C.uint, SocketAddressList unsafe.Pointer, LocalAddressLength *C.ulong, LocalAddress unsafe.Pointer, RemoteAddressLength *C.ulong, RemoteAddress unsafe.Pointer, timeout unsafe.Pointer, Reserved unsafe.Pointer) C.int {
	return C.int(winsock.GoWSAConnectByList(uint64(s), SocketAddressList, (*uint32)(unsafe.Pointer(LocalAddressLength)), LocalAddress, (*uint32)(unsafe.Pointer(RemoteAddressLength)), RemoteAddress, timeout, Reserved))
}

//export go_WSAConnectByNameA
func go_WSAConnectByNameA(s C.uint, nodename *C.char, servicename *C.char, LocalAddressLength *C.ulong, LocalAddress unsafe.Pointer, RemoteAddressLength *C.ulong, RemoteAddress unsafe.Pointer, timeout unsafe.Pointer, Reserved unsafe.Pointer) C.int {
	return C.int(winsock.GoWSAConnectByNameA(uint64(s), (*byte)(unsafe.Pointer(nodename)), (*byte)(unsafe.Pointer(servicename)), (*uint32)(unsafe.Pointer(LocalAddressLength)), LocalAddress, (*uint32)(unsafe.Pointer(RemoteAddressLength)), RemoteAddress, timeout, Reserved))
}

//export go_WSAConnectByNameW
func go_WSAConnectByNameW(s C.uint, nodename *C.ushort, servicename *C.ushort, LocalAddressLength *C.ulong, LocalAddress unsafe.Pointer, RemoteAddressLength *C.ulong, RemoteAddress unsafe.Pointer, timeout unsafe.Pointer, Reserved unsafe.Pointer) C.int {
	return C.int(winsock.GoWSAConnectByNameW(uint64(s), (*uint16)(unsafe.Pointer(nodename)), (*uint16)(unsafe.Pointer(servicename)), (*uint32)(unsafe.Pointer(LocalAddressLength)), LocalAddress, (*uint32)(unsafe.Pointer(RemoteAddressLength)), RemoteAddress, timeout, Reserved))
}

//export go_WSACreateEvent
func go_WSACreateEvent() unsafe.Pointer {
	return unsafe.Pointer(winsock.GoWSACreateEvent())
}

//export go_WSADuplicateSocketA
func go_WSADuplicateSocketA(s C.uint, dwProcessId C.ulong, lpProtocolInfo unsafe.Pointer) C.int {
	return C.int(winsock.GoWSADuplicateSocketA(uint64(s), uint32(dwProcessId), lpProtocolInfo))
}

//export go_WSADuplicateSocketW
func go_WSADuplicateSocketW(s C.uint, dwProcessId C.ulong, lpProtocolInfo unsafe.Pointer) C.int {
	return C.int(winsock.GoWSADuplicateSocketW(uint64(s), uint32(dwProcessId), lpProtocolInfo))
}

//export go_WSAEnumNameSpaceProvidersA
func go_WSAEnumNameSpaceProvidersA(lpdwBufferLength *C.ulong, lpnspBuffer unsafe.Pointer) C.int {
	return C.int(winsock.GoWSAEnumNameSpaceProvidersA((*uint32)(unsafe.Pointer(lpdwBufferLength)), lpnspBuffer))
}

//export go_WSAEnumNameSpaceProvidersExA
func go_WSAEnumNameSpaceProvidersExA(lpdwBufferLength *C.ulong, lpnspBuffer unsafe.Pointer) C.int {
	return C.int(winsock.GoWSAEnumNameSpaceProvidersExA((*uint32)(unsafe.Pointer(lpdwBufferLength)), lpnspBuffer))
}

//export go_WSAEnumNameSpaceProvidersExW
func go_WSAEnumNameSpaceProvidersExW(lpdwBufferLength *C.ulong, lpnspBuffer unsafe.Pointer) C.int {
	return C.int(winsock.GoWSAEnumNameSpaceProvidersExW((*uint32)(unsafe.Pointer(lpdwBufferLength)), lpnspBuffer))
}

//export go_WSAEnumNameSpaceProvidersW
func go_WSAEnumNameSpaceProvidersW(lpdwBufferLength *C.ulong, lpnspBuffer unsafe.Pointer) C.int {
	return C.int(winsock.GoWSAEnumNameSpaceProvidersW((*uint32)(unsafe.Pointer(lpdwBufferLength)), lpnspBuffer))
}

//export go_WSAEnumNetworkEvents
func go_WSAEnumNetworkEvents(s C.uint, hEventObject unsafe.Pointer, lpNetworkEvents unsafe.Pointer) C.int {
	return C.int(winsock.GoWSAEnumNetworkEvents(uint64(s), hEventObject, lpNetworkEvents))
}

//export go_WSAEnumProtocolsA
func go_WSAEnumProtocolsA(lpiProtocols *C.int, lpProtocolBuffer unsafe.Pointer, lpdwBufferLength *C.ulong) C.int {
	return C.int(winsock.GoWSAEnumProtocolsA((*int32)(unsafe.Pointer(lpiProtocols)), lpProtocolBuffer, (*uint32)(unsafe.Pointer(lpdwBufferLength))))
}

//export go_WSAEnumProtocolsW
func go_WSAEnumProtocolsW(lpiProtocols *C.int, lpProtocolBuffer unsafe.Pointer, lpdwBufferLength *C.ulong) C.int {
	return C.int(winsock.GoWSAEnumProtocolsW((*int32)(unsafe.Pointer(lpiProtocols)), lpProtocolBuffer, (*uint32)(unsafe.Pointer(lpdwBufferLength))))
}

//export go_WSAEventSelect
func go_WSAEventSelect(s C.uint, hEventObject unsafe.Pointer, lNetworkEvents C.int) C.int {
	return C.int(winsock.GoWSAEventSelect(uint64(s), hEventObject, int32(lNetworkEvents)))
}

//export go___WSAFDIsSet
func go___WSAFDIsSet(s C.uint, fdset unsafe.Pointer) C.int {
	return C.int(winsock.GoWSAFDIsSet(uint64(s), fdset))
}

//export go_WSAGetLastError
func go_WSAGetLastError() C.int {
	return C.int(winsock.GoWSAGetLastError())
}

//export go_WSAGetOverlappedResult
func go_WSAGetOverlappedResult(s C.uint, lpOverlapped unsafe.Pointer, lpcbTransfer *C.ulong, fWait C.int, lpdwFlags *C.ulong) C.int {
	return C.int(winsock.GoWSAGetOverlappedResult(uint64(s), lpOverlapped, (*uint32)(unsafe.Pointer(lpcbTransfer)), int32(fWait), (*uint32)(unsafe.Pointer(lpdwFlags))))
}

//export go_WSAGetQOSByName
func go_WSAGetQOSByName(s C.uint, lpQOSName unsafe.Pointer, lpQOS unsafe.Pointer) C.int {
	return C.int(winsock.GoWSAGetQOSByName(uint64(s), lpQOSName, lpQOS))
}

//export go_WSAGetServiceClassInfoA
func go_WSAGetServiceClassInfoA(lpProviderId unsafe.Pointer, lpServiceClassId unsafe.Pointer, lpdwBufLenth *C.ulong, lpServiceClassInfo unsafe.Pointer) C.int {
	return C.int(winsock.GoWSAGetServiceClassInfoA(lpProviderId, lpServiceClassId, (*uint32)(unsafe.Pointer(lpdwBufLenth)), lpServiceClassInfo))
}

//export go_WSAGetServiceClassInfoW
func go_WSAGetServiceClassInfoW(lpProviderId unsafe.Pointer, lpServiceClassId unsafe.Pointer, lpdwBufLenth *C.ulong, lpServiceClassInfo unsafe.Pointer) C.int {
	return C.int(winsock.GoWSAGetServiceClassInfoW(lpProviderId, lpServiceClassId, (*uint32)(unsafe.Pointer(lpdwBufLenth)), lpServiceClassInfo))
}

//export go_WSAGetServiceClassNameByClassIdA
func go_WSAGetServiceClassNameByClassIdA(lpServiceClassId unsafe.Pointer, lpszServiceClassName *C.char, lpdwBufferLength *C.ulong) C.int {
	return C.int(winsock.GoWSAGetServiceClassNameByClassIdA(lpServiceClassId, (*byte)(unsafe.Pointer(lpszServiceClassName)), (*uint32)(unsafe.Pointer(lpdwBufferLength))))
}

//export go_WSAGetServiceClassNameByClassIdW
func go_WSAGetServiceClassNameByClassIdW(lpServiceClassId unsafe.Pointer, lpszServiceClassName *C.ushort, lpdwBufferLength *C.ulong) C.int {
	return C.int(winsock.GoWSAGetServiceClassNameByClassIdW(lpServiceClassId, (*uint16)(unsafe.Pointer(lpszServiceClassName)), (*uint32)(unsafe.Pointer(lpdwBufferLength))))
}

//export go_WSAHtonl
func go_WSAHtonl(s C.uint, hostlong C.ulong, lpnetlong *C.ulong) C.int {
	return C.int(winsock.GoWSAHtonl(uint64(s), uint32(hostlong), (*uint32)(unsafe.Pointer(lpnetlong))))
}

//export go_WSAHtons
func go_WSAHtons(s C.uint, hostshort C.ushort, lpnetshort *C.ushort) C.int {
	return C.int(winsock.GoWSAHtons(uint64(s), uint16(hostshort), (*uint16)(unsafe.Pointer(lpnetshort))))
}

//export go_WSAInstallServiceClassA
func go_WSAInstallServiceClassA(lpServiceClassInfo unsafe.Pointer) C.int {
	return C.int(winsock.GoWSAInstallServiceClassA(lpServiceClassInfo))
}

//export go_WSAInstallServiceClassW
func go_WSAInstallServiceClassW(lpServiceClassInfo unsafe.Pointer) C.int {
	return C.int(winsock.GoWSAInstallServiceClassW(lpServiceClassInfo))
}

//export go_WSAIoctl
func go_WSAIoctl(s C.uint, dwIoControlCode C.ulong, lpvInBuffer unsafe.Pointer, cbInBuffer C.ulong, lpvOutBuffer unsafe.Pointer, cbOutBuffer C.ulong, lpcbBytesReturned *C.ulong, lpOverlapped unsafe.Pointer, lpCompletionRoutine unsafe.Pointer) C.int {
	return C.int(winsock.GoWSAIoctl(uint64(s), uint32(dwIoControlCode), lpvInBuffer, uint32(cbInBuffer), lpvOutBuffer, uint32(cbOutBuffer), (*uint32)(unsafe.Pointer(lpcbBytesReturned)), lpOverlapped, lpCompletionRoutine))
}

//export go_WSALookupServiceBeginA
func go_WSALookupServiceBeginA(lpqsRestrictions unsafe.Pointer, dwControlFlags C.ulong, lphLookup *unsafe.Pointer) C.int {
	return C.int(winsock.GoWSALookupServiceBeginA(lpqsRestrictions, uint32(dwControlFlags), (*unsafe.Pointer)(unsafe.Pointer(lphLookup))))
}

//export go_WSALookupServiceBeginW
func go_WSALookupServiceBeginW(lpqsRestrictions unsafe.Pointer, dwControlFlags C.ulong, lphLookup *unsafe.Pointer) C.int {
	return C.int(winsock.GoWSALookupServiceBeginW(lpqsRestrictions, uint32(dwControlFlags), (*unsafe.Pointer)(unsafe.Pointer(lphLookup))))
}

//export go_WSALookupServiceEnd
func go_WSALookupServiceEnd(hLookup unsafe.Pointer) C.int {
	return C.int(winsock.GoWSALookupServiceEnd(hLookup))
}

//export go_WSALookupServiceNextA
func go_WSALookupServiceNextA(hLookup unsafe.Pointer, dwControlFlags C.ulong, lpdwBufferLength *C.ulong, lpqsResults unsafe.Pointer) C.int {
	return C.int(winsock.GoWSALookupServiceNextA(hLookup, uint32(dwControlFlags), (*uint32)(unsafe.Pointer(lpdwBufferLength)), lpqsResults))
}

//export go_WSALookupServiceNextW
func go_WSALookupServiceNextW(hLookup unsafe.Pointer, dwControlFlags C.ulong, lpdwBufferLength *C.ulong, lpqsResults unsafe.Pointer) C.int {
	return C.int(winsock.GoWSALookupServiceNextW(hLookup, uint32(dwControlFlags), (*uint32)(unsafe.Pointer(lpdwBufferLength)), lpqsResults))
}

//export go_WSANSPIoctl
func go_WSANSPIoctl(hLookup unsafe.Pointer, dwControlCode C.ulong, lpvInBuffer unsafe.Pointer, cbInBuffer C.ulong, lpvOutBuffer unsafe.Pointer, cbOutBuffer C.ulong, lpcbBytesReturned *C.ulong, lpCompletion unsafe.Pointer) C.int {
	return C.int(winsock.GoWSANSPIoctl(hLookup, uint32(dwControlCode), lpvInBuffer, uint32(cbInBuffer), lpvOutBuffer, uint32(cbOutBuffer), (*uint32)(unsafe.Pointer(lpcbBytesReturned)), lpCompletion))
}

//export go_WSANtohl
func go_WSANtohl(s C.uint, netlong C.ulong, lphostlong *C.ulong) C.int {
	return C.int(winsock.GoWSANtohl(uint64(s), uint32(netlong), (*uint32)(unsafe.Pointer(lphostlong))))
}

//export go_WSANtohs
func go_WSANtohs(s C.uint, netshort C.ushort, lphostshort *C.ushort) C.int {
	return C.int(winsock.GoWSANtohs(uint64(s), uint16(netshort), (*uint16)(unsafe.Pointer(lphostshort))))
}

//export go_WSAPoll
func go_WSAPoll(fdArray unsafe.Pointer, fds C.ulong, timeout C.int) C.int {
	return C.int(winsock.GoWSAPoll(fdArray, uint32(fds), int32(timeout)))
}

//export go_WSAProviderConfigChange
func go_WSAProviderConfigChange(lpNotificationHandle *unsafe.Pointer, lpOverlapped unsafe.Pointer, lpCompletionRoutine unsafe.Pointer) C.int {
	return C.int(winsock.GoWSAProviderConfigChange((*unsafe.Pointer)(unsafe.Pointer(lpNotificationHandle)), lpOverlapped, lpCompletionRoutine))
}

//export go_WSARecv
func go_WSARecv(s C.uint, lpBuffers unsafe.Pointer, dwBufferCount C.ulong, lpNumberOfBytesRecvd *C.ulong, lpFlags *C.ulong, lpOverlapped unsafe.Pointer, lpCompletionRoutine unsafe.Pointer) C.int {
	return C.int(winsock.GoWSARecv(uint64(s), lpBuffers, uint32(dwBufferCount), (*uint32)(unsafe.Pointer(lpNumberOfBytesRecvd)), (*uint32)(unsafe.Pointer(lpFlags)), lpOverlapped, lpCompletionRoutine))
}

//export go_WSARecvDisconnect
func go_WSARecvDisconnect(s C.uint, lpInboundDisconnectData unsafe.Pointer) C.int {
	return C.int(winsock.GoWSARecvDisconnect(uint64(s), lpInboundDisconnectData))
}

//export go_WSARecvFrom
func go_WSARecvFrom(s C.uint, lpBuffers unsafe.Pointer, dwBufferCount C.ulong, lpNumberOfBytesRecvd *C.ulong, lpFlags *C.ulong, lpFrom unsafe.Pointer, lpFromlen *C.int, lpOverlapped unsafe.Pointer, lpCompletionRoutine unsafe.Pointer) C.int {
	return C.int(winsock.GoWSARecvFrom(uint64(s), lpBuffers, uint32(dwBufferCount), (*uint32)(unsafe.Pointer(lpNumberOfBytesRecvd)), (*uint32)(unsafe.Pointer(lpFlags)), lpFrom, (*int32)(unsafe.Pointer(lpFromlen)), lpOverlapped, lpCompletionRoutine))
}

//export go_WSARecvMsg
func go_WSARecvMsg(s C.uint, lpMsg unsafe.Pointer, lpdwBytesReceived *C.ulong, lpOverlapped unsafe.Pointer, lpCompletionRoutine unsafe.Pointer) C.int {
	return C.int(winsock.GoWSARecvMsg(uint64(s), lpMsg, (*uint32)(unsafe.Pointer(lpdwBytesReceived)), lpOverlapped, lpCompletionRoutine))
}

//export go_WSARemoveServiceClass
func go_WSARemoveServiceClass(lpServiceClassId unsafe.Pointer) C.int {
	return C.int(winsock.GoWSARemoveServiceClass(lpServiceClassId))
}

//export go_WSAResetEvent
func go_WSAResetEvent(hEvent unsafe.Pointer) C.int {
	return C.int(winsock.GoWSAResetEvent(hEvent))
}

//export go_WSASend
func go_WSASend(s C.uint, lpBuffers unsafe.Pointer, dwBufferCount C.ulong, lpNumberOfBytesSent *C.ulong, dwFlags C.ulong, lpOverlapped unsafe.Pointer, lpCompletionRoutine unsafe.Pointer) C.int {
	return C.int(winsock.GoWSASend(uint64(s), lpBuffers, uint32(dwBufferCount), (*uint32)(unsafe.Pointer(lpNumberOfBytesSent)), uint32(dwFlags), lpOverlapped, lpCompletionRoutine))
}

//export go_WSASendDisconnect
func go_WSASendDisconnect(s C.uint, lpOutboundDisconnectData unsafe.Pointer) C.int {
	return C.int(winsock.GoWSASendDisconnect(uint64(s), lpOutboundDisconnectData))
}

//export go_WSASendMsg
func go_WSASendMsg(s C.uint, lpMsg unsafe.Pointer, dwFlags C.ulong, lpdwBytesSent *C.ulong, lpOverlapped unsafe.Pointer, lpCompletionRoutine unsafe.Pointer) C.int {
	return C.int(winsock.GoWSASendMsg(uint64(s), lpMsg, uint32(dwFlags), (*uint32)(unsafe.Pointer(lpdwBytesSent)), lpOverlapped, lpCompletionRoutine))
}

//export go_WSASendTo
func go_WSASendTo(s C.uint, lpBuffers unsafe.Pointer, dwBufferCount C.ulong, lpNumberOfBytesSent *C.ulong, dwFlags C.ulong, lpTo unsafe.Pointer, iTolen C.int, lpOverlapped unsafe.Pointer, lpCompletionRoutine unsafe.Pointer) C.int {
	return C.int(winsock.GoWSASendTo(uint64(s), lpBuffers, uint32(dwBufferCount), (*uint32)(unsafe.Pointer(lpNumberOfBytesSent)), uint32(dwFlags), lpTo, int32(iTolen), lpOverlapped, lpCompletionRoutine))
}

//export go_WSASetEvent
func go_WSASetEvent(hEvent unsafe.Pointer) C.int {
	return C.int(winsock.GoWSASetEvent(hEvent))
}

//export go_WSASetLastError
func go_WSASetLastError(iError C.int) {
	winsock.GoWSASetLastError(int32(iError))
}

//export go_WSASetServiceA
func go_WSASetServiceA(lpqsRegInfo unsafe.Pointer, essOperation C.int, dwControlFlags C.ulong) C.int {
	return C.int(winsock.GoWSASetServiceA(lpqsRegInfo, int32(essOperation), uint32(dwControlFlags)))
}

//export go_WSASetServiceW
func go_WSASetServiceW(lpqsRegInfo unsafe.Pointer, essOperation C.int, dwControlFlags C.ulong) C.int {
	return C.int(winsock.GoWSASetServiceW(lpqsRegInfo, int32(essOperation), uint32(dwControlFlags)))
}

//export go_WSASocketA
func go_WSASocketA(af C.int, typ C.int, protocol C.int, lpProtocolInfo unsafe.Pointer, g C.uint, dwFlags C.ulong) C.uint {
	return C.uint(winsock.GoWSASocketA(int32(af), int32(typ), int32(protocol), lpProtocolInfo, uint32(g), uint32(dwFlags)))
}

//export go_WSASocketW
func go_WSASocketW(af C.int, typ C.int, protocol C.int, lpProtocolInfo unsafe.Pointer, g C.uint, dwFlags C.ulong) C.uint {
	return C.uint(winsock.GoWSASocketW(int32(af), int32(typ), int32(protocol), lpProtocolInfo, uint32(g), uint32(dwFlags)))
}

//export go_WSAStartup
func go_WSAStartup(wVersionRequested C.ushort, lpWSAData unsafe.Pointer) C.int {
	return C.int(winsock.GoWSAStartup(uint16(wVersionRequested), lpWSAData))
}

//export go_WSAStringToAddressA
func go_WSAStringToAddressA(AddressString *C.char, AddressFamily C.int, lpProtocolInfo unsafe.Pointer, lpAddress unsafe.Pointer, lpAddressLength *C.int) C.int {
	return C.int(winsock.GoWSAStringToAddressA((*byte)(unsafe.Pointer(AddressString)), int32(AddressFamily), lpProtocolInfo, lpAddress, (*int32)(unsafe.Pointer(lpAddressLength))))
}

//export go_WSAStringToAddressW
func go_WSAStringToAddressW(AddressString *C.ushort, AddressFamily C.int, lpProtocolInfo unsafe.Pointer, lpAddress unsafe.Pointer, lpAddressLength *C.int) C.int {
	return C.int(winsock.GoWSAStringToAddressW((*uint16)(unsafe.Pointer(AddressString)), int32(AddressFamily), lpProtocolInfo, lpAddress, (*int32)(unsafe.Pointer(lpAddressLength))))
}

//export go_WSAWaitForMultipleEvents
func go_WSAWaitForMultipleEvents(cEvents C.ulong, lphEvents *unsafe.Pointer, fWaitAll C.int, dwTimeout C.ulong, fAlertable C.int) C.ulong {
	return C.ulong(winsock.GoWSAWaitForMultipleEvents(uint32(cEvents), (*unsafe.Pointer)(unsafe.Pointer(lphEvents)), int32(fWaitAll), uint32(dwTimeout), int32(fAlertable)))
}

//export go_AcceptEx
func go_AcceptEx(sListenSocket C.uint, sAcceptSocket C.uint, lpOutputBuffer unsafe.Pointer, dwReceiveDataLength C.ulong, dwLocalAddressLength C.ulong, dwRemoteAddressLength C.ulong, lpdwBytesReceived *C.ulong, lpOverlapped unsafe.Pointer) C.int {
	return C.int(winsock.GoAcceptEx(uint64(sListenSocket), uint64(sAcceptSocket), lpOutputBuffer, uint32(dwReceiveDataLength), uint32(dwLocalAddressLength), uint32(dwRemoteAddressLength), (*uint32)(unsafe.Pointer(lpdwBytesReceived)), lpOverlapped))
}

//export go_ConnectEx
func go_ConnectEx(s C.uint, name unsafe.Pointer, namelen C.int, lpSendBuffer unsafe.Pointer, dwSendDataLength C.ulong, lpdwBytesSent *C.ulong, lpOverlapped unsafe.Pointer) C.int {
	return C.int(winsock.GoConnectEx(uint64(s), name, int32(namelen), lpSendBuffer, uint32(dwSendDataLength), (*uint32)(unsafe.Pointer(lpdwBytesSent)), lpOverlapped))
}

//export go_WSAAsyncGetHostByAddr
func go_WSAAsyncGetHostByAddr(hWnd unsafe.Pointer, wMsg C.uint, addr *C.char, addrLen C.int, addrType C.int, buf unsafe.Pointer, bufLen C.int) C.uint {
	return C.uint(winsock.GoWSAAsyncGetHostByAddr(hWnd, uint32(wMsg), (*byte)(unsafe.Pointer(addr)), int32(addrLen), int32(addrType), buf, int32(bufLen)))
}

//export go_WSAAsyncGetHostByName
func go_WSAAsyncGetHostByName(hWnd unsafe.Pointer, wMsg C.uint, name *C.char, buf unsafe.Pointer, bufLen C.int) C.uint {
	return C.uint(winsock.GoWSAAsyncGetHostByName(hWnd, uint32(wMsg), (*byte)(unsafe.Pointer(name)), buf, int32(bufLen)))
}

//export go_WSAAsyncGetServByPort
func go_WSAAsyncGetServByPort(hWnd unsafe.Pointer, wMsg C.uint, port C.int, proto *C.char, buf unsafe.Pointer, bufLen C.int) C.uint {
	return C.uint(winsock.GoWSAAsyncGetServByPort(hWnd, uint32(wMsg), int32(port), (*byte)(unsafe.Pointer(proto)), buf, int32(bufLen)))
}

//export go_WSAAsyncGetProtoByName
func go_WSAAsyncGetProtoByName(hWnd unsafe.Pointer, wMsg C.uint, name *C.char, buf unsafe.Pointer, bufLen C.int) C.uint {
	return C.uint(winsock.GoWSAAsyncGetProtoByName(hWnd, uint32(wMsg), (*byte)(unsafe.Pointer(name)), buf, int32(bufLen)))
}

//export go_WSAAsyncGetProtoByNumber
func go_WSAAsyncGetProtoByNumber(hWnd unsafe.Pointer, wMsg C.uint, number C.int, buf unsafe.Pointer, bufLen C.int) C.uint {
	return C.uint(winsock.GoWSAAsyncGetProtoByNumber(hWnd, uint32(wMsg), int32(number), buf, int32(bufLen)))
}

//export go_WSAAsyncGetServByName
func go_WSAAsyncGetServByName(hWnd unsafe.Pointer, wMsg C.uint, name *C.char, proto *C.char, buf unsafe.Pointer, bufLen C.int) C.uint {
	return C.uint(winsock.GoWSAAsyncGetServByName(hWnd, uint32(wMsg), (*byte)(unsafe.Pointer(name)), (*byte)(unsafe.Pointer(proto)), buf, int32(bufLen)))
}

//export go_WSACancelAsyncRequest
func go_WSACancelAsyncRequest(hAsyncTaskHandle C.uint) C.int {
	return C.int(winsock.GoWSACancelAsyncRequest(uintptr(hAsyncTaskHandle)))
}

//export go_WSASetBlockingHook
func go_WSASetBlockingHook(lpBlockFunc unsafe.Pointer) unsafe.Pointer {
	return winsock.GoWSASetBlockingHook(lpBlockFunc)
}

//export go_WSAUnhookBlockingHook
func go_WSAUnhookBlockingHook() C.int {
	return C.int(winsock.GoWSAUnhookBlockingHook())
}

//export go_WSACancelBlockingCall
func go_WSACancelBlockingCall() C.int {
	return C.int(winsock.GoWSACancelBlockingCall())
}

//export go_WSAIsBlocking
func go_WSAIsBlocking() C.int {
	return C.int(winsock.GoWSAIsBlocking())
}
