/*
 * stdcall_exports.c — Win32 __stdcall wrappers for Go-exported cdecl functions.
 *
 * On Win32, Winsock functions use __stdcall (callee pops stack). Go cgo //export
 * on GOARCH=386 emits __cdecl (caller pops stack). Without these wrappers, every
 * call from a Win32 application would corrupt the stack.
 *
 * Each wrapper forwards to the corresponding go_Xxx cdecl function exported from
 * exports.go. The .def file exports these __stdcall symbols as the public DLL API.
 *
 * SOCKET = unsigned int (UINT_PTR) on Win32.
 * HANDLE = void* on Win32.
 */

#include <stddef.h>
#include <stdint.h>

/* ========== Forward declarations of Go-exported cdecl functions ========== */

/* --- Core socket operations --- */
extern unsigned int go_accept(unsigned int s, void* addr, int* addrlen);
extern int go_bind(unsigned int s, void* name, int namelen);
extern int go_closesocket(unsigned int s);
extern int go_connect(unsigned int s, void* name, int namelen);
extern int go_getpeername(unsigned int s, void* name, int* namelen);
extern int go_getsockname(unsigned int s, void* name, int* namelen);
extern int go_getsockopt(unsigned int s, int level, int optname, void* optval, int* optlen);
extern int go_ioctlsocket(unsigned int s, int cmd, unsigned long* argp);
extern int go_listen(unsigned int s, int backlog);
extern int go_recv(unsigned int s, void* buf, int len, int flags);
extern int go_recvfrom(unsigned int s, void* buf, int len, int flags, void* from, int* fromlen);
extern int go_send(unsigned int s, void* buf, int len, int flags);
extern int go_sendto(unsigned int s, void* buf, int len, int flags, void* to, int tolen);
extern int go_setsockopt(unsigned int s, int level, int optname, void* optval, int optlen);
extern int go_shutdown(unsigned int s, int how);
extern unsigned int go_socket(int af, int type, int protocol);

/* --- select (name collision workaround via go_select_) --- */
extern int go_select_(int nfds, void* readfds, void* writefds, void* exceptfds, void* timeout);

/* --- Address resolution --- */
extern void go_freeaddrinfo(void* ai);
extern void go_FreeAddrInfoW(void* ai);
extern int go_getaddrinfo(char* node, char* service, void* hints, void** res);
extern int go_GetAddrInfoW(unsigned short* node, unsigned short* service, void* hints, void** res);
extern void* go_gethostbyaddr(char* addr, int addrLen, int addrType);
extern void* go_gethostbyname(char* name);
extern int go_GetHostNameW(unsigned short* name, int namelen);
extern int go_gethostname(char* name, int namelen);
extern int go_getnameinfo(void* sa, int salen, char* host, unsigned long hostlen, char* serv, unsigned long servlen, int flags);
extern int go_GetNameInfoW(void* sa, int salen, unsigned short* host, unsigned long hostlen, unsigned short* serv, unsigned long servlen, int flags);

/* --- Protocol/service lookups --- */
extern void* go_getprotobyname(char* name);
extern void* go_getprotobynumber(int proto);
extern void* go_getservbyname(char* name, char* proto);
extern void* go_getservbyport(int port, char* proto);

/* --- Byte order --- */
extern double go_htond(double hostdouble);
extern float go_htonf(float hostfloat);
extern unsigned long go_htonl(unsigned long hostlong);
extern unsigned long long go_htonll(unsigned long long hostlonglong);
extern unsigned short go_htons(unsigned short hostshort);
extern double go_ntohd(double netdouble);
extern float go_ntohf(float netfloat);
extern unsigned long go_ntohl(unsigned long netlong);
extern unsigned long long go_ntohll(unsigned long long netlonglong);
extern unsigned short go_ntohs(unsigned short netshort);

/* --- Address string conversion --- */
extern unsigned long go_inet_addr(char* cp);
extern char* go_inet_ntoa(unsigned long in);
extern int go_inet_pton(int family, char* src, void* dst);
extern char* go_inet_ntop(int family, void* src, char* dst, int size);
extern int go_InetPtonW(int family, unsigned short* src, void* dst);
extern unsigned short* go_InetNtopW(int family, void* src, unsigned short* dst, int size);

/* --- WSA lifecycle --- */
extern int go_WSAStartup(unsigned short wVersionRequested, void* lpWSAData);
extern int go_WSACleanup(void);
extern int go_WSAGetLastError(void);
extern void go_WSASetLastError(int iError);

/* --- WSA extended socket --- */
extern unsigned int go_WSAAccept(unsigned int s, void* addr, int* addrlen, void* lpfnCondition, unsigned long dwCallbackData);
extern unsigned int go_WSASocketA(int af, int type, int protocol, void* lpProtocolInfo, unsigned int g, unsigned long dwFlags);
extern unsigned int go_WSASocketW(int af, int type, int protocol, void* lpProtocolInfo, unsigned int g, unsigned long dwFlags);
extern int go_WSAConnect(unsigned int s, void* name, int namelen, void* lpCallerData, void* lpCalleeData, void* lpSQOS, void* lpGQOS);
extern int go_WSAConnectByList(unsigned int s, void* SocketAddressList, unsigned long* LocalAddressLength, void* LocalAddress, unsigned long* RemoteAddressLength, void* RemoteAddress, void* timeout, void* Reserved);
extern int go_WSAConnectByNameA(unsigned int s, char* nodename, char* servicename, unsigned long* LocalAddressLength, void* LocalAddress, unsigned long* RemoteAddressLength, void* RemoteAddress, void* timeout, void* Reserved);
extern int go_WSAConnectByNameW(unsigned int s, unsigned short* nodename, unsigned short* servicename, unsigned long* LocalAddressLength, void* LocalAddress, unsigned long* RemoteAddressLength, void* RemoteAddress, void* timeout, void* Reserved);
extern int go_WSADuplicateSocketA(unsigned int s, unsigned long dwProcessId, void* lpProtocolInfo);
extern int go_WSADuplicateSocketW(unsigned int s, unsigned long dwProcessId, void* lpProtocolInfo);
extern int go_WSAAsyncSelect(unsigned int s, void* hWnd, unsigned int wMsg, int lEvent);

/* --- WSA event objects --- */
extern void* go_WSACreateEvent(void);
extern int go_WSACloseEvent(void* hEvent);
extern int go_WSASetEvent(void* hEvent);
extern int go_WSAResetEvent(void* hEvent);
extern int go_WSAEventSelect(unsigned int s, void* hEventObject, int lNetworkEvents);
extern int go_WSAEnumNetworkEvents(unsigned int s, void* hEventObject, void* lpNetworkEvents);
extern unsigned long go_WSAWaitForMultipleEvents(unsigned long cEvents, void** lphEvents, int fWaitAll, unsigned long dwTimeout, int fAlertable);

/* --- WSA I/O --- */
extern int go_WSARecv(unsigned int s, void* lpBuffers, unsigned long dwBufferCount, unsigned long* lpNumberOfBytesRecvd, unsigned long* lpFlags, void* lpOverlapped, void* lpCompletionRoutine);
extern int go_WSARecvDisconnect(unsigned int s, void* lpInboundDisconnectData);
extern int go_WSARecvFrom(unsigned int s, void* lpBuffers, unsigned long dwBufferCount, unsigned long* lpNumberOfBytesRecvd, unsigned long* lpFlags, void* lpFrom, int* lpFromlen, void* lpOverlapped, void* lpCompletionRoutine);
extern int go_WSARecvMsg(unsigned int s, void* lpMsg, unsigned long* lpdwBytesReceived, void* lpOverlapped, void* lpCompletionRoutine);
extern int go_WSASend(unsigned int s, void* lpBuffers, unsigned long dwBufferCount, unsigned long* lpNumberOfBytesSent, unsigned long dwFlags, void* lpOverlapped, void* lpCompletionRoutine);
extern int go_WSASendDisconnect(unsigned int s, void* lpOutboundDisconnectData);
extern int go_WSASendMsg(unsigned int s, void* lpMsg, unsigned long dwFlags, unsigned long* lpdwBytesSent, void* lpOverlapped, void* lpCompletionRoutine);
extern int go_WSASendTo(unsigned int s, void* lpBuffers, unsigned long dwBufferCount, unsigned long* lpNumberOfBytesSent, unsigned long dwFlags, void* lpTo, int iTolen, void* lpOverlapped, void* lpCompletionRoutine);
extern int go_WSAIoctl(unsigned int s, unsigned long dwIoControlCode, void* lpvInBuffer, unsigned long cbInBuffer, void* lpvOutBuffer, unsigned long cbOutBuffer, unsigned long* lpcbBytesReturned, void* lpOverlapped, void* lpCompletionRoutine);
extern int go_WSAGetOverlappedResult(unsigned int s, void* lpOverlapped, unsigned long* lpcbTransfer, int fWait, unsigned long* lpdwFlags);
extern int go_WSAGetQOSByName(unsigned int s, void* lpQOSName, void* lpQOS);

/* --- WSA poll/select --- */
extern int go_WSAPoll(void* fdArray, unsigned long fds, int timeout);
extern int go___WSAFDIsSet(unsigned int s, void* fdset);

/* --- WSA byte order helpers --- */
extern int go_WSAHtonl(unsigned int s, unsigned long hostlong, unsigned long* lpnetlong);
extern int go_WSAHtons(unsigned int s, unsigned short hostshort, unsigned short* lpnetshort);
extern int go_WSANtohl(unsigned int s, unsigned long netlong, unsigned long* lphostlong);
extern int go_WSANtohs(unsigned int s, unsigned short netshort, unsigned short* lphostshort);

/* --- WSA address string conversion --- */
extern int go_WSAAddressToStringA(void* lpsaAddress, unsigned long dwAddressLength, void* lpProtocolInfo, char* lpszAddressString, unsigned long* lpdwAddressStringLength);
extern int go_WSAAddressToStringW(void* lpsaAddress, unsigned long dwAddressLength, void* lpProtocolInfo, unsigned short* lpszAddressString, unsigned long* lpdwAddressStringLength);
extern int go_WSAStringToAddressA(char* AddressString, int AddressFamily, void* lpProtocolInfo, void* lpAddress, int* lpAddressLength);
extern int go_WSAStringToAddressW(unsigned short* AddressString, int AddressFamily, void* lpProtocolInfo, void* lpAddress, int* lpAddressLength);

/* --- WSA protocol enumeration --- */
extern int go_WSAEnumProtocolsA(int* lpiProtocols, void* lpProtocolBuffer, unsigned long* lpdwBufferLength);
extern int go_WSAEnumProtocolsW(int* lpiProtocols, void* lpProtocolBuffer, unsigned long* lpdwBufferLength);

/* --- WSA namespace/service --- */
extern int go_WSAEnumNameSpaceProvidersA(unsigned long* lpdwBufferLength, void* lpnspBuffer);
extern int go_WSAEnumNameSpaceProvidersExA(unsigned long* lpdwBufferLength, void* lpnspBuffer);
extern int go_WSAEnumNameSpaceProvidersExW(unsigned long* lpdwBufferLength, void* lpnspBuffer);
extern int go_WSAEnumNameSpaceProvidersW(unsigned long* lpdwBufferLength, void* lpnspBuffer);
extern int go_WSAInstallServiceClassA(void* lpServiceClassInfo);
extern int go_WSAInstallServiceClassW(void* lpServiceClassInfo);
extern int go_WSARemoveServiceClass(void* lpServiceClassId);
extern int go_WSAGetServiceClassInfoA(void* lpProviderId, void* lpServiceClassId, unsigned long* lpdwBufLenth, void* lpServiceClassInfo);
extern int go_WSAGetServiceClassInfoW(void* lpProviderId, void* lpServiceClassId, unsigned long* lpdwBufLenth, void* lpServiceClassInfo);
extern int go_WSAGetServiceClassNameByClassIdA(void* lpServiceClassId, char* lpszServiceClassName, unsigned long* lpdwBufferLength);
extern int go_WSAGetServiceClassNameByClassIdW(void* lpServiceClassId, unsigned short* lpszServiceClassName, unsigned long* lpdwBufferLength);
extern int go_WSASetServiceA(void* lpqsRegInfo, int essOperation, unsigned long dwControlFlags);
extern int go_WSASetServiceW(void* lpqsRegInfo, int essOperation, unsigned long dwControlFlags);
extern int go_WSALookupServiceBeginA(void* lpqsRestrictions, unsigned long dwControlFlags, void** lphLookup);
extern int go_WSALookupServiceBeginW(void* lpqsRestrictions, unsigned long dwControlFlags, void** lphLookup);
extern int go_WSALookupServiceEnd(void* hLookup);
extern int go_WSALookupServiceNextA(void* hLookup, unsigned long dwControlFlags, unsigned long* lpdwBufferLength, void* lpqsResults);
extern int go_WSALookupServiceNextW(void* hLookup, unsigned long dwControlFlags, unsigned long* lpdwBufferLength, void* lpqsResults);
extern int go_WSANSPIoctl(void* hLookup, unsigned long dwControlCode, void* lpvInBuffer, unsigned long cbInBuffer, void* lpvOutBuffer, unsigned long cbOutBuffer, unsigned long* lpcbBytesReturned, void* lpCompletion);
extern int go_WSAProviderConfigChange(void** lpNotificationHandle, void* lpOverlapped, void* lpCompletionRoutine);

/* --- WSA notification stubs --- */
extern int go_ProcessSocketNotifications(void* completionPort, unsigned int registrationCount, void* registrationInfos, unsigned int timeout, unsigned int completionCount, void* completionInfos, unsigned long* receivedCount);
extern int go_SocketNotificationRetrieveEvents(void* notificationRegistration, void* notificationEvents);

/* --- Extended connection APIs --- */
extern int go_AcceptEx(unsigned int sListenSocket, unsigned int sAcceptSocket, void* lpOutputBuffer, unsigned long dwReceiveDataLength, unsigned long dwLocalAddressLength, unsigned long dwRemoteAddressLength, unsigned long* lpdwBytesReceived, void* lpOverlapped);
extern int go_ConnectEx(unsigned int s, void* name, int namelen, void* lpSendBuffer, unsigned long dwSendDataLength, unsigned long* lpdwBytesSent, void* lpOverlapped);

/* --- Legacy async functions --- */
extern unsigned int go_WSAAsyncGetHostByAddr(void* hWnd, unsigned int wMsg, char* addr, int addrLen, int addrType, void* buf, int bufLen);
extern unsigned int go_WSAAsyncGetHostByName(void* hWnd, unsigned int wMsg, char* name, void* buf, int bufLen);
extern unsigned int go_WSAAsyncGetServByPort(void* hWnd, unsigned int wMsg, int port, char* proto, void* buf, int bufLen);
extern unsigned int go_WSAAsyncGetProtoByName(void* hWnd, unsigned int wMsg, char* name, void* buf, int bufLen);
extern unsigned int go_WSAAsyncGetProtoByNumber(void* hWnd, unsigned int wMsg, int number, void* buf, int bufLen);
extern unsigned int go_WSAAsyncGetServByName(void* hWnd, unsigned int wMsg, char* name, char* proto, void* buf, int bufLen);
extern int go_WSACancelAsyncRequest(unsigned int hAsyncTaskHandle);

/* --- Legacy blocking hooks --- */
extern void* go_WSASetBlockingHook(void* lpBlockFunc);
extern int go_WSAUnhookBlockingHook(void);
extern int go_WSACancelBlockingCall(void);
extern int go_WSAIsBlocking(void);


/* ==================== __stdcall wrappers ==================== */

/* --- Core socket operations --- */

unsigned int __stdcall accept(unsigned int s, void* addr, int* addrlen) {
    return go_accept(s, addr, addrlen);
}

int __stdcall bind(unsigned int s, void* name, int namelen) {
    return go_bind(s, name, namelen);
}

int __stdcall closesocket(unsigned int s) {
    return go_closesocket(s);
}

int __stdcall connect(unsigned int s, void* name, int namelen) {
    return go_connect(s, name, namelen);
}

int __stdcall getpeername(unsigned int s, void* name, int* namelen) {
    return go_getpeername(s, name, namelen);
}

int __stdcall getsockname(unsigned int s, void* name, int* namelen) {
    return go_getsockname(s, name, namelen);
}

int __stdcall getsockopt(unsigned int s, int level, int optname, void* optval, int* optlen) {
    return go_getsockopt(s, level, optname, optval, optlen);
}

int __stdcall ioctlsocket(unsigned int s, int cmd, unsigned long* argp) {
    return go_ioctlsocket(s, cmd, argp);
}

int __stdcall listen(unsigned int s, int backlog) {
    return go_listen(s, backlog);
}

int __stdcall recv(unsigned int s, void* buf, int len, int flags) {
    return go_recv(s, buf, len, flags);
}

int __stdcall recvfrom(unsigned int s, void* buf, int len, int flags, void* from, int* fromlen) {
    return go_recvfrom(s, buf, len, flags, from, fromlen);
}

int __stdcall select(int nfds, void* readfds, void* writefds, void* exceptfds, void* timeout) {
    return go_select_(nfds, readfds, writefds, exceptfds, timeout);
}

int __stdcall send(unsigned int s, void* buf, int len, int flags) {
    return go_send(s, buf, len, flags);
}

int __stdcall sendto(unsigned int s, void* buf, int len, int flags, void* to, int tolen) {
    return go_sendto(s, buf, len, flags, to, tolen);
}

int __stdcall setsockopt(unsigned int s, int level, int optname, void* optval, int optlen) {
    return go_setsockopt(s, level, optname, optval, optlen);
}

int __stdcall shutdown(unsigned int s, int how) {
    return go_shutdown(s, how);
}

unsigned int __stdcall socket(int af, int type, int protocol) {
    return go_socket(af, type, protocol);
}

/* --- Address resolution --- */

void __stdcall freeaddrinfo(void* ai) {
    go_freeaddrinfo(ai);
}

void __stdcall FreeAddrInfoW(void* ai) {
    go_FreeAddrInfoW(ai);
}

int __stdcall getaddrinfo(char* node, char* service, void* hints, void** res) {
    return go_getaddrinfo(node, service, hints, res);
}

int __stdcall GetAddrInfoW(unsigned short* node, unsigned short* service, void* hints, void** res) {
    return go_GetAddrInfoW(node, service, hints, res);
}

void* __stdcall gethostbyaddr(char* addr, int addrLen, int addrType) {
    return go_gethostbyaddr(addr, addrLen, addrType);
}

void* __stdcall gethostbyname(char* name) {
    return go_gethostbyname(name);
}

int __stdcall GetHostNameW(unsigned short* name, int namelen) {
    return go_GetHostNameW(name, namelen);
}

int __stdcall gethostname(char* name, int namelen) {
    return go_gethostname(name, namelen);
}

int __stdcall getnameinfo(void* sa, int salen, char* host, unsigned long hostlen, char* serv, unsigned long servlen, int flags) {
    return go_getnameinfo(sa, salen, host, hostlen, serv, servlen, flags);
}

int __stdcall GetNameInfoW(void* sa, int salen, unsigned short* host, unsigned long hostlen, unsigned short* serv, unsigned long servlen, int flags) {
    return go_GetNameInfoW(sa, salen, host, hostlen, serv, servlen, flags);
}

/* --- Protocol/service lookups --- */

void* __stdcall getprotobyname(char* name) {
    return go_getprotobyname(name);
}

void* __stdcall getprotobynumber(int proto) {
    return go_getprotobynumber(proto);
}

void* __stdcall getservbyname(char* name, char* proto) {
    return go_getservbyname(name, proto);
}

void* __stdcall getservbyport(int port, char* proto) {
    return go_getservbyport(port, proto);
}

/* --- Byte order --- */

double __stdcall htond(double hostdouble) {
    return go_htond(hostdouble);
}

float __stdcall htonf(float hostfloat) {
    return go_htonf(hostfloat);
}

unsigned long __stdcall htonl(unsigned long hostlong) {
    return go_htonl(hostlong);
}

unsigned long long __stdcall htonll(unsigned long long hostlonglong) {
    return go_htonll(hostlonglong);
}

unsigned short __stdcall htons(unsigned short hostshort) {
    return go_htons(hostshort);
}

double __stdcall ntohd(double netdouble) {
    return go_ntohd(netdouble);
}

float __stdcall ntohf(float netfloat) {
    return go_ntohf(netfloat);
}

unsigned long __stdcall ntohl(unsigned long netlong) {
    return go_ntohl(netlong);
}

unsigned long long __stdcall ntohll(unsigned long long netlonglong) {
    return go_ntohll(netlonglong);
}

unsigned short __stdcall ntohs(unsigned short netshort) {
    return go_ntohs(netshort);
}

/* --- Address string conversion --- */

unsigned long __stdcall inet_addr(char* cp) {
    return go_inet_addr(cp);
}

char* __stdcall inet_ntoa(unsigned long in) {
    return go_inet_ntoa(in);
}

int __stdcall inet_pton(int family, char* src, void* dst) {
    return go_inet_pton(family, src, dst);
}

char* __stdcall inet_ntop(int family, void* src, char* dst, int size) {
    return go_inet_ntop(family, src, dst, size);
}

int __stdcall InetPtonW(int family, unsigned short* src, void* dst) {
    return go_InetPtonW(family, src, dst);
}

unsigned short* __stdcall InetNtopW(int family, void* src, unsigned short* dst, int size) {
    return go_InetNtopW(family, src, dst, size);
}

/* --- WSA lifecycle --- */

int __stdcall WSAStartup(unsigned short wVersionRequested, void* lpWSAData) {
    return go_WSAStartup(wVersionRequested, lpWSAData);
}

int __stdcall WSACleanup(void) {
    return go_WSACleanup();
}

int __stdcall WSAGetLastError(void) {
    return go_WSAGetLastError();
}

void __stdcall WSASetLastError(int iError) {
    go_WSASetLastError(iError);
}

/* --- WSA extended socket --- */

unsigned int __stdcall WSAAccept(unsigned int s, void* addr, int* addrlen, void* lpfnCondition, unsigned long dwCallbackData) {
    return go_WSAAccept(s, addr, addrlen, lpfnCondition, dwCallbackData);
}

unsigned int __stdcall WSASocketA(int af, int type, int protocol, void* lpProtocolInfo, unsigned int g, unsigned long dwFlags) {
    return go_WSASocketA(af, type, protocol, lpProtocolInfo, g, dwFlags);
}

unsigned int __stdcall WSASocketW(int af, int type, int protocol, void* lpProtocolInfo, unsigned int g, unsigned long dwFlags) {
    return go_WSASocketW(af, type, protocol, lpProtocolInfo, g, dwFlags);
}

int __stdcall WSAConnect(unsigned int s, void* name, int namelen, void* lpCallerData, void* lpCalleeData, void* lpSQOS, void* lpGQOS) {
    return go_WSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
}

int __stdcall WSAConnectByList(unsigned int s, void* SocketAddressList, unsigned long* LocalAddressLength, void* LocalAddress, unsigned long* RemoteAddressLength, void* RemoteAddress, void* timeout, void* Reserved) {
    return go_WSAConnectByList(s, SocketAddressList, LocalAddressLength, LocalAddress, RemoteAddressLength, RemoteAddress, timeout, Reserved);
}

int __stdcall WSAConnectByNameA(unsigned int s, char* nodename, char* servicename, unsigned long* LocalAddressLength, void* LocalAddress, unsigned long* RemoteAddressLength, void* RemoteAddress, void* timeout, void* Reserved) {
    return go_WSAConnectByNameA(s, nodename, servicename, LocalAddressLength, LocalAddress, RemoteAddressLength, RemoteAddress, timeout, Reserved);
}

int __stdcall WSAConnectByNameW(unsigned int s, unsigned short* nodename, unsigned short* servicename, unsigned long* LocalAddressLength, void* LocalAddress, unsigned long* RemoteAddressLength, void* RemoteAddress, void* timeout, void* Reserved) {
    return go_WSAConnectByNameW(s, nodename, servicename, LocalAddressLength, LocalAddress, RemoteAddressLength, RemoteAddress, timeout, Reserved);
}

int __stdcall WSADuplicateSocketA(unsigned int s, unsigned long dwProcessId, void* lpProtocolInfo) {
    return go_WSADuplicateSocketA(s, dwProcessId, lpProtocolInfo);
}

int __stdcall WSADuplicateSocketW(unsigned int s, unsigned long dwProcessId, void* lpProtocolInfo) {
    return go_WSADuplicateSocketW(s, dwProcessId, lpProtocolInfo);
}

int __stdcall WSAAsyncSelect(unsigned int s, void* hWnd, unsigned int wMsg, int lEvent) {
    return go_WSAAsyncSelect(s, hWnd, wMsg, lEvent);
}

/* --- WSA event objects --- */

void* __stdcall WSACreateEvent(void) {
    return go_WSACreateEvent();
}

int __stdcall WSACloseEvent(void* hEvent) {
    return go_WSACloseEvent(hEvent);
}

int __stdcall WSASetEvent(void* hEvent) {
    return go_WSASetEvent(hEvent);
}

int __stdcall WSAResetEvent(void* hEvent) {
    return go_WSAResetEvent(hEvent);
}

int __stdcall WSAEventSelect(unsigned int s, void* hEventObject, int lNetworkEvents) {
    return go_WSAEventSelect(s, hEventObject, lNetworkEvents);
}

int __stdcall WSAEnumNetworkEvents(unsigned int s, void* hEventObject, void* lpNetworkEvents) {
    return go_WSAEnumNetworkEvents(s, hEventObject, lpNetworkEvents);
}

unsigned long __stdcall WSAWaitForMultipleEvents(unsigned long cEvents, void** lphEvents, int fWaitAll, unsigned long dwTimeout, int fAlertable) {
    return go_WSAWaitForMultipleEvents(cEvents, lphEvents, fWaitAll, dwTimeout, fAlertable);
}

/* --- WSA I/O --- */

int __stdcall WSARecv(unsigned int s, void* lpBuffers, unsigned long dwBufferCount, unsigned long* lpNumberOfBytesRecvd, unsigned long* lpFlags, void* lpOverlapped, void* lpCompletionRoutine) {
    return go_WSARecv(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped, lpCompletionRoutine);
}

int __stdcall WSARecvDisconnect(unsigned int s, void* lpInboundDisconnectData) {
    return go_WSARecvDisconnect(s, lpInboundDisconnectData);
}

int __stdcall WSARecvFrom(unsigned int s, void* lpBuffers, unsigned long dwBufferCount, unsigned long* lpNumberOfBytesRecvd, unsigned long* lpFlags, void* lpFrom, int* lpFromlen, void* lpOverlapped, void* lpCompletionRoutine) {
    return go_WSARecvFrom(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpFrom, lpFromlen, lpOverlapped, lpCompletionRoutine);
}

int __stdcall WSARecvMsg(unsigned int s, void* lpMsg, unsigned long* lpdwBytesReceived, void* lpOverlapped, void* lpCompletionRoutine) {
    return go_WSARecvMsg(s, lpMsg, lpdwBytesReceived, lpOverlapped, lpCompletionRoutine);
}

int __stdcall WSASend(unsigned int s, void* lpBuffers, unsigned long dwBufferCount, unsigned long* lpNumberOfBytesSent, unsigned long dwFlags, void* lpOverlapped, void* lpCompletionRoutine) {
    return go_WSASend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine);
}

int __stdcall WSASendDisconnect(unsigned int s, void* lpOutboundDisconnectData) {
    return go_WSASendDisconnect(s, lpOutboundDisconnectData);
}

int __stdcall WSASendMsg(unsigned int s, void* lpMsg, unsigned long dwFlags, unsigned long* lpdwBytesSent, void* lpOverlapped, void* lpCompletionRoutine) {
    return go_WSASendMsg(s, lpMsg, dwFlags, lpdwBytesSent, lpOverlapped, lpCompletionRoutine);
}

int __stdcall WSASendTo(unsigned int s, void* lpBuffers, unsigned long dwBufferCount, unsigned long* lpNumberOfBytesSent, unsigned long dwFlags, void* lpTo, int iTolen, void* lpOverlapped, void* lpCompletionRoutine) {
    return go_WSASendTo(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpTo, iTolen, lpOverlapped, lpCompletionRoutine);
}

int __stdcall WSAIoctl(unsigned int s, unsigned long dwIoControlCode, void* lpvInBuffer, unsigned long cbInBuffer, void* lpvOutBuffer, unsigned long cbOutBuffer, unsigned long* lpcbBytesReturned, void* lpOverlapped, void* lpCompletionRoutine) {
    return go_WSAIoctl(s, dwIoControlCode, lpvInBuffer, cbInBuffer, lpvOutBuffer, cbOutBuffer, lpcbBytesReturned, lpOverlapped, lpCompletionRoutine);
}

int __stdcall WSAGetOverlappedResult(unsigned int s, void* lpOverlapped, unsigned long* lpcbTransfer, int fWait, unsigned long* lpdwFlags) {
    return go_WSAGetOverlappedResult(s, lpOverlapped, lpcbTransfer, fWait, lpdwFlags);
}

int __stdcall WSAGetQOSByName(unsigned int s, void* lpQOSName, void* lpQOS) {
    return go_WSAGetQOSByName(s, lpQOSName, lpQOS);
}

/* --- WSA poll/select helpers --- */

int __stdcall WSAPoll(void* fdArray, unsigned long fds, int timeout) {
    return go_WSAPoll(fdArray, fds, timeout);
}

int __stdcall __WSAFDIsSet(unsigned int s, void* fdset) {
    return go___WSAFDIsSet(s, fdset);
}

/* --- WSA byte order helpers --- */

int __stdcall WSAHtonl(unsigned int s, unsigned long hostlong, unsigned long* lpnetlong) {
    return go_WSAHtonl(s, hostlong, lpnetlong);
}

int __stdcall WSAHtons(unsigned int s, unsigned short hostshort, unsigned short* lpnetshort) {
    return go_WSAHtons(s, hostshort, lpnetshort);
}

int __stdcall WSANtohl(unsigned int s, unsigned long netlong, unsigned long* lphostlong) {
    return go_WSANtohl(s, netlong, lphostlong);
}

int __stdcall WSANtohs(unsigned int s, unsigned short netshort, unsigned short* lphostshort) {
    return go_WSANtohs(s, netshort, lphostshort);
}

/* --- WSA address string conversion --- */

int __stdcall WSAAddressToStringA(void* lpsaAddress, unsigned long dwAddressLength, void* lpProtocolInfo, char* lpszAddressString, unsigned long* lpdwAddressStringLength) {
    return go_WSAAddressToStringA(lpsaAddress, dwAddressLength, lpProtocolInfo, lpszAddressString, lpdwAddressStringLength);
}

int __stdcall WSAAddressToStringW(void* lpsaAddress, unsigned long dwAddressLength, void* lpProtocolInfo, unsigned short* lpszAddressString, unsigned long* lpdwAddressStringLength) {
    return go_WSAAddressToStringW(lpsaAddress, dwAddressLength, lpProtocolInfo, lpszAddressString, lpdwAddressStringLength);
}

int __stdcall WSAStringToAddressA(char* AddressString, int AddressFamily, void* lpProtocolInfo, void* lpAddress, int* lpAddressLength) {
    return go_WSAStringToAddressA(AddressString, AddressFamily, lpProtocolInfo, lpAddress, lpAddressLength);
}

int __stdcall WSAStringToAddressW(unsigned short* AddressString, int AddressFamily, void* lpProtocolInfo, void* lpAddress, int* lpAddressLength) {
    return go_WSAStringToAddressW(AddressString, AddressFamily, lpProtocolInfo, lpAddress, lpAddressLength);
}

/* --- WSA protocol enumeration --- */

int __stdcall WSAEnumProtocolsA(int* lpiProtocols, void* lpProtocolBuffer, unsigned long* lpdwBufferLength) {
    return go_WSAEnumProtocolsA(lpiProtocols, lpProtocolBuffer, lpdwBufferLength);
}

int __stdcall WSAEnumProtocolsW(int* lpiProtocols, void* lpProtocolBuffer, unsigned long* lpdwBufferLength) {
    return go_WSAEnumProtocolsW(lpiProtocols, lpProtocolBuffer, lpdwBufferLength);
}

/* --- WSA namespace/service --- */

int __stdcall WSAEnumNameSpaceProvidersA(unsigned long* lpdwBufferLength, void* lpnspBuffer) {
    return go_WSAEnumNameSpaceProvidersA(lpdwBufferLength, lpnspBuffer);
}

int __stdcall WSAEnumNameSpaceProvidersExA(unsigned long* lpdwBufferLength, void* lpnspBuffer) {
    return go_WSAEnumNameSpaceProvidersExA(lpdwBufferLength, lpnspBuffer);
}

int __stdcall WSAEnumNameSpaceProvidersExW(unsigned long* lpdwBufferLength, void* lpnspBuffer) {
    return go_WSAEnumNameSpaceProvidersExW(lpdwBufferLength, lpnspBuffer);
}

int __stdcall WSAEnumNameSpaceProvidersW(unsigned long* lpdwBufferLength, void* lpnspBuffer) {
    return go_WSAEnumNameSpaceProvidersW(lpdwBufferLength, lpnspBuffer);
}

int __stdcall WSAInstallServiceClassA(void* lpServiceClassInfo) {
    return go_WSAInstallServiceClassA(lpServiceClassInfo);
}

int __stdcall WSAInstallServiceClassW(void* lpServiceClassInfo) {
    return go_WSAInstallServiceClassW(lpServiceClassInfo);
}

int __stdcall WSARemoveServiceClass(void* lpServiceClassId) {
    return go_WSARemoveServiceClass(lpServiceClassId);
}

int __stdcall WSAGetServiceClassInfoA(void* lpProviderId, void* lpServiceClassId, unsigned long* lpdwBufLenth, void* lpServiceClassInfo) {
    return go_WSAGetServiceClassInfoA(lpProviderId, lpServiceClassId, lpdwBufLenth, lpServiceClassInfo);
}

int __stdcall WSAGetServiceClassInfoW(void* lpProviderId, void* lpServiceClassId, unsigned long* lpdwBufLenth, void* lpServiceClassInfo) {
    return go_WSAGetServiceClassInfoW(lpProviderId, lpServiceClassId, lpdwBufLenth, lpServiceClassInfo);
}

int __stdcall WSAGetServiceClassNameByClassIdA(void* lpServiceClassId, char* lpszServiceClassName, unsigned long* lpdwBufferLength) {
    return go_WSAGetServiceClassNameByClassIdA(lpServiceClassId, lpszServiceClassName, lpdwBufferLength);
}

int __stdcall WSAGetServiceClassNameByClassIdW(void* lpServiceClassId, unsigned short* lpszServiceClassName, unsigned long* lpdwBufferLength) {
    return go_WSAGetServiceClassNameByClassIdW(lpServiceClassId, lpszServiceClassName, lpdwBufferLength);
}

int __stdcall WSASetServiceA(void* lpqsRegInfo, int essOperation, unsigned long dwControlFlags) {
    return go_WSASetServiceA(lpqsRegInfo, essOperation, dwControlFlags);
}

int __stdcall WSASetServiceW(void* lpqsRegInfo, int essOperation, unsigned long dwControlFlags) {
    return go_WSASetServiceW(lpqsRegInfo, essOperation, dwControlFlags);
}

int __stdcall WSALookupServiceBeginA(void* lpqsRestrictions, unsigned long dwControlFlags, void** lphLookup) {
    return go_WSALookupServiceBeginA(lpqsRestrictions, dwControlFlags, lphLookup);
}

int __stdcall WSALookupServiceBeginW(void* lpqsRestrictions, unsigned long dwControlFlags, void** lphLookup) {
    return go_WSALookupServiceBeginW(lpqsRestrictions, dwControlFlags, lphLookup);
}

int __stdcall WSALookupServiceEnd(void* hLookup) {
    return go_WSALookupServiceEnd(hLookup);
}

int __stdcall WSALookupServiceNextA(void* hLookup, unsigned long dwControlFlags, unsigned long* lpdwBufferLength, void* lpqsResults) {
    return go_WSALookupServiceNextA(hLookup, dwControlFlags, lpdwBufferLength, lpqsResults);
}

int __stdcall WSALookupServiceNextW(void* hLookup, unsigned long dwControlFlags, unsigned long* lpdwBufferLength, void* lpqsResults) {
    return go_WSALookupServiceNextW(hLookup, dwControlFlags, lpdwBufferLength, lpqsResults);
}

int __stdcall WSANSPIoctl(void* hLookup, unsigned long dwControlCode, void* lpvInBuffer, unsigned long cbInBuffer, void* lpvOutBuffer, unsigned long cbOutBuffer, unsigned long* lpcbBytesReturned, void* lpCompletion) {
    return go_WSANSPIoctl(hLookup, dwControlCode, lpvInBuffer, cbInBuffer, lpvOutBuffer, cbOutBuffer, lpcbBytesReturned, lpCompletion);
}

int __stdcall WSAProviderConfigChange(void** lpNotificationHandle, void* lpOverlapped, void* lpCompletionRoutine) {
    return go_WSAProviderConfigChange(lpNotificationHandle, lpOverlapped, lpCompletionRoutine);
}

/* --- WSA notification stubs --- */

int __stdcall ProcessSocketNotifications(void* completionPort, unsigned int registrationCount, void* registrationInfos, unsigned int timeout, unsigned int completionCount, void* completionInfos, unsigned long* receivedCount) {
    return go_ProcessSocketNotifications(completionPort, registrationCount, registrationInfos, timeout, completionCount, completionInfos, receivedCount);
}

int __stdcall SocketNotificationRetrieveEvents(void* notificationRegistration, void* notificationEvents) {
    return go_SocketNotificationRetrieveEvents(notificationRegistration, notificationEvents);
}

/* --- Extended connection APIs --- */

int __stdcall AcceptEx(unsigned int sListenSocket, unsigned int sAcceptSocket, void* lpOutputBuffer, unsigned long dwReceiveDataLength, unsigned long dwLocalAddressLength, unsigned long dwRemoteAddressLength, unsigned long* lpdwBytesReceived, void* lpOverlapped) {
    return go_AcceptEx(sListenSocket, sAcceptSocket, lpOutputBuffer, dwReceiveDataLength, dwLocalAddressLength, dwRemoteAddressLength, lpdwBytesReceived, lpOverlapped);
}

int __stdcall ConnectEx(unsigned int s, void* name, int namelen, void* lpSendBuffer, unsigned long dwSendDataLength, unsigned long* lpdwBytesSent, void* lpOverlapped) {
    return go_ConnectEx(s, name, namelen, lpSendBuffer, dwSendDataLength, lpdwBytesSent, lpOverlapped);
}

/* --- Legacy async functions --- */

unsigned int __stdcall WSAAsyncGetHostByAddr(void* hWnd, unsigned int wMsg, char* addr, int addrLen, int addrType, void* buf, int bufLen) {
    return go_WSAAsyncGetHostByAddr(hWnd, wMsg, addr, addrLen, addrType, buf, bufLen);
}

unsigned int __stdcall WSAAsyncGetHostByName(void* hWnd, unsigned int wMsg, char* name, void* buf, int bufLen) {
    return go_WSAAsyncGetHostByName(hWnd, wMsg, name, buf, bufLen);
}

unsigned int __stdcall WSAAsyncGetServByPort(void* hWnd, unsigned int wMsg, int port, char* proto, void* buf, int bufLen) {
    return go_WSAAsyncGetServByPort(hWnd, wMsg, port, proto, buf, bufLen);
}

unsigned int __stdcall WSAAsyncGetProtoByName(void* hWnd, unsigned int wMsg, char* name, void* buf, int bufLen) {
    return go_WSAAsyncGetProtoByName(hWnd, wMsg, name, buf, bufLen);
}

unsigned int __stdcall WSAAsyncGetProtoByNumber(void* hWnd, unsigned int wMsg, int number, void* buf, int bufLen) {
    return go_WSAAsyncGetProtoByNumber(hWnd, wMsg, number, buf, bufLen);
}

unsigned int __stdcall WSAAsyncGetServByName(void* hWnd, unsigned int wMsg, char* name, char* proto, void* buf, int bufLen) {
    return go_WSAAsyncGetServByName(hWnd, wMsg, name, proto, buf, bufLen);
}

int __stdcall WSACancelAsyncRequest(unsigned int hAsyncTaskHandle) {
    return go_WSACancelAsyncRequest(hAsyncTaskHandle);
}

/* --- Legacy blocking hooks --- */

void* __stdcall WSASetBlockingHook(void* lpBlockFunc) {
    return go_WSASetBlockingHook(lpBlockFunc);
}

int __stdcall WSAUnhookBlockingHook(void) {
    return go_WSAUnhookBlockingHook();
}

int __stdcall WSACancelBlockingCall(void) {
    return go_WSACancelBlockingCall();
}

int __stdcall WSAIsBlocking(void) {
    return go_WSAIsBlocking();
}
