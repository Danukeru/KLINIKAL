// svc_disc.go — Service discovery and service class management stubs. Implements
// WSALookupServiceBeginA/W (returns a dummy lookup handle), WSALookupServiceNextA/W
// (returns WSA_E_NO_MORE), WSALookupServiceEnd, WSASetServiceA/W,
// WSAGetServiceClassInfoA/W, WSAGetServiceClassNameByClassIdA/W,
// WSAInstallServiceClassA/W, and WSARemoveServiceClass. All are minimal stubs
// required for link compatibility — service registration and class management are
// not applicable in the Go bridge.
package winsock

import (
	"unsafe"
)

// goWSALookupServiceBeginA begins a client query for a network service. (ANSI)
func GoWSALookupServiceBeginA(lpqsRestrictions unsafe.Pointer, dwControlFlags uint32, lphLookup *unsafe.Pointer) int32 {
	LogCall("WSALookupServiceBeginA", lpqsRestrictions, dwControlFlags, lphLookup)
	if lphLookup != nil {
		*lphLookup = unsafe.Pointer(uintptr(0xDEADBEEF))
	}
	return 0
}

// goWSALookupServiceBeginW begins a client query for a network service. (Unicode)
func GoWSALookupServiceBeginW(lpqsRestrictions unsafe.Pointer, dwControlFlags uint32, lphLookup *unsafe.Pointer) int32 {
	LogCall("WSALookupServiceBeginW", lpqsRestrictions, dwControlFlags, lphLookup)
	if lphLookup != nil {
		*lphLookup = unsafe.Pointer(uintptr(0xDEADBEEF))
	}
	return 0
}

// goWSALookupServiceNextA retrieves results from a previous service lookup. (ANSI)
func GoWSALookupServiceNextA(hLookup unsafe.Pointer, dwControlFlags uint32, lpdwBufferLength *uint32, lpqsResults unsafe.Pointer) int32 {
	LogCall("WSALookupServiceNextA", hLookup, dwControlFlags, lpdwBufferLength, lpqsResults)
	setLastError(10110) // WSA_E_NO_MORE
	return -1
}

// goWSALookupServiceNextW retrieves results from a previous service lookup. (Unicode)
func GoWSALookupServiceNextW(hLookup unsafe.Pointer, dwControlFlags uint32, lpdwBufferLength *uint32, lpqsResults unsafe.Pointer) int32 {
	LogCall("WSALookupServiceNextW", hLookup, dwControlFlags, lpdwBufferLength, lpqsResults)
	setLastError(10110) // WSA_E_NO_MORE
	return -1
}

// goWSALookupServiceEnd terminates the use of a service lookup handle.
// It should return 0 on success.
func GoWSALookupServiceEnd(hLookup unsafe.Pointer) int32 {
	LogCall("WSALookupServiceEnd", hLookup)
	// Dummy implementation: always succeed
	return 0
}

// goWSASetServiceA registers or removes a service instance within one or more namespaces. (ANSI)
// It should return 0 on success.
func GoWSASetServiceA(lpqsRegInfo unsafe.Pointer, essOperation int32, dwControlFlags uint32) int32 {
	LogCall("WSASetServiceA", lpqsRegInfo, essOperation, dwControlFlags)
	// Dummy implementation: always succeed
	return 0
}

// goWSASetServiceW registers or removes a service instance within one or more namespaces. (Unicode)
// It should return 0 on success.
func GoWSASetServiceW(lpqsRegInfo unsafe.Pointer, essOperation int32, dwControlFlags uint32) int32 {
	LogCall("WSASetServiceW", lpqsRegInfo, essOperation, dwControlFlags)
	// Dummy implementation: always succeed
	return 0
}

// goWSAGetServiceClassInfoA retrieves the class information for a specified provider. (ANSI)
// It should return 0 on success.
func GoWSAGetServiceClassInfoA(lpProviderId unsafe.Pointer, lpServiceClassId unsafe.Pointer, lpdwBufLenth *uint32, lpServiceClassInfo unsafe.Pointer) int32 {
	LogCall("WSAGetServiceClassInfoA", lpProviderId, lpServiceClassId, lpdwBufLenth, lpServiceClassInfo)
	// Dummy implementation: always succeed
	return 0
}

// goWSAGetServiceClassInfoW retrieves the class information for a specified provider. (Unicode)
// It should return 0 on success.
func GoWSAGetServiceClassInfoW(lpProviderId unsafe.Pointer, lpServiceClassId unsafe.Pointer, lpdwBufLenth *uint32, lpServiceClassInfo unsafe.Pointer) int32 {
	LogCall("WSAGetServiceClassInfoW", lpProviderId, lpServiceClassId, lpdwBufLenth, lpServiceClassInfo)
	// Dummy implementation: always succeed
	return 0
}

// goWSAGetServiceClassNameByClassIdA retrieves the name of the service associated with the specified type. (ANSI)
// It should return 0 on success.
func GoWSAGetServiceClassNameByClassIdA(lpServiceClassId unsafe.Pointer, lpszServiceClassName *byte, lpdwBufferLength *uint32) int32 {
	LogCall("WSAGetServiceClassNameByClassIdA", lpServiceClassId, lpszServiceClassName, lpdwBufferLength)
	// Dummy implementation: always succeed
	return 0
}

// goWSAGetServiceClassNameByClassIdW retrieves the name of the service associated with the specified type. (Unicode)
// It should return 0 on success.
func GoWSAGetServiceClassNameByClassIdW(lpServiceClassId unsafe.Pointer, lpszServiceClassName *uint16, lpdwBufferLength *uint32) int32 {
	LogCall("WSAGetServiceClassNameByClassIdW", lpServiceClassId, lpszServiceClassName, lpdwBufferLength)
	// Dummy implementation: always succeed
	return 0
}

// goWSAInstallServiceClassA registers a service class schema within a namespace. (ANSI)
// It should return 0 on success.
func GoWSAInstallServiceClassA(lpServiceClassInfo unsafe.Pointer) int32 {
	LogCall("WSAInstallServiceClassA", lpServiceClassInfo)
	// Dummy implementation: always succeed
	return 0
}

// goWSAInstallServiceClassW registers a service class schema within a namespace. (Unicode)
// It should return 0 on success.
func GoWSAInstallServiceClassW(lpServiceClassInfo unsafe.Pointer) int32 {
	LogCall("WSAInstallServiceClassW", lpServiceClassInfo)
	// Dummy implementation: always succeed
	return 0
}

// goWSARemoveServiceClass permanently removes a specified service class schema.
// It should return 0 on success.
func GoWSARemoveServiceClass(lpServiceClassId unsafe.Pointer) int32 {
	LogCall("WSARemoveServiceClass", lpServiceClassId)
	// Dummy implementation: always succeed
	return 0
}
