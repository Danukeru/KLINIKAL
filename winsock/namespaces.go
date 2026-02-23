// namespaces.go — Namespace provider enumeration stubs. Implements
// WSAEnumNameSpaceProvidersA/W and WSAEnumNameSpaceProvidersExA/W, all returning
// zero providers. Namespace provider management is not applicable in the Go
// bridge but these exports are required for link compatibility.
package winsock

import (
	"unsafe"
)

// goWSAEnumNameSpaceProvidersA retrieves information about available namespace providers. (ANSI)
func GoWSAEnumNameSpaceProvidersA(lpdwBufferLength *uint32, lpnspBuffer unsafe.Pointer) int32 {
	LogCall("WSAEnumNameSpaceProvidersA", lpdwBufferLength, lpnspBuffer)
	if lpdwBufferLength != nil {
		*lpdwBufferLength = 0
	}
	return 0
}

// goWSAEnumNameSpaceProvidersW retrieves information about available namespace providers. (Unicode)
func GoWSAEnumNameSpaceProvidersW(lpdwBufferLength *uint32, lpnspBuffer unsafe.Pointer) int32 {
	LogCall("WSAEnumNameSpaceProvidersW", lpdwBufferLength, lpnspBuffer)
	if lpdwBufferLength != nil {
		*lpdwBufferLength = 0
	}
	return 0
}

// goWSAEnumNameSpaceProvidersExA retrieves information about available namespace providers with extended info. (ANSI)
func GoWSAEnumNameSpaceProvidersExA(lpdwBufferLength *uint32, lpnspBuffer unsafe.Pointer) int32 {
	LogCall("WSAEnumNameSpaceProvidersExA", lpdwBufferLength, lpnspBuffer)
	if lpdwBufferLength != nil {
		*lpdwBufferLength = 0
	}
	return 0
}

// goWSAEnumNameSpaceProvidersExW retrieves information about available namespace providers with extended info. (Unicode)
func GoWSAEnumNameSpaceProvidersExW(lpdwBufferLength *uint32, lpnspBuffer unsafe.Pointer) int32 {
	LogCall("WSAEnumNameSpaceProvidersExW", lpdwBufferLength, lpnspBuffer)
	if lpdwBufferLength != nil {
		*lpdwBufferLength = 0
	}
	return 0
}
