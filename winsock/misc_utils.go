// misc_utils.go — Miscellaneous Winsock utility functions. Implements __WSAFDIsSet
// (checks whether a socket handle exists in an fd_set by iterating its handle
// array), WSAGetQOSByName (stub — QOS not applicable in the Go bridge), and
// WSAProviderConfigChange (stub — provider change notification not applicable).
package winsock

import (
	"unsafe"
)

// goWSAFDIsSet checks if a socket is part of a socket set.
func GoWSAFDIsSet(s uint64, fdset unsafe.Pointer) int32 {
	LogCall("WSAFDIsSet", s, fdset)
	if fdset == nil {
		return 0
	}

	fds := (*struct {
		Count uint32
		Array [64]uint32
	})(fdset)

	for i := uint32(0); i < fds.Count; i++ {
		if uint64(fds.Array[i]) == s {
			return 1
		}
	}
	return 0
}

// goWSAProviderConfigChange notifies the application when the provider configuration changes.
// It should return 0 on success.
func GoWSAProviderConfigChange(lpNotificationHandle *unsafe.Pointer, lpOverlapped unsafe.Pointer, lpCompletionRoutine unsafe.Pointer) int32 {
	LogCall("WSAProviderConfigChange", lpNotificationHandle, lpOverlapped, lpCompletionRoutine)
	// Dummy implementation: always succeed
	return 0
}

// goWSAGetQOSByName retrieves a QOS structure by name.
// It should return 0 on success.
func GoWSAGetQOSByName(s uint64, lpQOSName unsafe.Pointer, lpQOS unsafe.Pointer) int32 {
	LogCall("WSAGetQOSByName", s, lpQOSName, lpQOS)
	// Dummy implementation: always succeed
	return 0
}
