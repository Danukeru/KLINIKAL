// lifecycle.go — WSA lifecycle management. Implements WSAStartup (reference-counted
// initialization that populates a WSADATA struct with version 2.2, description, and
// system status) and WSACleanup (decrements the reference count and calls PurgeAll
// to close all sockets when the last consumer cleans up).
package winsock

import (
	"sync"
	"unsafe"
)

type wsaData struct {
	wVersion       uint16
	wHighVersion   uint16
	szDescription  [257]byte
	szSystemStatus [129]byte
	iMaxSockets    uint16
	iMaxUdpDg      uint16
	lpVendorInfo   unsafe.Pointer
}

var (
	wsaRefCount int
	wsaMu       sync.Mutex
)

// goWSAStartup initializes the Winsock DLL and provides version negotiation.
func GoWSAStartup(wVersionRequested uint16, lpWSAData unsafe.Pointer) int32 {
	LogCall("WSAStartup", wVersionRequested, lpWSAData)
	wsaMu.Lock()
	defer wsaMu.Unlock()

	wsaRefCount++

	if lpWSAData != nil {
		data := (*wsaData)(lpWSAData)
		data.wVersion = wVersionRequested
		data.wHighVersion = 0x0202 // Support up to 2.2
		copy(data.szDescription[:], "Go-Winsock Bridge")
		copy(data.szSystemStatus[:], "Running")
		data.iMaxSockets = 32767
		data.iMaxUdpDg = 65467
	}

	// Phase 5: Initialize WireGuard stack during WSAStartup
	// We ignore the error as the stack will try to auto-init on first GetStack call if possible
	_ = InitializeStack("wg.conf")

	return 0
}

// goWSACleanup terminates the use of the Winsock DLL.
func GoWSACleanup() int32 {
	LogCall("WSACleanup")
	wsaMu.Lock()
	defer wsaMu.Unlock()

	if wsaRefCount > 0 {
		wsaRefCount--
		if wsaRefCount == 0 {
			registry.PurgeAll()
			CloseStack() // Shutdown WireGuard stack
		}
	}

	return 0
}
