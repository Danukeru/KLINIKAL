// event_objects.go — Winsock event object management. Implements WSACreateEvent
// (creates a buffered channel and registers it in the registry), WSACloseEvent,
// WSASetEvent (signals the channel), WSAResetEvent (drains the channel), and
// WSAWaitForMultipleEvents (uses reflect.Select with an optional timeout to wait
// on one or all events). These channels serve as the signaling mechanism for
// overlapped I/O completion and WSAEventSelect-driven notification.
package winsock

import (
	"reflect"
	"time"
	"unsafe"
)

// goWSACreateEvent creates a new event object.
func GoWSACreateEvent() unsafe.Pointer {
	LogCall("WSACreateEvent")
	handle := registry.RegisterEvent()
	return unsafe.Pointer(handle)
}

// goWSACloseEvent closes an open event object handle.
func GoWSACloseEvent(hEvent unsafe.Pointer) int32 {
	LogCall("WSACloseEvent", hEvent)
	handle := uintptr(hEvent)
	registry.UnregisterEvent(handle)
	return 1 // TRUE
}

// goWSASetEvent sets the state of the specified event object to signaled.
func GoWSASetEvent(hEvent unsafe.Pointer) int32 {
	LogCall("WSASetEvent", hEvent)
	handle := uintptr(hEvent)
	c, ok := registry.GetEvent(handle)
	if !ok {
		return 0 // FALSE
	}

	// Signal it
	select {
	case c <- struct{}{}:
	default:
	}
	return 1
}

// goWSAResetEvent sets the state of the specified event object to nonsignaled.
func GoWSAResetEvent(hEvent unsafe.Pointer) int32 {
	LogCall("WSAResetEvent", hEvent)
	handle := uintptr(hEvent)
	c, ok := registry.GetEvent(handle)
	if !ok {
		return 0
	}

	// Drain it
	select {
	case <-c:
	default:
	}
	return 1
}

// goWSAWaitForMultipleEvents waits for one or all of the specified event objects to be in the signaled state.
func GoWSAWaitForMultipleEvents(cEvents uint32, lphEvents *unsafe.Pointer, fWaitAll int32, dwTimeout uint32, fAlertable int32) uint32 {
	LogCall("WSAWaitForMultipleEvents", cEvents, lphEvents, fWaitAll, dwTimeout, fAlertable)

	if lphEvents == nil || cEvents == 0 {
		return 0xFFFFFFFF // WAIT_FAILED
	}

	handles := unsafe.Slice((*unsafe.Pointer)(lphEvents), int(cEvents))
	var cases []reflect.SelectCase

	for _, h := range handles {
		c, ok := registry.GetEvent(uintptr(h))
		if ok {
			cases = append(cases, reflect.SelectCase{
				Dir:  reflect.SelectRecv,
				Chan: reflect.ValueOf(c),
			})
		}
	}

	if dwTimeout != 0xFFFFFFFF {
		timer := time.NewTimer(time.Duration(dwTimeout) * time.Millisecond)
		cases = append(cases, reflect.SelectCase{
			Dir:  reflect.SelectRecv,
			Chan: reflect.ValueOf(timer.C),
		})
		defer timer.Stop()
	}

	chosen, _, ok := reflect.Select(cases)

	// In the case of timeout
	if dwTimeout != 0xFFFFFFFF && chosen == len(cases)-1 {
		return 0x102 // WAIT_TIMEOUT
	}

	if !ok {
		// Event was closed or some other error
		return 0xFFFFFFFF
	}

	return uint32(chosen)
}
