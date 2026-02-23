// io_multplx.go — I/O multiplexing and event-driven notification. Implements
// select (iterates fd_sets, probes read/write readiness via short-deadline I/O,
// modifies sets on return), WSAPoll (iterates WSAPOLLFD array and sets revents),
// WSAEventSelect (associates an event handle and network event mask with a socket,
// spawning a background monitor goroutine), WSAEnumNetworkEvents (returns and
// atomically resets accumulated fired events), and WSAAsyncSelect (returns
// WSAEOPNOTSUPP). Also stubs ProcessSocketNotifications and
// SocketNotificationRetrieveEvents.
package winsock

import (
	"sync/atomic"
	"time"
	"unsafe"

	"gvisor.dev/gvisor/pkg/waiter"
)

type timeval struct {
	Sec  int32
	Usec int32
}

type fd_set struct {
	Count uint32
	Array [64]uint32 // SOCKET = 4 bytes on Win32
}

// Network event flag constants (matching winsock2.h FD_* values)
const (
	FD_READ_BIT    = 0
	FD_WRITE_BIT   = 1
	FD_OOB_BIT     = 2
	FD_ACCEPT_BIT  = 3
	FD_CONNECT_BIT = 4
	FD_CLOSE_BIT   = 5

	FD_READ    = 1 << FD_READ_BIT
	FD_WRITE   = 1 << FD_WRITE_BIT
	FD_OOB     = 1 << FD_OOB_BIT
	FD_ACCEPT  = 1 << FD_ACCEPT_BIT
	FD_CONNECT = 1 << FD_CONNECT_BIT
	FD_CLOSE   = 1 << FD_CLOSE_BIT

	FD_MAX_EVENTS = 10
)

// wsaPollFD matches the Win32 WSAPOLLFD struct layout:
// { SOCKET fd (4); SHORT events (2); SHORT revents (2); } = 8 bytes total
type wsaPollFD struct {
	FD      uint32 // SOCKET = unsigned int on Win32
	Events  int16
	Revents int16
}

// POLLRDNORM/POLLWRNORM etc. constants
const (
	POLLIN     = 0x0100
	POLLRDNORM = 0x0100
	POLLPRI    = 0x0400
	POLLOUT    = 0x0010
	POLLWRNORM = 0x0010
	POLLERR    = 0x0001
	POLLHUP    = 0x0002
	POLLNVAL   = 0x0004
)

type channelNotifier chan struct{}

func (c channelNotifier) NotifyEvent(mask waiter.EventMask) {
	select {
	case c <- struct{}{}:
	default:
	}
}

// checkReadReady probes whether a socket has data available for reading.
func checkReadReady(st *SocketState) bool {
	if st.Endpoint != nil {
		mask := st.Endpoint.Readiness(waiter.EventIn | waiter.EventErr | waiter.EventHUp)
		return mask&(waiter.EventIn|waiter.EventErr|waiter.EventHUp) != 0
	}
	if st.Listener != nil {
		return true
	}
	return false
}

// checkWriteReady checks if a socket can accept data for writing.
func checkWriteReady(st *SocketState) bool {
	if st.Endpoint != nil {
		mask := st.Endpoint.Readiness(waiter.EventOut | waiter.EventErr | waiter.EventHUp)
		return mask&(waiter.EventOut|waiter.EventErr|waiter.EventHUp) != 0
	}
	if st.Conn == nil {
		return false
	}
	return true
}

func isTimeout(err error) bool {
	type timeouter interface{ Timeout() bool }
	if te, ok := err.(timeouter); ok {
		return te.Timeout()
	}
	return false
}

// goSelect determines the status of one or more sockets, waiting if necessary.
func GoSelect(nfds int32, readfds unsafe.Pointer, writefds unsafe.Pointer, exceptfds unsafe.Pointer, timeout unsafe.Pointer) int32 {
	LogCall("Select", nfds, readfds, writefds, exceptfds, timeout)

	var waitTime time.Duration
	infinite := false
	if timeout != nil {
		tv := (*timeval)(timeout)
		waitTime = time.Duration(tv.Sec)*time.Second + time.Duration(tv.Usec)*time.Microsecond
	} else {
		infinite = true
	}

	// Helper to check readiness
	checkReadiness := func() (int32, []uint32, []uint32) {
		readyCount := int32(0)
		var readRes []uint32
		var writeRes []uint32

		if readfds != nil {
			rs := (*fd_set)(readfds)
			for i := uint32(0); i < rs.Count; i++ {
				if st, ok := registry.Get(uint64(rs.Array[i])); ok {
					if checkReadReady(st) {
						readRes = append(readRes, rs.Array[i])
						readyCount++
					}
				}
			}
		}

		if writefds != nil {
			ws := (*fd_set)(writefds)
			for i := uint32(0); i < ws.Count; i++ {
				if st, ok := registry.Get(uint64(ws.Array[i])); ok {
					if checkWriteReady(st) {
						writeRes = append(writeRes, ws.Array[i])
						readyCount++
					}
				}
			}
		}

		// exceptfds — we don't track OOB, just clear
		if exceptfds != nil {
			es := (*fd_set)(exceptfds)
			es.Count = 0
		}

		return readyCount, readRes, writeRes
	}

	// Register waiters
	ch := make(channelNotifier, 1)
	type registration struct {
		wq    *waiter.Queue
		entry *waiter.Entry
	}
	var regs []registration

	register := func(fds unsafe.Pointer, mask waiter.EventMask) {
		if fds == nil {
			return
		}
		fs := (*fd_set)(fds)
		for i := uint32(0); i < fs.Count; i++ {
			if st, ok := registry.Get(uint64(fs.Array[i])); ok && st.WaiterQueue != nil {
				entry := &waiter.Entry{}
				entry.Init(ch, mask)
				st.WaiterQueue.EventRegister(entry)
				regs = append(regs, registration{wq: st.WaiterQueue, entry: entry})
			}
		}
	}

	register(readfds, waiter.EventIn|waiter.EventErr|waiter.EventHUp)
	register(writefds, waiter.EventOut|waiter.EventErr|waiter.EventHUp)

	unregister := func() {
		for _, reg := range regs {
			reg.wq.EventUnregister(reg.entry)
		}
	}
	defer unregister()

	// First pass: check if any are already ready
	readyCount, readRes, writeRes := checkReadiness()
	if readyCount > 0 || (!infinite && waitTime == 0) {
		if readfds != nil {
			rs := (*fd_set)(readfds)
			rs.Count = uint32(len(readRes))
			for i := 0; i < len(readRes); i++ {
				rs.Array[i] = readRes[i]
			}
		}
		if writefds != nil {
			ws := (*fd_set)(writefds)
			ws.Count = uint32(len(writeRes))
			for i := 0; i < len(writeRes); i++ {
				ws.Array[i] = writeRes[i]
			}
		}
		return readyCount
	}

	// Wait for event or timeout
	if infinite {
		<-ch
	} else {
		select {
		case <-ch:
		case <-time.After(waitTime):
		}
	}

	// Final pass: check readiness again
	readyCount, readRes, writeRes = checkReadiness()
	if readfds != nil {
		rs := (*fd_set)(readfds)
		rs.Count = uint32(len(readRes))
		for i := 0; i < len(readRes); i++ {
			rs.Array[i] = readRes[i]
		}
	}
	if writefds != nil {
		ws := (*fd_set)(writefds)
		ws.Count = uint32(len(writeRes))
		for i := 0; i < len(writeRes); i++ {
			ws.Array[i] = writeRes[i]
		}
	}
	return readyCount
}

// goWSAPoll determines the status of one or more sockets.
func GoWSAPoll(fdArray unsafe.Pointer, fds uint32, timeout int32) int32 {
	LogCall("WSAPoll", fdArray, fds, timeout)
	if fdArray == nil || fds == 0 {
		setLastError(WSAEINVAL)
		return -1
	}

	infinite := timeout < 0
	var waitTime time.Duration
	if !infinite {
		waitTime = time.Duration(timeout) * time.Millisecond
	}

	pollEntries := unsafe.Slice((*wsaPollFD)(fdArray), int(fds))

	checkReadiness := func() int32 {
		readyCount := int32(0)

		for i := uint32(0); i < fds; i++ {
			entry := &pollEntries[i]
			fdSocket := uint64(entry.FD)
			events := entry.Events

			entry.Revents = 0

			st, ok := registry.Get(fdSocket)
			if !ok {
				entry.Revents = POLLNVAL
				readyCount++
				continue
			}

			if st.Endpoint != nil {
				mask := st.Endpoint.Readiness(waiter.EventIn | waiter.EventOut | waiter.EventErr | waiter.EventHUp)
				if mask&waiter.EventErr != 0 {
					entry.Revents |= POLLERR
				}
				if mask&waiter.EventHUp != 0 {
					entry.Revents |= POLLHUP
				}
				if events&(POLLIN|POLLRDNORM) != 0 && mask&waiter.EventIn != 0 {
					entry.Revents |= POLLRDNORM
				}
				if events&(POLLOUT|POLLWRNORM) != 0 && mask&waiter.EventOut != 0 {
					entry.Revents |= POLLWRNORM
				}
			} else {
				if events&(POLLIN|POLLRDNORM) != 0 {
					if checkReadReady(st) {
						entry.Revents |= POLLRDNORM
					}
				}
				if events&(POLLOUT|POLLWRNORM) != 0 {
					if checkWriteReady(st) {
						entry.Revents |= POLLWRNORM
					}
				}
			}

			if entry.Revents != 0 {
				readyCount++
			}
		}
		return readyCount
	}

	// Register waiters
	ch := make(channelNotifier, 1)
	type registration struct {
		wq    *waiter.Queue
		entry *waiter.Entry
	}
	var regs []registration

	for i := uint32(0); i < fds; i++ {
		pe := &pollEntries[i]
		fdSocket := uint64(pe.FD)
		events := pe.Events

		if st, ok := registry.Get(fdSocket); ok && st.WaiterQueue != nil {
			mask := waiter.EventErr | waiter.EventHUp
			if events&(POLLIN|POLLRDNORM) != 0 {
				mask |= waiter.EventIn
			}
			if events&(POLLOUT|POLLWRNORM) != 0 {
				mask |= waiter.EventOut
			}
			if mask != 0 {
				wEntry := &waiter.Entry{}
				wEntry.Init(ch, mask)
				st.WaiterQueue.EventRegister(wEntry)
				regs = append(regs, registration{wq: st.WaiterQueue, entry: wEntry})
			}
		}
	}

	unregister := func() {
		for _, reg := range regs {
			reg.wq.EventUnregister(reg.entry)
		}
	}
	defer unregister()

	// First pass: check if any are already ready
	readyCount := checkReadiness()
	if readyCount > 0 || (!infinite && waitTime == 0) {
		return readyCount
	}

	// Wait for event or timeout
	if infinite {
		<-ch
	} else {
		select {
		case <-ch:
		case <-time.After(waitTime):
		}
	}

	// Final pass: check readiness again
	return checkReadiness()
}

// goWSAAsyncSelect requests Windows message-based notification of network events for a socket.
// Not supported in non-Windows bridge — returns WSAEOPNOTSUPP.
func GoWSAAsyncSelect(s uint64, hWnd unsafe.Pointer, wMsg uint32, lEvent int32) int32 {
	LogCall("WSAAsyncSelect", s, hWnd, wMsg, lEvent)
	setLastError(WSAEOPNOTSUPP)
	return -1
}

// goWSAEventSelect associates network events with an event object.
func GoWSAEventSelect(s uint64, hEventObject unsafe.Pointer, lNetworkEvents int32) int32 {
	LogCall("WSAEventSelect", s, hEventObject, lNetworkEvents)

	st, ok := registry.Get(s)
	if !ok {
		setLastError(WSAENOTSOCK)
		return -1
	}

	handle := uintptr(hEventObject)

	// Verify the event handle exists
	if hEventObject != nil {
		if _, ok := registry.GetEvent(handle); !ok {
			setLastError(WSAEINVAL)
			return -1
		}
	}

	// Unregister existing waiter if any
	if st.WaiterEntry != nil && st.WaiterQueue != nil {
		st.WaiterQueue.EventUnregister(st.WaiterEntry)
		st.WaiterEntry = nil
	}

	st.EventHandle = handle
	st.NetworkEvents = lNetworkEvents

	// The socket is automatically set to non-blocking mode
	st.IsNonBlocking = true

	// If an event mask is set, register a waiter
	if lNetworkEvents != 0 && hEventObject != nil && st.WaiterQueue != nil {
		var mask waiter.EventMask
		if lNetworkEvents&(FD_READ|FD_ACCEPT) != 0 {
			mask |= waiter.EventIn
		}
		if lNetworkEvents&FD_WRITE != 0 {
			mask |= waiter.EventOut
		}
		if lNetworkEvents&FD_CLOSE != 0 {
			mask |= waiter.EventErr | waiter.EventHUp
		}

		if mask != 0 {
			st.WaiterEntry = &waiter.Entry{}
			st.WaiterEntry.Init(st, mask)
			st.WaiterQueue.EventRegister(st.WaiterEntry)

			// Trigger an initial notification to catch already-ready events
			if st.Endpoint != nil {
				readyMask := st.Endpoint.Readiness(mask)
				if readyMask != 0 {
					st.NotifyEvent(readyMask)
				}
			} else if st.Listener != nil {
				// Listeners are always ready for accept in our model
				st.NotifyEvent(waiter.EventIn)
			}
		}
	}

	return 0
}

// goWSAEnumNetworkEvents discovers occurrences of network events for the specified socket.
// Returns accumulated events and resets them. Optionally resets the event object.
func GoWSAEnumNetworkEvents(s uint64, hEventObject unsafe.Pointer, lpNetworkEvents unsafe.Pointer) int32 {
	LogCall("WSAEnumNetworkEvents", s, hEventObject, lpNetworkEvents)

	st, ok := registry.Get(s)
	if !ok {
		setLastError(WSAENOTSOCK)
		return -1
	}

	if lpNetworkEvents == nil {
		setLastError(WSAEFAULT)
		return -1
	}

	// WSANETWORKEVENTS struct: { lNetworkEvents int32; iErrorCode [FD_MAX_EVENTS]int32 }
	type wsaNetworkEvents struct {
		NetworkEvents int32
		ErrorCode     [FD_MAX_EVENTS]int32
	}

	result := (*wsaNetworkEvents)(lpNetworkEvents)

	// Atomically swap fired events to 0
	fired := atomic.SwapInt32(&st.FiredEvents, 0)
	result.NetworkEvents = fired

	// Clear error codes (no errors tracked currently)
	for i := range result.ErrorCode {
		result.ErrorCode[i] = 0
	}

	// Reset the event object if provided
	if hEventObject != nil {
		handle := uintptr(hEventObject)
		if c, ok := registry.GetEvent(handle); ok {
			select {
			case <-c:
			default:
			}
		}
	}

	return 0
}

// goProcessSocketNotifications — Windows completion port integration (not applicable).
func GoProcessSocketNotifications(completionPort unsafe.Pointer, registrationCount uint32, registrationInfos unsafe.Pointer, timeout uint32, completionCount uint32, completionInfos unsafe.Pointer, receivedCount *uint32) int32 {
	LogCall("ProcessSocketNotifications", completionPort, registrationCount, registrationInfos, timeout, completionCount, completionInfos, receivedCount)
	setLastError(WSAEOPNOTSUPP)
	return -1
}

// goSocketNotificationRetrieveEvents — Windows completion port integration (not applicable).
func GoSocketNotificationRetrieveEvents(notificationRegistration unsafe.Pointer, notificationEvents unsafe.Pointer) int32 {
	LogCall("SocketNotificationRetrieveEvents", notificationRegistration, notificationEvents)
	setLastError(WSAEOPNOTSUPP)
	return -1
}
