// registry.go — Central socket and event registry. Defines SocketState (the per-
// socket record holding the Go net.Conn/Listener, socket type, address family,
// protocol, options map, non-blocking flag, peek buffer, and event-driven I/O
// state) and the socketRegistry singleton that maps uint64 handles to SocketState,
// manages event object channels, and tracks overlapped I/O completion results.
// Provides Register/Get/Unregister for sockets, RegisterEvent/GetEvent/UnregisterEvent
// for event objects, SetOverlappedResult/GetOverlappedResult for async I/O, and
// PurgeAll for cleanup.
package winsock

import (
	"net"
	"sync"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/waiter"
)

// SocketType defines the protocol type (TCP/UDP)
type SocketType int

const (
	TypeTCP SocketType = iota
	TypeUDP
	TypeRaw
)

// SocketState holds the runtime information for a Winsock handle.
type SocketState struct {
	Handle         uint64
	Conn           net.Conn
	Listener       net.Listener
	Type           SocketType
	AddressFamily  int32 // AF_INET=2, AF_INET6=23
	Protocol       int32 // IPPROTO_TCP=6, IPPROTO_UDP=17
	IsNonBlocking  bool
	LastErrorCode  int32
	BoundAddr      string // Added for bind/listen decoupling
	Options        map[int32][]byte // socket options storage (key = level<<16|optname)
	PeekBuf        []byte // buffered data from MSG_PEEK or readiness probes

	// Event-driven I/O (WSAEventSelect)
	EventHandle    uintptr // associated event object (0 = none)
	NetworkEvents  int32   // event mask from WSAEventSelect (FD_READ|FD_WRITE|...)
	FiredEvents    int32   // accumulated events that have occurred

	// True I/O Multiplexing
	WaiterQueue *waiter.Queue
	WaiterEntry *waiter.Entry
	Endpoint    tcpip.Endpoint
}

// NotifyEvent implements waiter.EventListener for SocketState.
func (st *SocketState) NotifyEvent(mask waiter.EventMask) {
	fired := int32(0)

	if mask&waiter.EventIn != 0 {
		if st.Listener != nil {
			fired |= FD_ACCEPT
		} else {
			fired |= FD_READ
		}
	}
	if mask&waiter.EventOut != 0 {
		fired |= FD_WRITE
	}
	if mask&waiter.EventErr != 0 || mask&waiter.EventHUp != 0 {
		fired |= FD_CLOSE
	}

	// Only accumulate events that the user requested
	fired &= st.NetworkEvents

	if fired != 0 {
		atomic.AddInt32(&st.FiredEvents, fired)

		// Signal the associated event object
		if st.EventHandle != 0 {
			if c, ok := registry.GetEvent(st.EventHandle); ok {
				select {
				case c <- struct{}{}:
				default:
				}
			}
		}
	}
}

// OptKey builds a unique key for a socket option from level and optname.
func OptKey(level, optname int32) int32 {
	return (level << 16) | (optname & 0xFFFF)
}

type socketRegistry struct {
	NextHandle uint64 // must be first field for 8-byte alignment on 386 (atomic access)
	sockets    map[uint64]*SocketState
	events     map[uintptr]chan struct{}
	overlapped map[uintptr]*OverlappedResult // overlapped ptr → completion result
	mu         sync.RWMutex
}

// OverlappedResult stores the completion state for an overlapped I/O operation.
type OverlappedResult struct {
	BytesTransferred uint32
	Error            int32
	Complete         bool
	Flags            uint32
}

var (
	registry = &socketRegistry{
		sockets:    make(map[uint64]*SocketState),
		events:     make(map[uintptr]chan struct{}),
		overlapped: make(map[uintptr]*OverlappedResult),
		NextHandle: 1000,
	}
)

// RegisterEvent creates a new event object and returns a handle.
func (r *socketRegistry) RegisterEvent() uintptr {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	handle := uintptr(atomic.AddUint64(&r.NextHandle, 1))
	r.events[handle] = make(chan struct{}, 1)
	return handle
}

// GetEvent retrieves a channel for an event handle.
func (r *socketRegistry) GetEvent(handle uintptr) (chan struct{}, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	c, ok := r.events[handle]
	return c, ok
}

// UnregisterEvent removes an event from the registry.
func (r *socketRegistry) UnregisterEvent(handle uintptr) {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	delete(r.events, handle)
}

// Register creates a new entry and returns a unique handle.
func (r *socketRegistry) Register(st *SocketState) uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()

	handle := atomic.AddUint64(&r.NextHandle, 1)
	st.Handle = handle
	r.sockets[handle] = st
	return handle
}

// Get retrieves a socket state by its handle.
func (r *socketRegistry) Get(handle uint64) (*SocketState, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	st, ok := r.sockets[handle]
	return st, ok
}

// Unregister removes a handle from the registry.
func (r *socketRegistry) Unregister(handle uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if st, ok := r.sockets[handle]; ok {
		if st.WaiterEntry != nil && st.WaiterQueue != nil {
			st.WaiterQueue.EventUnregister(st.WaiterEntry)
			st.WaiterEntry = nil
		}
		delete(r.sockets, handle)
	}
}

// PurgeAll closes all sockets and clears the registry.
func (r *socketRegistry) PurgeAll() {
	r.mu.Lock()
	defer r.mu.Unlock()

	for handle, st := range r.sockets {
		if st.WaiterEntry != nil && st.WaiterQueue != nil {
			st.WaiterQueue.EventUnregister(st.WaiterEntry)
			st.WaiterEntry = nil
		}
		if st.Conn != nil {
			st.Conn.Close()
		}
		if st.Listener != nil {
			st.Listener.Close()
		}
		delete(r.sockets, handle)
	}
}

// SetLastError updates the last error code for a socket handle.
func (r *socketRegistry) SetLastError(handle uint64, errCode int32) {
	if st, ok := r.Get(handle); ok {
		st.LastErrorCode = errCode
	}
}

// GetLastError retrieves the last error for a socket handle.
func (r *socketRegistry) GetLastError(handle uint64) int32 {
	if st, ok := r.Get(handle); ok {
		return st.LastErrorCode
	}
	return 0
}

// SetOverlappedResult stores an overlapped completion result.
func (r *socketRegistry) SetOverlappedResult(key uintptr, result *OverlappedResult) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.overlapped[key] = result
}

// GetOverlappedResult retrieves and removes an overlapped completion result.
func (r *socketRegistry) GetOverlappedResult(key uintptr) (*OverlappedResult, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	res, ok := r.overlapped[key]
	if ok {
		delete(r.overlapped, key)
	}
	return res, ok
}
