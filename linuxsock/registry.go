// registry.go — Central socket registry. Defines SocketState (the per-socket
// record holding the netstack Conn/Listener, address family, protocol, options
// map, non-blocking flag, peek buffer, async-connect state, eventfd bridge, and
// a shared refcount for dup'd descriptors) and the socketRegistry singleton that
// maps file descriptors to SocketState. The registry key IS the application's
// fd number: the C loader allocates the fd, then registers it here, so the Go
// side speaks the same fd namespace as the kernel.
package linuxsock

import (
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/waiter"
)

// SocketType defines the protocol type (TCP/UDP)
type SocketType int

// Socket kinds the stack serves; Raw is ICMP echo (ping) sockets.
const (
	TypeTCP SocketType = iota
	TypeUDP
	TypeRaw
)

// refcount tracks how many fds refer to one underlying socket (dup/dup2).
type refcount struct {
	n int32
}

// inc/dec are lock-free; dec returns the post-decrement count so the
// caller can tell when the last alias closed.
func (r *refcount) inc() { atomic.AddInt32(&r.n, 1) }
func (r *refcount) dec() int32 { return atomic.AddInt32(&r.n, -1) }

// SocketState holds the runtime information for one socket.
type SocketState struct {
	Handle         uint64 // == the application fd number
	Conn           net.Conn
	Listener       net.Listener
	Type           SocketType
	AddressFamily  int32 // AF_INET=2, AF_INET6=10 (Linux values)
	Protocol       int32 // IPPROTO_TCP=6, IPPROTO_UDP=17
	IsNonBlocking  bool
	LastErrorCode  int32 // errno recorded for SO_ERROR
	BoundAddr      string // for bind/listen decoupling
	Options        map[int32][]byte // socket options storage (key = level<<16|optname)
	PeekBuf        []byte // buffered data from MSG_PEEK or readiness probes
	Refs           *refcount

	// gVisor waiter plumbing for select/poll
	WaiterQueue *waiter.Queue
	WaiterEntry *waiter.Entry
	Endpoint    tcpip.Endpoint

	// Pending non-blocking connect (EINPROGRESS semantics)
	DialDone chan struct{} // closed when the async dial finishes
	DialErr  error         // result of the async dial
	// Set once the app closed the fd (last alias): an in-flight async
	// dial must discard (not adopt) the connection it produces.
	// Pointer so dup aliases share it and struct copies stay legal.
	Closed *atomic.Bool

	// SO_RCVTIMEO / SO_SNDTIMEO (applied per I/O call, like Linux)
	RcvTimeout time.Duration
	SndTimeout time.Duration

	// eventfd bridge (Linux loader epoll) + lock for mutable I/O state
	// (pointer so dup aliases share one lock)
	mu          *sync.Mutex
	NotifyFd    int32
	NotifyEntry *waiter.Entry
}

// NotifyEvent implements waiter.EventListener for SocketState: any readiness
// change signals the eventfd bridge (if one is registered).
func (st *SocketState) NotifyEvent(mask waiter.EventMask) {
	if os.Getenv("KLINIKAL_VERBOSE") != "" {
		fmt.Fprintf(os.Stderr, "kl: NotifyEvent t=%s mask=%d\n",
			time.Now().Format("15:04:05.000"), mask)
	}
	signalNotify(st)
}

// OptKey builds a unique key for a socket option from level and optname.
func OptKey(level, optname int32) int32 {
	return (level << 16) | (optname & 0xFFFF)
}

// socketRegistry maps fd numbers (allocated by the C loader, below
// FD_SETSIZE) to socket state. The fd number IS the identity: there is
// no handle space.
type socketRegistry struct {
	sockets map[uint64]*SocketState
	mu      sync.RWMutex
}

// The one registry; the loader guarantees fd uniqueness so lookups are
// keyed by the app-visible fd number.
var (
	registry = &socketRegistry{
		sockets: make(map[uint64]*SocketState),
	}
)

// Register inserts a socket state under an explicit fd number chosen by the
// loader. Returns false if the number is already taken.
func (r *socketRegistry) Register(fd uint64, st *SocketState) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.sockets[fd]; dup {
		return false
	}
	if st.Closed == nil {
		st.Closed = &atomic.Bool{} // every construction path gets one
	}
	st.Handle = fd
	r.sockets[fd] = st
	return true
}

// Get retrieves a socket state by its fd.
func (r *socketRegistry) Get(fd uint64) (*SocketState, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	st, ok := r.sockets[fd]
	return st, ok
}

// Exists reports whether an fd is registered.
func (r *socketRegistry) Exists(fd uint64) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.sockets[fd]
	return ok
}

// Unregister removes an fd from the registry. The underlying socket is closed
// only when the last referring fd is gone (dup semantics).
func (r *socketRegistry) Unregister(fd uint64) {
	r.mu.Lock()
	st, ok := r.sockets[fd]
	if ok {
		if st.WaiterEntry != nil && st.WaiterQueue != nil {
			st.WaiterQueue.EventUnregister(st.WaiterEntry)
			st.WaiterEntry = nil
		}
		delete(r.sockets, fd)
	}
	r.mu.Unlock()
	if !ok {
		return
	}
	if st.Refs != nil && st.Refs.dec() > 0 {
		return // other fds still refer to this socket
	}
	// last alias gone: an in-flight async dial must discard its result
	st.Closed.Store(true)
	stopNotify(st)
	if st.Conn != nil {
		st.Conn.Close()
	}
	if st.Listener != nil {
		st.Listener.Close()
	}
}

// Sockets returns a snapshot of all registered socket states (for select/poll
// iteration over fd bitmaps).
func (r *socketRegistry) Sockets() []*SocketState {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*SocketState, 0, len(r.sockets))
	for _, st := range r.sockets {
		out = append(out, st)
	}
	return out
}

// SetLastError records the last operation error for a socket (SO_ERROR).
func (r *socketRegistry) SetLastError(fd uint64, errCode int32) {
	if st, ok := r.Get(fd); ok {
		st.LastErrorCode = errCode
	}
}

// PurgeAll closes all sockets and clears the registry.
func (r *socketRegistry) PurgeAll() {
	r.mu.Lock()
	states := make([]*SocketState, 0, len(r.sockets))
	for fd, st := range r.sockets {
		if st.WaiterEntry != nil && st.WaiterQueue != nil {
			st.WaiterQueue.EventUnregister(st.WaiterEntry)
			st.WaiterEntry = nil
		}
		states = append(states, st)
		delete(r.sockets, fd)
	}
	r.mu.Unlock()
	for _, st := range states {
		if st.Conn != nil {
			st.Conn.Close()
		}
		if st.Listener != nil {
			st.Listener.Close()
		}
	}
}
