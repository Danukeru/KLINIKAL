// notify.go — eventfd bridge for the Linux LD_PRELOAD shim.
//
// The C interposer cannot wait on Go channels or gvisor waiter entries, so
// when it registers a tunnel fd in a real epoll we create an eventfd,
// register the socket's existing waiter listener (SocketState.NotifyEvent)
// on the gvisor waiter queue, and signal the eventfd from NotifyEvent.
// The kernel epoll then blocks on the eventfd and wakes exactly on state
// changes — no polling slices.

package linuxsock

/*
#include <sys/eventfd.h>
#include <unistd.h>
*/
import "C"

import "fmt"
import "os"
import "unsafe"

import "gvisor.dev/gvisor/pkg/waiter"

// StartNotify attaches an eventfd to a socket's readiness notifications.
// Returns the eventfd number (to be added to a real epoll by the C shim),
// or -1 if the socket has no waiter queue yet (e.g. connect in progress —
// the shim retries after connect completes).
func StartNotify(fd int32) int32 {
	st, ok := registry.Get(uint64(fd))
	if !ok {
		return -1
	}
	if st.NotifyFd > 0 {
		return st.NotifyFd
	}
	if st.WaiterQueue == nil {
		return -1
	}
	efd := C.eventfd(C.uint(0), C.EFD_NONBLOCK|C.EFD_CLOEXEC)
	if efd < 0 {
		return -1
	}
	if os.Getenv("KLINIKAL_VERBOSE") != "" {
		fmt.Fprintf(os.Stderr, "kl: StartNotify sock=%d queue=%p eventfd=%d\n", fd, st.WaiterQueue, efd)
	}
	st.mu.Lock()
	st.NotifyFd = int32(efd)
	if st.NotifyEntry == nil {
		mask := waiter.EventIn | waiter.EventOut | waiter.EventErr | waiter.EventHUp
		e := &waiter.Entry{}
		e.Init(st, mask)
		st.WaiterQueue.EventRegister(e)
		st.NotifyEntry = e
		if os.Getenv("KLINIKAL_VERBOSE") != "" {
			fmt.Fprintf(os.Stderr, "kl: registered mask=%d queue_events=%d\n",
				mask, st.WaiterQueue.Events())
		}
	}
	st.mu.Unlock()
	signalNotify(st) // report already-current state immediately
	return int32(efd)
}

// signalNotify bumps the eventfd counter (non-blocking write).
func signalNotify(st *SocketState) {
	if st.NotifyFd <= 0 {
		if os.Getenv("KLINIKAL_VERBOSE") != "" {
			fmt.Fprintf(os.Stderr, "kl: signalNotify skipped (NotifyFd=%d)\n", st.NotifyFd)
		}
		return
	}
	buf := [8]byte{1, 0, 0, 0, 0, 0, 0, 0}
	n := C.write(C.int(st.NotifyFd), unsafe.Pointer(&buf[0]), C.size_t(8))
	if os.Getenv("KLINIKAL_VERBOSE") != "" {
		fmt.Fprintf(os.Stderr, "kl: signalNotify fd=%d wrote=%d\n", st.NotifyFd, n)
	}
}

// stopNotify tears the bridge down (called when the last fd alias closes).
func stopNotify(st *SocketState) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.NotifyEntry != nil && st.WaiterQueue != nil {
		st.WaiterQueue.EventUnregister(st.NotifyEntry)
	}
	st.NotifyEntry = nil
	if st.NotifyFd > 0 {
		if os.Getenv("KLINIKAL_VERBOSE") != "" {
			fmt.Fprintf(os.Stderr, "kl: closing eventfd=%d\n", st.NotifyFd)
		}
		C.close(C.int(st.NotifyFd))
		st.NotifyFd = 0
	}
}
