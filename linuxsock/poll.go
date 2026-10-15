// I/O multiplexing: select (iterates fd_set bitmaps, probes read/write
// readiness, modifies sets on return) and poll (iterates struct pollfd,
// sets revents). Both use the gVisor waiter queues for event-driven waits
// rather than polling loops.
package linuxsock

import (
	"net"
	"time"
	"unsafe"

	"gvisor.dev/gvisor/pkg/waiter"
)

// Linux struct timeval (as passed by select/pselect)
type timeval struct {
	Sec  int64
	Usec int64
}

// fdSetBits is the glibc fd_set: FD_SETSIZE/64 = 16 uint64 words.
const fdSetWords = 16

// Bit helpers over the glibc fd_set bitmap (fd < 1024 guaranteed by
// the loader's fd allocation policy).
func fdIsSet(bits *[fdSetWords]uint64, fd uint32) bool {
	w := bits[fd>>6]
	return w&(uint64(1)<<(fd&63)) != 0
}

func fdClr(bits *[fdSetWords]uint64, fd uint32) {
	bits[fd>>6] &^= uint64(1) << (fd & 63)
}

func fdSetBit(bits *[fdSetWords]uint64, fd uint32) {
	bits[fd>>6] |= uint64(1) << (fd & 63)
}

// Linux struct pollfd and event bits
type pollFD struct {
	FD      int32
	Events  int16
	Revents int16
}

const (
	POLLIN    = 0x0001
	POLLPRI   = 0x0002
	POLLOUT   = 0x0004
	POLLERR   = 0x0008
	POLLHUP   = 0x0010
	POLLNVAL  = 0x0020
)

// channelNotifier turns gVisor waiter events into a non-blocking send
// on itself: a buffered channel used as a readiness signal (the select
// with default drops repeats — level state is recomputed after wake).
type channelNotifier chan struct{}

// NotifyEvent never blocks: it signals once and drops repeats; the
// waiter recomputes actual readiness after waking.
func (c channelNotifier) NotifyEvent(mask waiter.EventMask) {
	select {
	case c <- struct{}{}:
	default:
	}
}

// checkReadReady probes whether a socket has data available for reading.
func checkReadReady(st *SocketState) bool {
	if st.DialDone != nil {
		select {
		case <-st.DialDone:
		default:
			return false // connect in progress
		}
	}
	if st.Endpoint != nil {
		mask := st.Endpoint.Readiness(waiter.EventIn | waiter.EventErr | waiter.EventHUp)
		return mask&(waiter.EventIn|waiter.EventErr|waiter.EventHUp) != 0
	}
	if st.Listener != nil {
		return true
	}
	if st.Conn != nil {
		return st.probeReadReady()
	}
	return false
}

// probeReadReady probes a net.Conn-backed socket for readability, parking
// any probed byte in the peek buffer so Recv serves it next. Serialized
// with send/recv on the same socket via st.mu.
func (st *SocketState) probeReadReady() bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	if builtins_len(st.PeekBuf) > 0 {
		return true
	}
	// gVisor errors on an expired deadline even when data is queued,
	// so the probe uses a short grace window: data present completes
	// at once, no data costs one 50ms wait before reporting not-ready.
	st.Conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	probe := make([]byte, 1)
	n, err := st.Conn.Read(probe)
	st.Conn.SetReadDeadline(time.Time{})
	if n > 0 {
		st.PeekBuf = append(st.PeekBuf, probe[:n]...)
		return true
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return false
	}
	return true // EOF or error: recv should proceed and report it
}

// checkWriteReady checks if a socket can accept data for writing.
func checkWriteReady(st *SocketState) bool {
	if st.DialDone != nil {
		// connect in progress: writable only once it completes (success
		// or failure); SO_ERROR carries the result.
		select {
		case <-st.DialDone:
			return true
		default:
			return false
		}
	}
	if st.Endpoint != nil {
		mask := st.Endpoint.Readiness(waiter.EventOut | waiter.EventErr | waiter.EventHUp)
		return mask&(waiter.EventOut|waiter.EventErr|waiter.EventHUp) != 0
	}
	if st.Conn == nil {
		return false
	}
	return true
}

// isTimeout reports gVisor/netstack deadline errors (used to tell
// EAGAIN from a real failure on probe reads).
func isTimeout(err error) bool {
	type timeouter interface{ Timeout() bool }
	if te, ok := err.(timeouter); ok {
		return te.Timeout()
	}
	return false
}

// Select waits for readability/writability on the registered fds named by the
// glibc fd_set bitmaps, clearing bits for fds that are not ready.
func Select(nfds int32, readfds unsafe.Pointer, writefds unsafe.Pointer, exceptfds unsafe.Pointer, timeout unsafe.Pointer) int32 {
	LogCall("Select", nfds, readfds, writefds, exceptfds, timeout)

	var waitTime time.Duration
	infinite := false
	if timeout != nil {
		tv := (*timeval)(timeout)
		waitTime = time.Duration(tv.Sec)*time.Second + time.Duration(tv.Usec)*time.Microsecond
	} else {
		infinite = true
	}

	var rBits, wBits, eBits *[fdSetWords]uint64
	if readfds != nil {
		rBits = (*[fdSetWords]uint64)(readfds)
	}
	if writefds != nil {
		wBits = (*[fdSetWords]uint64)(writefds)
	}
	if exceptfds != nil {
		eBits = (*[fdSetWords]uint64)(exceptfds)
	}
	// OOB data is not modeled: clear exceptfds.
	if eBits != nil {
		for i := 0; i < fdSetWords; i++ {
			eBits[i] = 0
		}
	}

	type target struct {
		st    *SocketState
		inR   bool
		inW   bool
	}
	var targets []*target
	for _, st := range registry.Sockets() {
		fd := uint32(st.Handle)
		if int32(fd) >= nfds {
			continue
		}
		inR := rBits != nil && fdIsSet(rBits, fd)
		inW := wBits != nil && fdIsSet(wBits, fd)
		if inR || inW {
			targets = append(targets, &target{st: st, inR: inR, inW: inW})
		}
	}

	// Helper to check readiness; clears unready bits and reports ready count.
	checkReadiness := func() int32 {
		readyCount := int32(0)
		for _, t := range targets {
			fd := uint32(t.st.Handle)
			rReady := t.inR && checkReadReady(t.st)
			wReady := t.inW && checkWriteReady(t.st)
			if rReady {
				readyCount++
				if t.inR {
					fdSetBit(rBits, fd) // may have been cleared on an earlier pass
				}
			} else if t.inR {
				fdClr(rBits, fd)
			}
			if wReady {
				readyCount++
				if t.inW {
					fdSetBit(wBits, fd)
				}
			} else if t.inW {
				fdClr(wBits, fd)
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
	for _, t := range targets {
		st := t.st
		if st.WaiterQueue == nil {
			continue
		}
		mask := waiter.EventErr | waiter.EventHUp
		if t.inR {
			mask |= waiter.EventIn
		}
		if t.inW {
			mask |= waiter.EventOut
		}
		entry := &waiter.Entry{}
		entry.Init(ch, mask)
		st.WaiterQueue.EventRegister(entry)
		regs = append(regs, registration{wq: st.WaiterQueue, entry: entry})
	}
	defer func() {
		for _, reg := range regs {
			reg.wq.EventUnregister(reg.entry)
		}
	}()

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

// Poll determines the status of one or more sockets (Linux poll).
func Poll(fdArray unsafe.Pointer, nfds int32, timeout int32) int32 {
	LogCall("Poll", fdArray, nfds, timeout)
	if fdArray == nil || nfds <= 0 {
		setLastError(EINVAL)
		return -1
	}

	infinite := timeout < 0
	var waitTime time.Duration
	if !infinite {
		waitTime = time.Duration(timeout) * time.Millisecond
	}

	pollEntries := unsafe.Slice((*pollFD)(fdArray), int(nfds))

	checkReadiness := func() int32 {
		readyCount := int32(0)

		for i := int32(0); i < nfds; i++ {
			entry := &pollEntries[i]
			fdSocket := uint64(uint32(entry.FD))
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
				if events&POLLIN != 0 && mask&waiter.EventIn != 0 {
					entry.Revents |= POLLIN
				}
				if events&POLLOUT != 0 && mask&waiter.EventOut != 0 {
					entry.Revents |= POLLOUT
				}
			} else {
				if events&POLLIN != 0 {
					if checkReadReady(st) {
						entry.Revents |= POLLIN
					}
				}
				if events&POLLOUT != 0 {
					if checkWriteReady(st) {
						entry.Revents |= POLLOUT
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

	for i := int32(0); i < nfds; i++ {
		pe := &pollEntries[i]
		fdSocket := uint64(uint32(pe.FD))
		events := pe.Events

		if st, ok := registry.Get(fdSocket); ok && st.WaiterQueue != nil {
			mask := waiter.EventErr | waiter.EventHUp
			if events&POLLIN != 0 {
				mask |= waiter.EventIn
			}
			if events&POLLOUT != 0 {
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





