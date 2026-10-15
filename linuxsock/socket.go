// socket.go — Socket creation, duplication, and destruction. socket() creates a
// SocketState under an fd number chosen by the loader; dup() installs a second
// fd referring to the same underlying socket (shared refcount); close()
// unregisters an fd and closes the underlying socket only when the last
// referring fd is gone.
package linuxsock

import "sync"

// Socket creates a socket and registers it under the fd number the loader has
// already reserved in the application's fd space.
func Socket(fd int32, domain int32, typ int32, protocol int32) int32 {
	LogCall("Socket", fd, domain, typ, protocol)
	st := &SocketState{
		Type:          TypeTCP,
		AddressFamily: domain,
		Protocol:      protocol,
		Options:       make(map[int32][]byte),
		Refs:          &refcount{n: 1},
		mu:            &sync.Mutex{},
	}
	if typ == 2 { // SOCK_DGRAM
		st.Type = TypeUDP
	} else if typ == 3 { // SOCK_RAW
		st.Type = TypeRaw
	}
	if !registry.Register(uint64(fd), st) {
		setLastError(EBADF)
		return -1
	}
	return 0
}

// Dup registers newfd as an alias of oldfd (dup/dup2/F_DUPFD semantics).
func Dup(oldfd, newfd int32) int32 {
	LogCall("Dup", oldfd, newfd)
	st, ok := registry.Get(uint64(oldfd))
	if !ok {
		setLastError(EBADF)
		return -1
	}
alias := *st // shallow copy: shares Conn/Listener/Options/Refs/mu
	alias.Handle = uint64(newfd)
	alias.Refs = st.Refs
	st.Refs.inc()
	if !registry.Register(uint64(newfd), &alias) {
		setLastError(EBADF)
		return -1
	}
	st.Refs.n++
	return 0
}

// Close unregisters an fd; the underlying socket closes with the last alias.
func Close(fd int32) int32 {
	LogCall("Close", fd)
	if !registry.Exists(uint64(fd)) {
		setLastError(ENOTSOCK)
		return -1
	}
	registry.Unregister(uint64(fd))
	return 0
}
