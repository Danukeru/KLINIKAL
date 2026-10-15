// exports.go — the C-facing export surface of the KLINIKAL Linux port.
//
// These are the cgo exports the LD_PRELOAD loader (linux_preload.c)
// calls. The surface is the POSIX socket API itself: fd-numbered
// operations, Linux errno error reporting, native fd_set/pollfd/addrinfo
// layouts, and Linux socket option/ioctl numbers. The loader does no
// protocol translation — it reserves fd numbers in the application's
// fd space, hands those numbers here, and passes struct pointers
// through unchanged.
package main

import "C"

import "unsafe"

import "klinikal-linux/linuxsock"

//export go_socket
func go_socket(fd C.int, domain C.int, typ C.int, protocol C.int) C.int {
	return C.int(linuxsock.Socket(int32(fd), int32(domain), int32(typ), int32(protocol)))
}
//export go_dup
func go_dup(oldfd C.int, newfd C.int) C.int {
	return C.int(linuxsock.Dup(int32(oldfd), int32(newfd)))
}
//export go_close
func go_close(fd C.int) C.int {
	return C.int(linuxsock.Close(int32(fd)))
}
//export go_connect
func go_connect(fd C.int, name unsafe.Pointer, namelen C.int) C.int {
	return C.int(linuxsock.Connect(int32(fd), name, int32(namelen)))
}
//export go_bind
func go_bind(fd C.int, name unsafe.Pointer, namelen C.int) C.int {
	return C.int(linuxsock.Bind(int32(fd), name, int32(namelen)))
}
//export go_listen
func go_listen(fd C.int, backlog C.int) C.int {
	return C.int(linuxsock.Listen(int32(fd), int32(backlog)))
}
//export go_accept
func go_accept(listenfd C.int, newfd C.int, addr unsafe.Pointer, addrlen *C.int) C.int {
	return C.int(linuxsock.Accept(int32(listenfd), int32(newfd), addr, (*int32)(unsafe.Pointer(addrlen))))
}
//export go_send
func go_send(fd C.int, buf unsafe.Pointer, len C.int, flags C.int) C.int {
	return C.int(linuxsock.Send(int32(fd), buf, int32(len), int32(flags)))
}
//export go_recv
func go_recv(fd C.int, buf unsafe.Pointer, len C.int, flags C.int) C.int {
	return C.int(linuxsock.Recv(int32(fd), buf, int32(len), int32(flags)))
}
//export go_sendto
func go_sendto(fd C.int, buf unsafe.Pointer, len C.int, flags C.int, to unsafe.Pointer, tolen C.int) C.int {
	return C.int(linuxsock.Sendto(int32(fd), buf, int32(len), int32(flags), to, int32(tolen)))
}
//export go_recvfrom
func go_recvfrom(fd C.int, buf unsafe.Pointer, len C.int, flags C.int, from unsafe.Pointer, fromlen *C.int) C.int {
	return C.int(linuxsock.Recvfrom(int32(fd), buf, int32(len), int32(flags), from, (*int32)(unsafe.Pointer(fromlen))))
}
//export go_setsockopt
func go_setsockopt(fd C.int, level C.int, optname C.int, optval unsafe.Pointer, optlen C.int) C.int {
	return C.int(linuxsock.Setsockopt(int32(fd), int32(level), int32(optname), optval, int32(optlen)))
}
//export go_getsockopt
func go_getsockopt(fd C.int, level C.int, optname C.int, optval unsafe.Pointer, optlen *C.int) C.int {
	return C.int(linuxsock.Getsockopt(int32(fd), int32(level), int32(optname), optval, (*int32)(unsafe.Pointer(optlen))))
}
//export go_ioctl
func go_ioctl(fd C.int, request C.ulong, argp *C.uint) C.int {
	return C.int(linuxsock.Ioctl(int32(fd), uint64(request), (*uint32)(unsafe.Pointer(argp))))
}
//export go_select
func go_select(nfds C.int, readfds unsafe.Pointer, writefds unsafe.Pointer, exceptfds unsafe.Pointer, timeout unsafe.Pointer) C.int {
	return C.int(linuxsock.Select(int32(nfds), readfds, writefds, exceptfds, timeout))
}
//export go_poll
func go_poll(fdArray unsafe.Pointer, nfds C.int, timeout C.int) C.int {
	return C.int(linuxsock.Poll(fdArray, int32(nfds), int32(timeout)))
}
//export go_getaddrinfo
func go_getaddrinfo(node *C.char, service *C.char, hints unsafe.Pointer, res *unsafe.Pointer) C.int {
	return C.int(linuxsock.Getaddrinfo((*byte)(unsafe.Pointer(node)), (*byte)(unsafe.Pointer(service)), hints, res))
}
//export go_freeaddrinfo
func go_freeaddrinfo(ai unsafe.Pointer) {
	linuxsock.Freeaddrinfo(ai)
}
//export go_addrinfo_owned
func go_addrinfo_owned(ai unsafe.Pointer) C.int {
	if linuxsock.AddrinfoOwned(ai) {
		return 1
	}
	return 0
}
//export go_getpeername
func go_getpeername(fd C.int, name unsafe.Pointer, namelen *C.int) C.int {
	return C.int(linuxsock.Getpeername(int32(fd), name, (*int32)(unsafe.Pointer(namelen))))
}
//export go_getsockname
func go_getsockname(fd C.int, name unsafe.Pointer, namelen *C.int) C.int {
	return C.int(linuxsock.Getsockname(int32(fd), name, (*int32)(unsafe.Pointer(namelen))))
}
//export go_shutdown
func go_shutdown(fd C.int, how C.int) C.int {
	return C.int(linuxsock.Shutdown(int32(fd), int32(how)))
}
//export go_start_notify
func go_start_notify(fd C.int) C.int {
	return C.int(linuxsock.StartNotify(int32(fd)))
}
