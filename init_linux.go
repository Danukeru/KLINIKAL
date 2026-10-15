// init_linux.go — entry point for the LD_PRELOAD build: the loader
// constructor calls klinikal_init with an explicit wg.conf path, which
// brings up the WireGuard client and the embedded netstack.
package main

/*
#include <stdlib.h>
*/
import "C"

import "klinikal-linux/linuxsock"

//export klinikal_init
func klinikal_init(path *C.char) C.int {
	p := C.GoString(path)
	if p == "" {
		p = "wg.conf"
	}
	if err := linuxsock.InitStack(p); err != nil {
		return C.int(-1)
	}
	return 0
}

//export klinikal_last_error
func klinikal_last_error() C.int {
	return C.int(linuxsock.GetLastError())
}
