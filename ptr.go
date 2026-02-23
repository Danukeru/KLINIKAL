package main

/*
extern int __stdcall AcceptEx(unsigned int, unsigned int, void*, unsigned long, unsigned long, unsigned long, unsigned long*, void*);
extern int __stdcall ConnectEx(unsigned int, void*, int, void*, unsigned long, unsigned long*, void*);

static inline void* get_AcceptEx_ptr() {
    return (void*)AcceptEx;
}

static inline void* get_ConnectEx_ptr() {
    return (void*)ConnectEx;
}
*/
import "C"
import "klinikal/winsock"

func init() {
	winsock.AcceptExPtr = uintptr(C.get_AcceptEx_ptr())
	winsock.ConnectExPtr = uintptr(C.get_ConnectEx_ptr())
}
