package winsock

import "unsafe"

// Legacy Winsock 1.1 async functions — all return error (0 = failure for handles, -1 for SOCKET_ERROR)

func GoWSAAsyncGetHostByAddr(hWnd unsafe.Pointer, wMsg uint32, addr *byte, addrLen int32, addrType int32, buf unsafe.Pointer, bufLen int32) uintptr {
	LogCall("WSAAsyncGetHostByAddr", hWnd, wMsg, addr, addrLen, addrType, buf, bufLen)
	setLastError(WSAEOPNOTSUPP)
	return 0
}

func GoWSAAsyncGetHostByName(hWnd unsafe.Pointer, wMsg uint32, name *byte, buf unsafe.Pointer, bufLen int32) uintptr {
	LogCall("WSAAsyncGetHostByName", hWnd, wMsg, name, buf, bufLen)
	setLastError(WSAEOPNOTSUPP)
	return 0
}

func GoWSAAsyncGetServByPort(hWnd unsafe.Pointer, wMsg uint32, port int32, proto *byte, buf unsafe.Pointer, bufLen int32) uintptr {
	LogCall("WSAAsyncGetServByPort", hWnd, wMsg, port, proto, buf, bufLen)
	setLastError(WSAEOPNOTSUPP)
	return 0
}

func GoWSAAsyncGetProtoByName(hWnd unsafe.Pointer, wMsg uint32, name *byte, buf unsafe.Pointer, bufLen int32) uintptr {
	LogCall("WSAAsyncGetProtoByName", hWnd, wMsg, name, buf, bufLen)
	setLastError(WSAEOPNOTSUPP)
	return 0
}

func GoWSAAsyncGetProtoByNumber(hWnd unsafe.Pointer, wMsg uint32, number int32, buf unsafe.Pointer, bufLen int32) uintptr {
	LogCall("WSAAsyncGetProtoByNumber", hWnd, wMsg, number, buf, bufLen)
	setLastError(WSAEOPNOTSUPP)
	return 0
}

func GoWSAAsyncGetServByName(hWnd unsafe.Pointer, wMsg uint32, name *byte, proto *byte, buf unsafe.Pointer, bufLen int32) uintptr {
	LogCall("WSAAsyncGetServByName", hWnd, wMsg, name, proto, buf, bufLen)
	setLastError(WSAEOPNOTSUPP)
	return 0
}

func GoWSACancelAsyncRequest(hAsyncTaskHandle uintptr) int32 {
	LogCall("WSACancelAsyncRequest", hAsyncTaskHandle)
	setLastError(WSAEOPNOTSUPP)
	return -1
}

func GoWSASetBlockingHook(lpBlockFunc unsafe.Pointer) unsafe.Pointer {
	LogCall("WSASetBlockingHook", lpBlockFunc)
	return nil
}

func GoWSAUnhookBlockingHook() int32 {
	LogCall("WSAUnhookBlockingHook")
	return 0
}

func GoWSACancelBlockingCall() int32 {
	LogCall("WSACancelBlockingCall")
	setLastError(WSAEOPNOTSUPP)
	return -1
}

func GoWSAIsBlocking() int32 {
	LogCall("WSAIsBlocking")
	return 0 // Not blocking
}
