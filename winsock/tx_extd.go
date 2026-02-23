// tx_extd.go — Extended data transfer APIs. Implements WSASend and WSARecv with
// multi-buffer (scatter/gather) support and true async overlapped dispatch (when
// lpOverlapped is non-nil, I/O runs in a goroutine that stores the result in the
// overlapped tracking map and signals hEvent). Implements WSASendTo and WSARecvFrom
// (single-buffer delegation to sendto/recvfrom). Implements WSASendMsg and
// WSARecvMsg (parse WSAMSG struct, route to sendto/recvfrom or WSASend/WSARecv;
// ancillary data is not supported). Implements WSASendDisconnect and
// WSARecvDisconnect (map to shutdown SD_SEND/SD_RECEIVE).
package winsock

import (
	"unsafe"
)

type wsaBuf struct {
	Len uint32
	Buf *byte
}

type wsaOverlapped struct {
	Internal     uintptr
	InternalHigh uintptr
	Offset       uint32
	OffsetHigh   uint32
	HEvent       unsafe.Pointer
}

// WSAMSG layout for WSASendMsg / WSARecvMsg
type wsaMsg struct {
	Name      unsafe.Pointer // LPSOCKADDR
	Namelen   int32
	Buffers   *wsaBuf // LPWSABUF
	BufferCnt uint32
	Control   wsaBuf // WSABUF for control/ancillary data
	Flags     uint32
}

// gatherBuffers concatenates all WSABUF entries into a single byte slice.
func gatherBuffers(lpBuffers unsafe.Pointer, count uint32) []byte {
	bufs := unsafe.Slice((*wsaBuf)(lpBuffers), int(count))
	total := 0
	for i := range bufs {
		total += int(bufs[i].Len)
	}
	out := make([]byte, 0, total)
	for i := range bufs {
		out = append(out, unsafe.Slice(bufs[i].Buf, int(bufs[i].Len))...)
	}
	return out
}

// scatterBuffers copies data into multiple WSABUF entries. Returns bytes copied.
func scatterBuffers(lpBuffers unsafe.Pointer, count uint32, data []byte) uint32 {
	bufs := unsafe.Slice((*wsaBuf)(lpBuffers), int(count))
	off := 0
	for i := range bufs {
		n := copy(unsafe.Slice(bufs[i].Buf, int(bufs[i].Len)), data[off:])
		off += n
		if off >= len(data) {
			break
		}
	}
	return uint32(off)
}

// GoWSASend sends data on a connected socket, supports multi-buffer and overlapped.
func GoWSASend(s uint64, lpBuffers unsafe.Pointer, dwBufferCount uint32, lpNumberOfBytesSent *uint32, dwFlags uint32, lpOverlapped unsafe.Pointer, lpCompletionRoutine unsafe.Pointer) int32 {
	LogCall("WSASend", s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine)

	st, ok := registry.Get(s)
	if !ok || st.Conn == nil {
		setLastError(WSAENOTSOCK)
		return -1
	}

	if dwBufferCount == 0 || lpBuffers == nil {
		setLastError(WSAEINVAL)
		return -1
	}

	// Async overlapped dispatch
	if lpOverlapped != nil {
		ov := (*wsaOverlapped)(lpOverlapped)
		ovKey := uintptr(lpOverlapped)
		registry.SetOverlappedResult(ovKey, &OverlappedResult{Complete: false})

		// CRITICAL: Gather buffer data BEFORE launching goroutine.
		// The caller may free lpBuffers after we return WSA_IO_PENDING.
		data := gatherBuffers(lpBuffers, dwBufferCount)

		go func() {
			n, err := st.Conn.Write(data)

			result := &OverlappedResult{
				BytesTransferred: uint32(n),
				Complete:         true,
			}
			if err != nil {
				result.Error = mapError(err)
			}
			registry.SetOverlappedResult(ovKey, result)

			if ov.HEvent != nil {
				GoWSASetEvent(ov.HEvent)
			}
		}()

		setLastError(WSA_IO_PENDING)
		return -1 // SOCKET_ERROR with WSA_IO_PENDING
	}

	// Synchronous: gather all buffers and write
	data := gatherBuffers(lpBuffers, dwBufferCount)
	n, err := st.Conn.Write(data)
	if err != nil {
		setLastError(mapError(err))
		return -1
	}
	if lpNumberOfBytesSent != nil {
		*lpNumberOfBytesSent = uint32(n)
	}
	return 0
}

// GoWSARecv receives data from a connected socket, supports multi-buffer and overlapped.
func GoWSARecv(s uint64, lpBuffers unsafe.Pointer, dwBufferCount uint32, lpNumberOfBytesRecvd *uint32, lpFlags *uint32, lpOverlapped unsafe.Pointer, lpCompletionRoutine unsafe.Pointer) int32 {
	LogCall("WSARecv", s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped, lpCompletionRoutine)

	st, ok := registry.Get(s)
	if !ok || st.Conn == nil {
		setLastError(WSAENOTSOCK)
		return -1
	}

	if dwBufferCount == 0 || lpBuffers == nil {
		setLastError(WSAEINVAL)
		return -1
	}

	// Calculate total buffer capacity
	bufs := unsafe.Slice((*wsaBuf)(lpBuffers), int(dwBufferCount))
	totalCap := 0
	for i := range bufs {
		totalCap += int(bufs[i].Len)
	}

	// Async overlapped dispatch
	if lpOverlapped != nil {
		ov := (*wsaOverlapped)(lpOverlapped)
		ovKey := uintptr(lpOverlapped)
		registry.SetOverlappedResult(ovKey, &OverlappedResult{Complete: false})

		// Snapshot buffer descriptors before launching goroutine.
		// Per Winsock spec, caller MUST keep buffers valid until overlapped completes.
		bufsCopy := make([]wsaBuf, dwBufferCount)
		copy(bufsCopy, unsafe.Slice((*wsaBuf)(lpBuffers), int(dwBufferCount)))
		scatterTarget := unsafe.Pointer(&bufsCopy[0])

		go func() {
			tmp := make([]byte, totalCap)
			n, err := st.Conn.Read(tmp)

			result := &OverlappedResult{
				BytesTransferred: uint32(n),
				Complete:         true,
			}
			if err != nil {
				result.Error = mapError(err)
			}
			if n > 0 {
				scatterBuffers(scatterTarget, dwBufferCount, tmp[:n])
			}
			registry.SetOverlappedResult(ovKey, result)

			if ov.HEvent != nil {
				GoWSASetEvent(ov.HEvent)
			}
		}()

		setLastError(WSA_IO_PENDING)
		return -1
	}

	// Synchronous: read into temporary buffer, then scatter
	tmp := make([]byte, totalCap)
	n, err := st.Conn.Read(tmp)
	if err != nil && n == 0 {
		setLastError(mapError(err))
		return -1
	}
	if n > 0 {
		scatterBuffers(lpBuffers, dwBufferCount, tmp[:n])
	}
	if lpNumberOfBytesRecvd != nil {
		*lpNumberOfBytesRecvd = uint32(n)
	}
	return 0
}

// GoWSASendTo sends data to a specific destination (overlapped).
func GoWSASendTo(s uint64, lpBuffers unsafe.Pointer, dwBufferCount uint32, lpNumberOfBytesSent *uint32, dwFlags uint32, lpTo unsafe.Pointer, iTolen int32, lpOverlapped unsafe.Pointer, lpCompletionRoutine unsafe.Pointer) int32 {
	LogCall("WSASendTo", s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpTo, iTolen, lpOverlapped, lpCompletionRoutine)

	if dwBufferCount == 0 || lpBuffers == nil {
		setLastError(WSAEINVAL)
		return -1
	}

	if lpOverlapped != nil {
		LogCall("WARNING: WSASendTo overlapped I/O not implemented, running synchronously")
	}

	// Gather all buffers into a single byte slice
	data := gatherBuffers(lpBuffers, dwBufferCount)

	// Simplified: delegate via a temporary single WSABUF
	tmpBuf := wsaBuf{Len: uint32(len(data)), Buf: &data[0]}
	n := GoSendto(s, unsafe.Pointer(tmpBuf.Buf), int32(tmpBuf.Len), int32(dwFlags), lpTo, iTolen)
	if n != -1 {
		if lpNumberOfBytesSent != nil {
			*lpNumberOfBytesSent = uint32(n)
		}
		return 0
	}
	return -1
}

// GoWSARecvFrom receives a datagram and stores the source address (overlapped).
func GoWSARecvFrom(s uint64, lpBuffers unsafe.Pointer, dwBufferCount uint32, lpNumberOfBytesRecvd *uint32, lpFlags *uint32, lpFrom unsafe.Pointer, lpFromlen *int32, lpOverlapped unsafe.Pointer, lpCompletionRoutine unsafe.Pointer) int32 {
	LogCall("WSARecvFrom", s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpFrom, lpFromlen, lpOverlapped, lpCompletionRoutine)

	if dwBufferCount == 0 || lpBuffers == nil {
		setLastError(WSAEINVAL)
		return -1
	}

	if lpOverlapped != nil {
		LogCall("WARNING: WSARecvFrom overlapped I/O not implemented, running synchronously")
	}

	// Calculate total buffer capacity
	bufs := unsafe.Slice((*wsaBuf)(lpBuffers), int(dwBufferCount))
	totalCap := 0
	for i := range bufs {
		totalCap += int(bufs[i].Len)
	}

	// Read flags
	var flags int32
	if lpFlags != nil {
		flags = int32(*lpFlags)
	}

	// Use first buffer for the underlying recvfrom call (it needs a contiguous buffer)
	tmp := make([]byte, totalCap)
	tmpPtr := unsafe.Pointer(&tmp[0])
	n := GoRecvfrom(s, tmpPtr, int32(totalCap), flags, lpFrom, lpFromlen)
	if n == -1 {
		return -1
	}

	// Scatter received data across the WSABUF array
	if n > 0 {
		scatterBuffers(lpBuffers, dwBufferCount, tmp[:n])
	}
	if lpNumberOfBytesRecvd != nil {
		*lpNumberOfBytesRecvd = uint32(n)
	}
	return 0
}

// GoWSARecvDisconnect terminates reception on a socket, maps to shutdown(SD_RECEIVE).
func GoWSARecvDisconnect(s uint64, lpInboundDisconnectData unsafe.Pointer) int32 {
	LogCall("WSARecvDisconnect", s, lpInboundDisconnectData)
	return GoShutdown(s, 0) // SD_RECEIVE
}

// GoWSASendDisconnect initiates termination of sending on a socket, maps to shutdown(SD_SEND).
func GoWSASendDisconnect(s uint64, lpOutboundDisconnectData unsafe.Pointer) int32 {
	LogCall("WSASendDisconnect", s, lpOutboundDisconnectData)
	return GoShutdown(s, 1) // SD_SEND
}

// GoWSASendMsg sends a message via WSAMSG. Ancillary data (cmsg) is ignored.
func GoWSASendMsg(s uint64, lpMsg unsafe.Pointer, dwFlags uint32, lpdwBytesSent *uint32, lpOverlapped unsafe.Pointer, lpCompletionRoutine unsafe.Pointer) int32 {
	LogCall("WSASendMsg", s, lpMsg, dwFlags, lpdwBytesSent, lpOverlapped, lpCompletionRoutine)

	if lpMsg == nil {
		setLastError(WSAEFAULT)
		return -1
	}

	msg := (*wsaMsg)(lpMsg)

	// If a destination name is provided, use sendto path
	if msg.Name != nil && msg.Namelen > 0 && msg.Buffers != nil && msg.BufferCnt > 0 {
		data := gatherBuffers(unsafe.Pointer(msg.Buffers), msg.BufferCnt)
		tmpBuf := wsaBuf{Len: uint32(len(data)), Buf: &data[0]}
		n := GoSendto(s, unsafe.Pointer(tmpBuf.Buf), int32(tmpBuf.Len), int32(dwFlags), msg.Name, msg.Namelen)
		if n != -1 {
			if lpdwBytesSent != nil {
				*lpdwBytesSent = uint32(n)
			}
			return 0
		}
		return -1
	}

	// No destination — use connected send via WSASend
	if msg.Buffers != nil && msg.BufferCnt > 0 {
		return GoWSASend(s, unsafe.Pointer(msg.Buffers), msg.BufferCnt, lpdwBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine)
	}

	setLastError(WSAEINVAL)
	return -1
}

// GoWSARecvMsg receives a message via WSAMSG. Ancillary data (cmsg) is ignored.
func GoWSARecvMsg(s uint64, lpMsg unsafe.Pointer, lpdwBytesReceived *uint32, lpOverlapped unsafe.Pointer, lpCompletionRoutine unsafe.Pointer) int32 {
	LogCall("WSARecvMsg", s, lpMsg, lpdwBytesReceived, lpOverlapped, lpCompletionRoutine)

	if lpMsg == nil {
		setLastError(WSAEFAULT)
		return -1
	}

	msg := (*wsaMsg)(lpMsg)

	// If a source address buffer is provided, use recvfrom path
	if msg.Name != nil && msg.Buffers != nil && msg.BufferCnt > 0 {
		namelen := msg.Namelen

		bufs := unsafe.Slice(msg.Buffers, int(msg.BufferCnt))
		totalCap := 0
		for i := range bufs {
			totalCap += int(bufs[i].Len)
		}

		tmp := make([]byte, totalCap)
		n := GoRecvfrom(s, unsafe.Pointer(&tmp[0]), int32(totalCap), 0, msg.Name, &namelen)
		if n != -1 {
			msg.Namelen = namelen
			scatterBuffers(unsafe.Pointer(msg.Buffers), msg.BufferCnt, tmp[:n])
			if lpdwBytesReceived != nil {
				*lpdwBytesReceived = uint32(n)
			}
			// Zero out control data (no cmsg support)
			msg.Control.Len = 0
			return 0
		}
		return -1
	}

	// No source address — use connected recv via WSARecv
	if msg.Buffers != nil && msg.BufferCnt > 0 {
		var flags uint32
		ret := GoWSARecv(s, unsafe.Pointer(msg.Buffers), msg.BufferCnt, lpdwBytesReceived, &flags, lpOverlapped, lpCompletionRoutine)
		msg.Flags = flags
		msg.Control.Len = 0
		return ret
	}

	setLastError(WSAEINVAL)
	return -1
}
