package winsock

import (
	"reflect"
	"unsafe"

	"gvisor.dev/gvisor/pkg/waiter"
	"gvisor.dev/gvisor/pkg/tcpip"
)

// GetWaiterQueue extracts the underlying waiter.Queue from a net.Conn or net.Listener
// returned by gvisor/netstack. It uses reflection and unsafe to access unexported fields.
func GetWaiterQueue(obj interface{}) *waiter.Queue {
	if obj == nil {
		return nil
	}

	v := reflect.ValueOf(obj)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return nil
	}

	wqField := v.FieldByName("wq")
	if !wqField.IsValid() {
		return nil
	}

	// It could be a pointer or a struct
	if wqField.Kind() == reflect.Ptr {
		ptr := unsafe.Pointer(wqField.Pointer())
		return (*waiter.Queue)(ptr)
	} else if wqField.Kind() == reflect.Struct {
		// To get the address of an unexported field, we need to use UnsafeAddr
		if wqField.CanAddr() {
			ptr := unsafe.Pointer(wqField.UnsafeAddr())
			return (*waiter.Queue)(ptr)
		}
	}
	return nil
}

// GetEndpoint extracts the underlying tcpip.Endpoint from a net.Conn or net.Listener.
func GetEndpoint(obj interface{}) tcpip.Endpoint {
	if obj == nil {
		return nil
	}

	v := reflect.ValueOf(obj)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return nil
	}

	epField := v.FieldByName("ep")
	if !epField.IsValid() {
		return nil
	}

	if epField.Kind() == reflect.Interface {
		if !epField.IsNil() {
			// We need to use unsafe to read the unexported interface value
			ptr := unsafe.Pointer(epField.UnsafeAddr())
			// An interface in Go is two words: type and data
			// We can use reflect.NewAt to create a pointer to the interface
			ifacePtr := reflect.NewAt(epField.Type(), ptr)
			return ifacePtr.Elem().Interface().(tcpip.Endpoint)
		}
	}
	return nil
}

// UpdateWaiterQueue updates the WaiterQueue and Endpoint for a SocketState.
func UpdateWaiterQueue(st *SocketState) {
	// Unregister existing waiter if any
	if st.WaiterEntry != nil && st.WaiterQueue != nil {
		st.WaiterQueue.EventUnregister(st.WaiterEntry)
		st.WaiterEntry = nil
	}

	if st.Conn != nil {
		st.WaiterQueue = GetWaiterQueue(st.Conn)
		st.Endpoint = GetEndpoint(st.Conn)
	} else if st.Listener != nil {
		st.WaiterQueue = GetWaiterQueue(st.Listener)
		st.Endpoint = GetEndpoint(st.Listener)
	} else {
		st.WaiterQueue = nil
		st.Endpoint = nil
	}

	// Re-register waiter if WSAEventSelect was called
	if st.NetworkEvents != 0 && st.EventHandle != 0 && st.WaiterQueue != nil {
		var mask waiter.EventMask
		if st.NetworkEvents&(FD_READ|FD_ACCEPT) != 0 {
			mask |= waiter.EventIn
		}
		if st.NetworkEvents&FD_WRITE != 0 {
			mask |= waiter.EventOut
		}
		if st.NetworkEvents&FD_CLOSE != 0 {
			mask |= waiter.EventErr | waiter.EventHUp
		}

		if mask != 0 {
			st.WaiterEntry = &waiter.Entry{}
			st.WaiterEntry.Init(st, mask)
			st.WaiterQueue.EventRegister(st.WaiterEntry)

			// Trigger an initial notification to catch already-ready events
			if st.Endpoint != nil {
				readyMask := st.Endpoint.Readiness(mask)
				if readyMask != 0 {
					st.NotifyEvent(readyMask)
				}
			} else if st.Listener != nil {
				st.NotifyEvent(waiter.EventIn)
			}
		}
	}
}
