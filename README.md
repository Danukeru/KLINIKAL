# KLINIKAL
WINSOCK2 TO WIREGUARD PROXY DLL
---
KLINIKAL is a Go-based userspace Winsock2 DLL drop-in replacement that transparently tunnels all Windows socket API calls through a WireGuard VPN using an in-process network stack. It cross-compiles from Linux to a Windows DLL via cgo and MinGW, exporting 100+ functions with byte-compatible C signatures matching winsock2.h and ws2tcpip.h. Any Windows application that loads this DLL instead of the system ws2_32.dll will have its entire network I/O silently routed through the configured WireGuard tunnel — without drivers, adapters, or elevated privileges.

## BUILDING
See the `Dockerfile`

## USAGE

See the demo folder.  
Due to `ws2_32.dll` being a protected system dll, it cannot simply be replaced by putting the dll next to the application.  
The application would have to call LoadLibrary itself on a renamed dll if used in your own project, or like in the demo, resolve the IAT by manually mapping the dll itself (ie through injection) for use in an existing executable.

## ARCHITECTURE
### High-Level Design

```mermaid
graph TD
    subgraph "Windows Process (Target Application)"
        APP[Application Code]
        APP -->|"WSAStartup, socket, connect, send, recv, ..."| DLL
    end

    subgraph "wsK_32.dll (KLINIKAL DLL)"
        DLL["C Exports<br/>(exports.go)"]
        DLL -->|"Type marshalling<br/>C ↔ Go"| WINSOCK
        subgraph "winsock/ package"
            WINSOCK["Go Implementations<br/>(Go* functions)"]
            WINSOCK --> REGISTRY["Socket Registry<br/>(registry.go)"]
            WINSOCK --> STACK["WireGuard Stack<br/>(stack.go)"]
            WINSOCK --> EVENTS["Event Objects<br/>(event_objects.go)"]
        end
    end

    subgraph "Userspace Network Stack"
        STACK --> NETSTACK["gVisor netstack<br/>(TUN device)"]
        NETSTACK --> WG["WireGuard Device<br/>(wireguard-go)"]
        WG -->|"Encrypted UDP"| PEER["WireGuard Peer<br/>(Remote Endpoint)"]
    end

    style APP fill:#4a90d9,color:#fff
    style DLL fill:#e8a838,color:#000
    style WINSOCK fill:#5cb85c,color:#fff
    style NETSTACK fill:#9b59b6,color:#fff
    style WG fill:#c0392b,color:#fff
    style PEER fill:#2c3e50,color:#fff
```

#### Socket Lifecycle
```mermaid
sequenceDiagram
    participant App as Application
    participant E as exports.go
    participant L as lifecycle.go
    participant SM as sock_mgmt.go
    participant CB as conn_basic.go
    participant S as stack.go
    participant R as registry.go
    participant NS as netstack

    App->>E: WSAStartup(0x0202, &data)
    E->>L: GoWSAStartup()
    L->>L: wsaRefCount++
    L->>S: InitializeStack("wg.conf")
    S->>S: Parse INI config
    S->>NS: CreateNetTUN(ips, dns, mtu)
    NS-->>S: tun, tnet
    S->>S: device.NewDevice(tun, bind, logger)
    S->>S: dev.IpcSet(config) → dev.Up()
    L-->>App: 0 (success)

    App->>E: socket(AF_INET, SOCK_STREAM, 0)
    E->>SM: GoSocket(2, 1, 0)
    SM->>R: Register(&SocketState{Type:TCP})
    R-->>SM: handle=1001
    SM-->>App: 1001

    App->>E: connect(1001, &addr, 16)
    E->>CB: GoConnect(1001, addr, 16)
    CB->>R: Get(1001)
    CB->>CB: parseSockAddrIn(addr) → "93.184.216.34:80"
    CB->>S: GetStack()
    S-->>CB: tnet
    CB->>NS: tnet.Dial("tcp", "93.184.216.34:80")
    NS-->>CB: conn
    CB->>CB: st.Conn = conn
    CB-->>App: 0 (success)

    App->>E: send(1001, buf, 64, 0)
    E->>CB: GoSend(1001, buf, 64, 0)
    CB->>CB: st.Conn.Write(data)
    CB-->>App: 64

    App->>E: closesocket(1001)
    E->>SM: GoClosesocket(1001)
    SM->>R: Get(1001)
    SM->>SM: st.Conn.Close()
    SM->>R: Unregister(1001)
    SM-->>App: 0

    App->>E: WSACleanup()
    E->>L: GoWSACleanup()
    L->>L: wsaRefCount--
    L->>R: PurgeAll()
    L->>S: CloseStack()
    L-->>App: 0
```
