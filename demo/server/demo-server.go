package main

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

func tcpServer(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	ln, err := net.Listen("tcp", ":9080")
	if err != nil {
		fmt.Println("TCP server error:", err)
		return
	}
	defer ln.Close()
	fmt.Println("TCP server listening on :9080")
	for {
		select {
		case <-ctx.Done():
			return
		default:
			conn, err := ln.Accept()
			if err != nil {
				continue
			}
			go handleTCP(conn)
		}
	}
}

func handleTCP(conn net.Conn) {
	defer conn.Close()
	conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\nHello from TCP"))
}

func udpServer(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	addr, _ := net.ResolveUDPAddr("udp", ":9081")
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		fmt.Println("UDP server error:", err)
		return
	}
	defer conn.Close()
	fmt.Println("UDP server listening on :9081")
	buf := make([]byte, 1024)
	for {
		select {
		case <-ctx.Done():
			return
		default:
			_, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				continue
			}
			conn.WriteToUDP([]byte("Hello from UDP"), addr)
		}
	}
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(2)
	go tcpServer(ctx, &wg)
	go udpServer(ctx, &wg)

	// Give listeners a moment to start
	time.Sleep(time.Second)

	cancel()
	wg.Wait()
	fmt.Println("Cleanup complete.")
}
