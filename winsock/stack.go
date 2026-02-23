package winsock

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"gopkg.in/ini.v1"
)

var (
	globalStack      *netstack.Net
	globalDevice     *device.Device
	globalDNS        []netip.Addr
	stackInitialized bool
	stackMu          sync.RWMutex
)

// InitializeStack initializes the userspace WireGuard stack with the given config file.
func InitializeStack(configPath string) error {
	stackMu.Lock()
	defer stackMu.Unlock()

	if stackInitialized {
		return nil
	}

	cfg, err := ini.Load(configPath)
	if err != nil {
		return fmt.Errorf("failed to load WG config: %w", err)
	}

	// Simplified parsing of [Interface] and [Peer]
	interfaceSection := cfg.Section("Interface")
	if interfaceSection == nil {
		return errors.New("missing [Interface] section")
	}

	privateKeyBase64 := interfaceSection.Key("PrivateKey").String()
	privateKeyHex, err := decodeBase64ToHex(privateKeyBase64)
	if err != nil {
		return fmt.Errorf("invalid PrivateKey: %w", err)
	}

	addressStr := interfaceSection.Key("Address").String()
	ips, err := parseIPs(addressStr)
	if err != nil {
		return fmt.Errorf("invalid Interface Address: %w", err)
	}

	dnsStr := interfaceSection.Key("DNS").String()
	dns, _ := parseIPs(dnsStr)

	mtu := 1420
	if interfaceSection.HasKey("MTU") {
		mtu, _ = interfaceSection.Key("MTU").Int()
	}

	// Setup tunnel and stack
	tun, tnet, err := netstack.CreateNetTUN(ips, dns, mtu)
	if err != nil {
		return fmt.Errorf("failed to create netstack TUN: %w", err)
	}

	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "wg-winsock: "))

	// Apply device configuration via IPC
	var request bytes.Buffer
	request.WriteString(fmt.Sprintf("private_key=%s\n", privateKeyHex))

	if interfaceSection.HasKey("ListenPort") {
		port, _ := interfaceSection.Key("ListenPort").Int()
		request.WriteString(fmt.Sprintf("listen_port=%d\n", port))
	}

	peers, _ := cfg.SectionsByName("Peer")
	for _, peerSection := range peers {
		publicKeyBase64 := peerSection.Key("PublicKey").String()
		publicKeyHex, err := decodeBase64ToHex(publicKeyBase64)
		if err != nil {
			return fmt.Errorf("invalid Peer PublicKey: %w", err)
		}

		request.WriteString(fmt.Sprintf("public_key=%s\n", publicKeyHex))

		if peerSection.HasKey("Endpoint") {
			endpoint := peerSection.Key("Endpoint").String()
			// Resolve endpoint if needed
			resolvedEndpoint, err := resolveEndpoint(endpoint)
			if err == nil {
				request.WriteString(fmt.Sprintf("endpoint=%s\n", resolvedEndpoint))
			}
		}

		if peerSection.HasKey("AllowedIPs") {
			allowedIPs := peerSection.Key("AllowedIPs").String()
			for _, cidr := range strings.Split(allowedIPs, ",") {
				cidr = strings.TrimSpace(cidr)
				if cidr != "" {
					request.WriteString(fmt.Sprintf("allowed_ip=%s\n", cidr))
				}
			}
		} else {
			request.WriteString("allowed_ip=0.0.0.0/0\n")
			request.WriteString("allowed_ip=::0/0\n")
		}

		if peerSection.HasKey("PersistentKeepalive") {
			keepalive, _ := peerSection.Key("PersistentKeepalive").Int()
			request.WriteString(fmt.Sprintf("persistent_keepalive_interval=%d\n", keepalive))
		}
	}

	if err := dev.IpcSet(request.String()); err != nil {
		return fmt.Errorf("failed to set device IPC: %w", err)
	}

	if err := dev.Up(); err != nil {
		return fmt.Errorf("failed to bring device up: %w", err)
	}

	globalStack = tnet
	globalDevice = dev
	globalDNS = dns
	stackInitialized = true

	return nil
}

// GetStack returns the initialized userspace stack.
func GetStack() (*netstack.Net, error) {
	stackMu.RLock()
	if stackInitialized {
		defer stackMu.RUnlock()
		return globalStack, nil
	}
	stackMu.RUnlock()

	// Not initialized — try to init (InitializeStack acquires its own write lock)
	if _, err := os.Stat("wg.conf"); err == nil {
		if err := InitializeStack("wg.conf"); err != nil {
			return nil, err
		}
	} else {
		return nil, errors.New("stack not initialized and wg.conf not found")
	}

	stackMu.RLock()
	defer stackMu.RUnlock()
	return globalStack, nil
}

// GetDNS returns the configured DNS servers.
func GetDNS() ([]netip.Addr, error) {
	stackMu.RLock()
	if stackInitialized {
		defer stackMu.RUnlock()
		return globalDNS, nil
	}
	stackMu.RUnlock()

	// Not initialized — try to init (InitializeStack acquires its own write lock)
	if _, err := os.Stat("wg.conf"); err == nil {
		if err := InitializeStack("wg.conf"); err != nil {
			return nil, err
		}
	} else {
		return nil, errors.New("stack not initialized and wg.conf not found")
	}

	stackMu.RLock()
	defer stackMu.RUnlock()
	return globalDNS, nil
}

// CloseStack shuts down the userspace stack.
func CloseStack() {
	stackMu.Lock()
	defer stackMu.Unlock()

	if !stackInitialized {
		return
	}

	if globalDevice != nil {
		globalDevice.Close()
	}
	globalStack = nil
	globalDevice = nil
	stackInitialized = false
}

// helpers to parse config

func decodeBase64ToHex(key string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", err
	}
	if len(decoded) != 32 {
		return "", errors.New("key should be 32 bytes")
	}
	return hex.EncodeToString(decoded), nil
}

func parseIPs(s string) ([]netip.Addr, error) {
	if s == "" {
		return nil, nil
	}
	parts := strings.Split(s, ",")
	var ips []netip.Addr
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		// Try parsing as CIDR first to get the IP
		if cidrIP, _, err := net.ParseCIDR(p); err == nil {
			if ip, ok := netip.AddrFromSlice(cidrIP); ok {
				ips = append(ips, ip.Unmap())
			}
		} else if ip, err := netip.ParseAddr(p); err == nil {
			ips = append(ips, ip.Unmap())
		} else {
			return nil, fmt.Errorf("invalid IP/CIDR: %s", p)
		}
	}
	return ips, nil
}

func resolveEndpoint(endpoint string) (string, error) {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return "", err
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return "", err
	}
	if len(ips) == 0 {
		return "", errors.New("no IPs found for host")
	}
	return net.JoinHostPort(ips[0].String(), port), nil
}
