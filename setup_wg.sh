#!/usr/bin/env bash
# Set up the proof environment:
#  - kernel wg0 on the host (10.9.9.1/28, listens on the LAN IP)
#  - client identity for KLINIKAL (10.9.9.2) in wg.conf
#  - an HTTP server bound to the tunnel-only address 10.9.9.1:8099
# The test target is reachable ONLY through the WireGuard tunnel: the
# KLINIKAL netstack has no other route, so a successful fetch proves
# traffic went through the embedded wireguard-go.
set -euo pipefail
cd "$(dirname "$0")"

LAN_IP=$(ip route get 8.8.8.8 | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')
echo "LAN IP: $LAN_IP"

# keys
SERVER_PRIV=$(wg genkey); echo "$SERVER_PRIV" | wg pubkey > .server.pub; SERVER_PUB=$(cat .server.pub)
CLIENT_PRIV=$(wg genkey); echo "$CLIENT_PRIV" | wg pubkey > .client.pub; CLIENT_PUB=$(cat .client.pub)
echo "$SERVER_PRIV" > .server.priv; chmod 600 .server.priv

# host side
sudo ip link del wg0 2>/dev/null || true
sudo ip link add wg0 type wireguard
sudo wg set wg0 private-key .server.priv peer "$CLIENT_PUB" allowed-ips 10.9.9.2/32
sudo ip addr add 10.9.9.1/28 dev wg0
sudo ip link set wg0 up
sudo wg set wg0 listen-port 51820
# forward + NAT so tunnel traffic (e.g. DNS to 1.1.1.1) can leave the host
sudo sysctl -q -w net.ipv4.ip_forward=1
sudo iptables -C FORWARD -i wg0 -j ACCEPT 2>/dev/null || sudo iptables -A FORWARD -i wg0 -j ACCEPT
sudo iptables -t nat C >/dev/null 2>&1 || true
sudo iptables -t nat -C POSTROUTING -s 10.9.9.0/28 ! -o wg0 -j MASQUERADE 2>/dev/null || \
  sudo iptables -t nat -A POSTROUTING -s 10.9.9.0/28 ! -o wg0 -j MASQUERADE

# klinikal client side
cat > wg.conf <<EOF
[Interface]
PrivateKey = $CLIENT_PRIV
Address = 10.9.9.2/28
DNS = 1.1.1.1

[Peer]
PublicKey = $SERVER_PUB
Endpoint = $LAN_IP:51820
AllowedIPs = 0.0.0.0/0
EOF
echo "wrote wg.conf (client 10.9.9.2 -> peer $LAN_IP:51820)"

# tunnel-only HTTP server
pkill -f 'kl_test_server' 2>/dev/null || true
python3 - <<'EOF' &
import http.server, socketserver
class TS(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/slow":
            import time; time.sleep(1.0)
            body = b"slow-ok\n"
        else:
            body = b"klinikal-tunnel-ok\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a): pass
srv = TS(("10.9.9.1", 8099), H)
srv.server_name = "kl_test_server"
srv.serve_forever()
EOF
sleep 1
echo "http server bound to 10.9.9.1:8099 (tunnel-only address)"
echo "SETUP_OK"
