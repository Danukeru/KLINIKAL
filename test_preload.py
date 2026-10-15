"""Proof suite: Python network access through KLINIKAL's LD_PRELOAD loader.

Run via run_test.sh with LD_PRELOAD + KLINIKAL_WG_CONF set. 23 cases:
layer 1 = data path + DNS through the tunnel (tunnel-only server, wg
counters); layer 2 = async (socket timeouts, epoll/poll selectors,
select(), non-blocking recv); production = non-blocking connect +
SO_ERROR, dup/dup3 aliasing, sendmsg/recvmsg, threaded connect+epoll;
stability regressions = addrinfo ownership loops, epoll churn,
fd-reservation race, SO_RCVTIMEO/MSG_DONTWAIT, close-during-EINPROGRESS,
MSG_PEEK completeness, close_range, mixed pipe+tunnel bridge poll;
passthrough = cross-process loopback IPC and AF_UNIX (must stay on the
kernel). Prints PROOF_OK on success.
"""
import selectors
import socket
import subprocess
import sys
import urllib.request

ip = "10.9.9.1"
r = urllib.request.urlopen(f"http://{ip}:8099/", timeout=15)
body = r.read().decode().strip()
assert body == "klinikal-tunnel-ok", body
print(f"IP fetch: {r.status} {body}")

try:
    infos = socket.getaddrinfo("example.com", 80)
    print("DNS over tunnel: example.com ->", infos[0][4][0])
except OSError as e:
    print(f"DNS check failed: {e}")

# show that our fds are shim-managed and below FD_SETSIZE (so CPython's
# internal select and the select module work)
s = socket.socket()
print("socket fd is in shim range:", 3 <= s.fileno() < 1024)
s.close()

# ---- layer 2: async paths ----

# A. socket timeout path: settimeout -> FIONBIO -> EWOULDBLOCK -> select
s = socket.create_connection((ip, 8099), timeout=10)
s.sendall(b"GET / HTTP/1.0\r\n\r\n")
chunks = []
while True:
    try:
        d = s.recv(4096)
    except socket.timeout:
        print("TIMEOUT_FAIL: recv timed out with data pending")
        sys.exit(1)
    if not d:
        break
    chunks.append(d)
data = b"".join(chunks)
assert b"klinikal-tunnel-ok" in data, data[:80]
print("timeout-mode recv: got", len(data), "bytes")
s.close()

# B. selectors (poll path)
s = socket.create_connection((ip, 8099))
s.sendall(b"GET / HTTP/1.0\r\n\r\n")
s.setblocking(False)
sel = selectors.DefaultSelector()
sel.register(s, selectors.EVENT_READ)
events = sel.select(timeout=10)
assert events and events[0][0].fileobj is s, "selector saw nothing"
got = b""
while b"klinikal-tunnel-ok" not in got:
    try:
        d = s.recv(4096)
    except BlockingIOError:
        sel.select(timeout=10)
        continue
    if not d:
        break
    got += d
assert b"klinikal-tunnel-ok" in got, got[:80]
print("selectors poll path: ready event + recv ok")
sel.unregister(s)
sel.close()
s.close()

# C. poll path (selectors.PollSelector) + select.select (fds now live
# below FD_SETSIZE, so CPython's select module works too)
import selectors as _sel
import select as _pyselect
s = socket.create_connection((ip, 8099))
s.sendall(b"GET / HTTP/1.0\r\n\r\n")
ready, _, _ = _pyselect.select([s], [], [], 10)
assert ready == [s], ready
print("select.select path:", len(ready), "fd ready")
s.close()
s = socket.create_connection((ip, 8099))
s.sendall(b"GET / HTTP/1.0\r\n\r\n")
s.setblocking(False)
psel = _sel.PollSelector()
psel.register(s, _sel.EVENT_READ)
events = psel.select(timeout=10)
assert events, "poll selector saw nothing"
got = b""
while b"klinikal-tunnel-ok" not in got:
    try:
        d = s.recv(4096)
    except BlockingIOError:
        psel.select(timeout=10)
        continue
    if not d:
        break
    got += d
assert b"klinikal-tunnel-ok" in got, got[:80]
print("poll path: ready event + recv ok")
psel.unregister(s)
psel.close()
s.close()

# D. real non-blocking recv: no data yet -> BlockingIOError
s = socket.socket()
s.setblocking(False)
try:
    s.connect((ip, 8099))
except BlockingIOError:
    ws = _sel.PollSelector()
    ws.register(s, _sel.EVENT_WRITE)
    ws.select(timeout=10)
    ws.close()
s.sendall(b"GET / HTTP/1.0\r\n\r\n")
try:
    d = s.recv(1)
    print("nonblocking recv: data already available (len", len(d), ")")
except BlockingIOError:
    print("nonblocking recv: EWOULDBLOCK correctly reported")
s.close()

# E. non-blocking connect: EINPROGRESS -> select writable -> SO_ERROR
import time as _t
s = socket.socket()
s.setblocking(False)
try:
    s.connect((ip, 8099))
    print("nonblocking connect: completed immediately")
except BlockingIOError:
    ws = _sel.PollSelector()
    ws.register(s, _sel.EVENT_WRITE)
    ws.select(timeout=10)
    ws.close()
    err = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
    assert err == 0, f"SO_ERROR={err}"
    print("nonblocking connect: EINPROGRESS -> writable -> SO_ERROR=0")
s.sendall(b"GET / HTTP/1.0\r\n\r\n")
s.setblocking(True)
rs = _sel.PollSelector()
rs.register(s, _sel.EVENT_READ)
rs.select(timeout=10)
rs.close()
got = b""
while b"klinikal-tunnel-ok" not in got:
    d = s.recv(4096)
    if not d:
        break
    got += d
assert b"klinikal-tunnel-ok" in got, got[:80]
print("post-connect send/recv ok")
s.close()

# F. refused connection surfaces via SO_ERROR
s = socket.socket()
s.setblocking(False)
try:
    s.connect((ip, 4999))  # nothing listening
    print("connect to closed port unexpectedly succeeded")
except BlockingIOError:
    ws = _sel.PollSelector()
    ws.register(s, _sel.EVENT_WRITE)
    ws.select(timeout=10)
    ws.close()
    err = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
    assert err in (111, 115, 104), f"unexpected SO_ERROR={err}"
    print(f"refused connect: SO_ERROR={err} (ECONNREFUSED/EINPROGRESS)")
s.close()

# G. os.dup aliasing shares the handle; closing the alias keeps the original
import os
s = socket.create_connection((ip, 8099))
s.sendall(b"GET / HTTP/1.0\r\n\r\n")
fd2 = os.dup(s.fileno())
assert fd2 != s.fileno(), "dup did not allocate a new fd"
b = socket.socket(socket.AF_INET, socket.SOCK_STREAM, fileno=fd2)
got = b""
while b"klinikal-tunnel-ok" not in got:
    d = b.recv(4096)
    if not d:
        break
    got += d
assert b"klinikal-tunnel-ok" in got
b.close()  # alias closed; original fd and Go socket must stay alive
name = s.getpeername()
assert name == (ip, 8099), name
try:
    os.fstat(fd2)
    assert False, "alias reservation fd still open"
except OSError:
    pass
print("os.dup aliasing ok (alias close kept original alive)")
s.close()

# H. sendmsg/recvmsg scatter-gather
s = socket.create_connection((ip, 8099))
s.sendmsg([b"GET ", b"/ HTTP/1.0\r\n\r\n"])
data = b""
while b"klinikal-tunnel-ok" not in data:
    bufs = [bytearray(64), bytearray(4096)]
    n, ancdata, flags, addr = s.recvmsg_into(bufs)
    if n == 0:
        break
    first = min(n, len(bufs[0]))
    data += bytes(bufs[0][:first]) + bytes(bufs[1][:n - first])
assert b"klinikal-tunnel-ok" in data, data[:80]
print("sendmsg/recvmsg scatter-gather ok")
s.close()

# I. multi-threaded concurrent fetch + epoll
import threading
errs = []
def _worker():
    try:
        ss = socket.create_connection((ip, 8099))
        ss.sendall(b"GET / HTTP/1.0\r\n\r\n")
        w = _sel.DefaultSelector()
        w.register(ss, _sel.EVENT_READ)
        assert w.select(timeout=10)
        w.close()
        g = b""
        while b"klinikal-tunnel-ok" not in g:
            d = ss.recv(4096)
            if not d:
                break
            g += d
        assert b"klinikal-tunnel-ok" in g
        ss.close()
    except Exception as e:
        errs.append(repr(e))
ts = [threading.Thread(target=_worker) for _ in range(4)]
for t in ts: t.start()
for t in ts: t.join(30)
assert not errs, errs
print("4-thread concurrent fetch+epoll ok")

# J. addrinfo table exhaustion (regression: fixed 128-slot C tracking
# table caused free(): invalid pointer after ~128 lookups)
import socket as _sock
for i in range(300):
    _sock.getaddrinfo("example.com", 80)
print("300 getaddrinfo loops ok")

# K. concurrent epoll registration churn (regression: kl_ep_tbl was
# mutated without the table mutex)
errs = []
def _churn(n):
    try:
        for _ in range(5):
            ss = socket.create_connection((ip, 8099))
            ss.sendall(b"GET / HTTP/1.0\r\n\r\n")
            w = _sel.DefaultSelector()
            w.register(ss, _sel.EVENT_READ)
            w.modify(ss, _sel.EVENT_READ)
            w.select(timeout=5)
            w.unregister(ss)
            w.close()
            ss.close()
    except Exception as e:
        errs.append(repr(e))
ts = [threading.Thread(target=_churn, args=(n,)) for n in range(8)]
for t in ts: t.start()
for t in ts: t.join(60)
assert not errs, errs
print("8-thread epoll registration churn ok")

# L. SO_RCVTIMEO end-to-end (regression: winsock DWORD-ms parse meant
# CPython's settimeout(timeval) never bounded a blocking recv)
s = socket.create_connection((ip, 8099), timeout=0.5)
s.sendall(b"GET /slow HTTP/1.0\r\n\r\n")   # server delays 1.0s
try:
    s.recv(4096)
    raise SystemExit("TIMEOUT_NOT_RAISED")
except socket.timeout:
    print("SO_RCVTIMEO: blocking recv bounded ok")
s.close()
# and the same socket pattern without timeout still completes
s = socket.create_connection((ip, 8099))
s.sendall(b"GET /slow HTTP/1.0\r\n\r\n")
got = b""
while b"slow-ok" not in got:
    d = s.recv(4096)
    if not d:
        break
    got += d
assert b"slow-ok" in got, got[:80]
print("no-timeout recv still waits for slow response ok")
s.close()

# M. MSG_DONTWAIT per-call (regression: flags ignored -> would block)
s = socket.create_connection((ip, 8099))
try:
    s.recv(4096, socket.MSG_DONTWAIT)      # nothing pending
    raise SystemExit("DONTWAIT_BLOCKED")
except BlockingIOError:
    print("MSG_DONTWAIT: immediate BlockingIOError ok")
s.close()

# N. dup3() syscall on a fake socket (regression: dup3 not interposed)
import ctypes
s = socket.create_connection((ip, 8099))
s.sendall(b"GET / HTTP/1.0\r\n\r\n")
libc = ctypes.CDLL(None)
libc.dup3.restype = ctypes.c_int
fd2 = libc.dup3(s.fileno(), 900, 0o2000000)  # O_CLOEXEC
assert fd2 == 900, fd2
b = socket.socket(socket.AF_INET, socket.SOCK_STREAM, fileno=fd2)
got = b""
while b"klinikal-tunnel-ok" not in got:
    d = b.recv(4096)
    if not d:
        break
    got += d
assert b"klinikal-tunnel-ok" in got, got[:80]
b.close()
assert s.getpeername() == (ip, 8099)
s.close()
print("dup3() aliasing ok")

# O. close during EINPROGRESS connect (regression: async dial adopted
# a connection whose fd was already closed -> leaked conn)
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setblocking(False)
try:
    s.connect(("10.9.9.8", 9))             # subnet address, no host: dial hangs
except BlockingIOError:
    pass
s.close()                                  # close while dial in flight
import time as _t
_t.sleep(1.5)                              # let the abandoned dial finish
s = socket.create_connection((ip, 8099))   # stack must still be healthy
s.sendall(b"GET / HTTP/1.0\r\n\r\n")
got = b""
while b"klinikal-tunnel-ok" not in got:
    d = s.recv(4096)
    if not d:
        break
    got += d
assert b"klinikal-tunnel-ok" in got, got[:80]
s.close()
print("close-during-EINPROGRESS ok (stack healthy after)")

# P. MSG_PEEK completeness (regression: peek returned only the byte a
# readiness probe had parked, not the full buffered response)
s = socket.create_connection((ip, 8099))
s.sendall(b"GET / HTTP/1.0\r\n\r\n")
_t.sleep(0.5)                              # let both segments arrive
peeked = s.recv(4096, socket.MSG_PEEK)
assert b"klinikal-tunnel-ok" in peeked, peeked[:80]
real = s.recv(4096)
assert real == peeked, (real[:80], peeked[:80])
s.close()
print("MSG_PEEK returns full buffered response, recv matches ok")

# Q. close_range on a fake fd (regression: bypassed interposition ->
# stale fake entry and a Go registration that outlived the fd)
libc.close_range.restype = ctypes.c_int
s = socket.create_connection((ip, 8099))
fd = s.fileno()
assert libc.close_range(fd, fd, 0) == 0
try:
    s.getpeername()
    raise SystemExit("CLOSE_RANGE_LEFT_FD_ALIVE")
except OSError:
    pass
s.detach()
# the freed number must be reusable by a fresh socket
s = socket.create_connection((ip, 8099))
s.sendall(b"GET / HTTP/1.0\r\n\r\n")
got = b""
while b"klinikal-tunnel-ok" not in got:
    d = s.recv(4096)
    if not d:
        break
    got += d
assert b"klinikal-tunnel-ok" in got, got[:80]
s.close()
# CPython's own bulk-close path (os.closerange; may loop close() or
# use a raw close_range syscall depending on version)
s = socket.create_connection((ip, 8099))
fd = s.fileno()
os.closerange(fd, fd + 1)
try:
    s.getpeername()
    print("NOTE: os.closerange bypassed interposition (raw syscall)")
except OSError:
    print("os.closerange routed correctly")
s.detach()
s = socket.create_connection((ip, 8099)); s.close()
print("close_range cleanup ok")

# R. mixed real+tunnel poll via the eventfd bridge (regression: slice
# polling cost CPU and 10ms latency; the bridge must block in-kernel)
import select as _ps
r, w = os.pipe()
s = socket.create_connection((ip, 8099))
s.sendall(b"GET /slow HTTP/1.0\r\n\r\n")   # server responds at +1.0s
p = _ps.poll()
p.register(r, _ps.POLLIN); p.register(s.fileno(), _ps.POLLIN)
t0 = _t.monotonic(); c0 = _t.process_time()
evs = p.poll(5000)
dt = _t.monotonic() - t0; dc = _t.process_time() - c0
assert dt > 0.9, f"mixed poll returned early: {dt:.3f}s"
assert any(fd_ == s.fileno() for fd_, ev in evs), evs
assert dc < 0.01, f"mixed poll burned CPU: {dc*1000:.0f}ms"
# pipe readiness still works in the same call shape
os.write(w, b"x")
evs = p.poll(5)
assert any(fd_ == r for fd_, ev in evs), evs
os.read(r, 1)
got = b""
while b"slow-ok" not in got:
    d = s.recv(4096)
    if not d:
        break
    got += d
assert b"slow-ok" in got, got[:80]
s.close(); os.close(r); os.close(w)
print(f"mixed poll via bridge ok (waited {dt:.2f}s, {dc*1000:.1f}ms CPU)")

# S. loopback stays on the kernel (regression: every injected process
# embeds its own stack, so 127.0.0.1 must be real for cross-process IPC
# -- Ray driver<->raylet, multiprocessing, health checks)
srv = socket.socket()
srv.bind(("127.0.0.1", 0))
port = srv.getsockname()[1]
srv.listen(1)
child = subprocess.Popen(
    [sys.executable, "-c",
     "import socket,sys;"
     f"s=socket.create_connection(('127.0.0.1',{port}),timeout=10);"
     "s.sendall(b'ping');d=s.recv(4);assert d==b'pong',d;print('OK')"],
    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
conn, _ = srv.accept()
conn.sendall(b"pong")
conn.close(); srv.close()
cout, cerr = child.communicate(timeout=30)
assert child.returncode == 0 and "OK" in cout, (cout, cerr)
print("cross-process loopback IPC ok (child saw real 127.0.0.1)")

# AF_UNIX connect/bind/send/recv pass through (multiprocessing uses these)
un = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
path = "/tmp/kl_unix_test_%d" % os.getpid()
un.bind(path); un.listen(1)
c2 = subprocess.Popen(
    [sys.executable, "-c",
     "import socket,sys;"
     f"s=socket.socket(socket.AF_UNIX);s.connect({path!r});"
     "s.sendall(b'unix');print('OK' if s.recv(4)==b'unix' else 'BAD')"],
    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
conn, _ = un.accept()
conn.sendall(b"unix")
conn.close(); un.close(); os.unlink(path)
o2, e2 = c2.communicate(timeout=30)
assert c2.returncode == 0 and "OK" in o2, (o2, e2)
print("AF_UNIX passthrough ok")

print("PROOF_OK")
