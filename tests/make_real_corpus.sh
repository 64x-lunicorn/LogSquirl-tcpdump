#!/usr/bin/env bash
# Records the real-capture corpus (tests/corpus/local/real-*.pcap, git-ignored
# and never committed) on this machine's loopback interface, so that only
# self-made traffic between local processes is in it. Needs root for tcpdump: run as `sudo bash tests/make_real_corpus.sh`,
# or name the captures to redo, e.g. `sudo bash tests/make_real_corpus.sh real-ping`.
# The TLS payload is cut by a small snaplen to keep the capture tiny.
set -euo pipefail

out="$(cd "$(dirname "$0")/corpus" && pwd)/local"  # git-ignored: never committed
mkdir -p "$out"
work="$(mktemp -d)"
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$work"' EXIT
lo=lo0
[ "$(uname)" = Linux ] && lo=lo

# tcpdump writes as root; hand the files back to whoever ran sudo.
owner="${SUDO_USER:-$(id -un)}"

# The captures named on the command line, or all of them.
wanted=" $* "
want() { [ "$wanted" = "  " ] || [[ "$wanted" == *" $1 "* ]]; }

record() { # <name> <snaplen> <filter> <command...>
    local name=$1 snap=$2 filter=$3
    shift 3
    want "$name" || return 0
    tcpdump -i "$lo" -s "$snap" -U -w "$out/$name.pcap" "$filter" 2>/dev/null &
    local pid=$!
    sleep 1
    "$@" || true
    sleep 1
    kill -INT "$pid"
    wait "$pid" || true
    chown "$owner" "$out/$name.pcap"
}

# HTTP: curl against a local Python web server.
echo "hello from the corpus" > "$work/index.html"
(cd "$work" && exec python3 -m http.server 8080 --bind 127.0.0.1 >/dev/null 2>&1) &
sleep 1
record real-http 262144 "tcp port 8080" \
    curl -s -o /dev/null http://127.0.0.1:8080/index.html

# DNS: dig against a minimal local responder answering example.org with an A record.
cat > "$work/dns.py" <<'PY'
import socket, struct
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 53))
while True:
    q, addr = s.recvfrom(512)
    tid, = struct.unpack("!H", q[:2])
    end = q.index(b"\0", 12) + 5  # question name + type + class
    hdr = struct.pack("!HHHHHH", tid, 0x8180, 1, 1, 0, 0)
    ans = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + socket.inet_aton("192.0.2.80")
    s.sendto(hdr + q[12:end] + ans, addr)
PY
python3 "$work/dns.py" &
sleep 1
record real-dns 262144 "udp port 53" \
    dig +tries=1 +time=2 +noedns @127.0.0.1 example.org A

# ICMP: ping request and reply.  The macOS firewall in stealth mode drops
# echo requests, even on loopback, so it is switched off for the recording.
fw=/usr/libexec/ApplicationFirewall/socketfilterfw
if want real-ping && [ -x "$fw" ] && "$fw" --getstealthmode | grep -q " on"; then
    "$fw" --setstealthmode off >/dev/null
    trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$work"; "$fw" --setstealthmode on >/dev/null' EXIT
fi
record real-ping 262144 "icmp" ping -c 2 127.0.0.1

# TLS: a TLS 1.3 handshake against a local openssl server, cut at 512 bytes
# so that the ClientHello keeps its SNI and ALPN while the certificate is cut.
openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=localhost -days 1 \
    -keyout "$work/key.pem" -out "$work/cert.pem" 2>/dev/null
openssl s_server -quiet -accept 127.0.0.1:8443 -key "$work/key.pem" -cert "$work/cert.pem" \
    -www >/dev/null 2>&1 &
sleep 1
record real-tls 512 "tcp port 8443" \
    curl -sk --resolve localhost:8443:127.0.0.1 -o /dev/null https://localhost:8443/

ls -l "$out"/real-*.pcap
