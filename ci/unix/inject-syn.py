"""Put TCP SYNs on the wire as a LAN neighbour would, through macOS BPF.

    inject-syn.py IFACE SRC_MAC DST_MAC SRC_IP DST_IP DST_PORT

Writes three Ethernet frames, each carrying an IPv4 TCP SYN, onto IFACE. The
smoke test sends them out of one end of a peered feth pair, so the host
receives them on the other end exactly as it would a neighbour's packet. Needs
root (for /dev/bpf*) and nothing outside the standard library.
"""

import fcntl
import os
import struct
import sys
import time

# <net/bpf.h>: _IOW('B', 108, struct ifreq) and _IOW('B', 117, u_int).
BIOCSETIF = 0x8020426C
BIOCSHDRCMPLT = 0x80044275


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def mac(text: str) -> bytes:
    return bytes(int(part, 16) for part in text.split(":"))


def ip(text: str) -> bytes:
    return bytes(int(part) for part in text.split("."))


def syn_frame(src_mac, dst_mac, src_ip, dst_ip, dst_port) -> bytes:
    tcp = struct.pack("!HHIIBBHHH", 40445, dst_port, 1000, 0, 5 << 4, 0x02, 8192, 0, 0)
    pseudo = src_ip + dst_ip + struct.pack("!BBH", 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp)) + tcp[18:]
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, src_ip, dst_ip)
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return dst_mac + src_mac + b"\x08\x00" + header + tcp


def open_bpf() -> int:
    for unit in range(256):
        try:
            return os.open(f"/dev/bpf{unit}", os.O_RDWR)
        except FileNotFoundError:
            break
        except OSError:
            continue
    sys.exit("no free /dev/bpf device")


def main() -> None:
    iface, src_mac, dst_mac, src_ip, dst_ip, dst_port = sys.argv[1:7]
    frame = syn_frame(mac(src_mac), mac(dst_mac), ip(src_ip), ip(dst_ip), int(dst_port))
    bpf = open_bpf()
    fcntl.ioctl(bpf, BIOCSETIF, struct.pack("16s16x", iface.encode()))
    # The frame carries its own source address; do not let BPF overwrite it.
    fcntl.ioctl(bpf, BIOCSHDRCMPLT, struct.pack("I", 1))
    for _ in range(3):
        os.write(bpf, frame)
        time.sleep(0.3)
    os.close(bpf)


if __name__ == "__main__":
    main()
