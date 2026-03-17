#!/usr/bin/env python3
"""Deterministic self-test for LLDP HMAC protection logic."""

import struct

from ryu.lib import hub

from topoguard_ryu import TopoGuardRyu


def corrupt_mac_tlv(frame: bytes, tlv_type_to_corrupt: int = 0x0D) -> bytes:
    if len(frame) < 14:
        raise ValueError("Frame too short")

    payload = bytearray(frame[14:])
    idx = 0

    while idx + 2 <= len(payload):
        header = struct.unpack_from("!H", payload, idx)[0]
        idx += 2

        tlv_type = header >> 9
        tlv_len = header & 0x1FF

        if tlv_type == 0:
            break
        if idx + tlv_len > len(payload):
            raise ValueError("Malformed TLV while corrupting")

        if tlv_type == tlv_type_to_corrupt and tlv_len > 0:
            payload[idx] ^= 0x01
            return frame[:14] + bytes(payload)

        idx += tlv_len

    raise ValueError("MAC TLV not found")


def main() -> int:
    app = TopoGuardRyu()
    try:
        # _verify_lldp expects remote_dpid to be known in datapaths.
        app.datapaths[1] = object()

        clean = app._build_lldp_frame(1, 1, "00:00:00:00:00:01")
        tampered = corrupt_mac_tlv(clean)

        clean_ok = app._verify_lldp(clean)
        tampered_ok = app._verify_lldp(tampered)

        if clean_ok and not tampered_ok:
            print("result=PASS")
            print("observed=LLDP HMAC verify accepts clean frame and rejects tampered frame")
            return 0

        print("result=FAIL")
        print(f"clean_ok={clean_ok} tampered_ok={tampered_ok}")
        return 2
    finally:
        hub.kill(app.lldp_thread)


if __name__ == "__main__":
    raise SystemExit(main())
