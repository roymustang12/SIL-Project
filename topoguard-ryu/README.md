# TopoGuard for Ryu

This directory contains a Ryu port of the TopoGuard logic from `topoguard-floodlight`.

## Lab Topology

- `s1 (dpid=1)` connected to `s2 (dpid=2)`
- `h1`, `h2` connected to `s1`
- `h3` connected to `s2`

This layout supports a realistic attack goal: an edge attacker on `h1` attempts to forge LLDP claiming to be switch endpoint `s2:1` (a host-facing port) to poison topology state.

## Implemented behaviors

1. Port role tracking (`ANY`, `HOST`, `SWITCH`) per switch port.
2. Violation logging for:
- LLDP packets received from a host-designated port.
- First-hop host packets received from a switch-designated port.
- Host move without prior port-down/shutdown signal.
- Host still reachable at old location after move (probe reply seen).
- Falsified LLDP (missing/invalid HMAC TLV).
3. LLDP generation with TopoGuard TLVs:
- Remote DPID TLV (`type=127`, OpenFlow OUI payload)
- Controller ID TLV (`type=0x0c`)
- Direction TLV (`type=0x73`)
- HMAC TLV (`type=0x0d`, HMAC-SHA256 over `<dpid><port>`)
4. ICMP host probing on host-move events (sent to old attachment port).
5. Basic L2 learning-switch forwarding so the app can run standalone.

## Basic usage (controller + Mininet)

Terminal 1:

```bash
ryu-manager topoguard_ryu.py
```

Terminal 2:

```bash
sudo python3 topology.py
```

Inside Mininet:

```bash
pingall
```

## Notes

- This is a direct behavioral port of the TopoGuard checks, not a byte-for-byte framework port.
- Ryu does not expose Floodlight's `IDeviceListener` API, so host-move handling is implemented from observed source-MAC location changes in `PacketIn` events.
- `CONTROLLER_IP` is set to `10.0.1.100` to match the Floodlight code default.

## Attack guides

This project includes two attack-specific walkthroughs. Use these for the step-by-step procedures and expected outputs:

- Host Location Hijacking (HLH): HLH_README.md
- Link Fabrication (LF): LF_README.md
- Port Amnesia (PA): PA_README.md