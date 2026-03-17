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

## Run

Terminal 1:

```bash
cd /home/yuvraj/repos/SIL-Project/topoguard-ryu
ryu-manager topoguard_ryu.py
```

Terminal 2:

```bash
cd /home/yuvraj/repos/SIL-Project/topoguard-ryu
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

## Safety Check (Automated)

This runs controller + Mininet + attack cases and verifies that TopoGuard violations are detected.

```bash
sudo python3 safety_check.py
```

Expected final output:

```text
result=PASS
observed=LLDP host-port + host-move violations
```

It writes controller logs to:

`/home/yuvraj/repos/SIL-Project/topoguard-ryu/topoguard_safety.log`

## LLDP HMAC Self-Test

This verifies that clean TopoGuard LLDP passes and tampered HMAC LLDP is rejected:

```bash
cd /home/yuvraj/repos/SIL-Project/topoguard-ryu
python3 hmac_self_test.py
```

Expected output:

```text
result=PASS
observed=LLDP HMAC verify accepts clean frame and rejects tampered frame
```

## Manual Attack Trigger

Inside Mininet CLI:

1. Warm up host-port state:
```bash
h1 ping -c 2 10.0.0.3
```
2. Launch a realistic link-fabrication attempt from compromised edge host `h1`:
```bash
h1 python3 attacks/send_fake_lldp.py h1-eth0 --remote-dpid 2 --remote-port 1
```
3. Simulate host move/MAC spoof from another port:
```bash
h2 ip link set dev h2-eth0 down
h2 ip link set dev h2-eth0 address 00:00:00:00:00:01
h2 ip link set dev h2-eth0 up
h2 ping -c 1 10.0.0.3
```

Expected in controller logs:

- `Violation: Receive LLDP packet from HOST port: ...`
- `Violation: Host Move from switch ... without Port ShutDown`

## Baseline vs TopoGuard (Side-by-Side)

`insecure_baseline_ryu.py` is an intentionally vulnerable controller that trusts all LLDP updates.

Run comparison:

```bash
cd /home/yuvraj/repos/SIL-Project/topoguard-ryu
sudo python3 ab_compare.py
```

Expected behavior:

- Baseline: `h3 -> h2` ping packet loss rises sharply after forged LLDP.
- TopoGuard: `h3 -> h2` remains reachable, while violations are logged and malicious LLDP is dropped.
