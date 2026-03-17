# Link Fabrication Attack Test (Manual First)

This guide shows how to run the same forged-LLDP link fabrication attack manually against:

1. `insecure_baseline_ryu.py` (expected to be vulnerable)
2. `topoguard_ryu.py` (expected to defend)

At the end, you can run `ab_compare.py` to automate the same A/B test.

## Test Setup

Use two terminals from `topoguard-ryu`:

- Terminal A: controller (`ryu-manager ...`)
- Terminal B: Mininet (`sudo python3 topology.py`)

Topology used:

- `h1`, `h2` on `s1`
- `h3` on `s2`
- Attack source is `h1`

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
# Warm up learning state
h2 ping -c 2 10.0.0.3
h3 ping -c 2 10.0.0.2

# ARP pinning
h2 arp -s 10.0.0.3 00:00:00:00:00:03
h3 arp -s 10.0.0.2 00:00:00:00:00:02

# Launch forged LLDP from compromised host h1
h1 python3 attacks/send_fake_lldp.py h1-eth0 --remote-dpid 2 --remote-port 1

# Post-attack reachability check
h3 ping -c 3 10.0.0.2
```

### Expected Output (Baseline)

- `pre` (before attack): low packet loss (usually `0%`).
- `post` (after attack): packet loss rises sharply (often `100%`).
- Controller log shows insecure LLDP learning, including the forged path, for example:

```text
[INSECURE] Learned link 2:1 -> 1:1 from LLDP packet-in on local port 1
```

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
h3 ping -c 2 10.0.0.2

# Same forged LLDP attempt
h1 python3 attacks/send_fake_lldp.py h1-eth0 --remote-dpid 2 --remote-port 1

# Post-attack reachability check
h3 ping -c 3 10.0.0.2
```

### Expected Output (TopoGuard)

- `pre` (before attack): low packet loss (usually `0%`).
- `post` (after attack): still low packet loss (host remains reachable).
- Controller log records the forged LLDP as a violation and drops it, for example:

```text
Violation: receive falsified LLDP (missing MAC TLV)
Violation: Receive LLDP packet from HOST port: sw=1 port=1
```

## 3) Automatic A/B Test

After the manual runs above, you can execute the automated comparison:

```bash
sudo python3 ab_compare.py
```

It prints:

- baseline `pre`/`post` packet-loss percentages
- topoguard `pre`/`post` packet-loss percentages
- final `result=PASS` or `result=FAIL`
