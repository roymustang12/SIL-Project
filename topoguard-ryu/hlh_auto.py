#!/usr/bin/env python3
"""A/B comparison: Host Location Hijacking (MAC-move spoof).

Run with sudo:
    sudo python3 hlh_auto.py

Scenario:
1. Warm up legitimate host learning for victim h2 (MAC ...:02).
2. Attacker h1 spoofs victim MAC and emits traffic.
3. Rebuild switch flows and inspect s1 flow output for victim MAC.

Reported checks:
- Baseline poisoning evidence (victim MAC traffic redirected to attacker port)
- TopoGuard host-move violation detection in controller logs
"""

from __future__ import annotations

from dataclasses import dataclass
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
VICTIM_IP = "10.0.0.2"
VICTIM_MAC = "00:00:00:00:00:02"


@dataclass
class TrialResult:
    name: str
    pre_loss: int
    post_loss: int
    attacker_port: int
    victim_port: int
    pre_outputs: Set[int]
    post_outputs: Set[int]
    host_move_violation: bool
    log_file: Path


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
        # Fallback to tx/rx parsing if percent is missing.
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
    out = host.cmd(f"ping -c {count} {ip}")
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

    log_path = ROOT / f"hlh_{name}.log"
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
        time.sleep(2)

        h1 = net.get("h1")  # attacker
        h2 = net.get("h2")  # victim
        h3 = net.get("h3")  # remote source
        s1 = net.get("s1")

        attacker_port = get_switch_port_for_host(s1, h1)
        victim_port = get_switch_port_for_host(s1, h2)

        # Warm-up host learning and pin victim ARP at source host.
        h2.cmd("ping -c 2 10.0.0.3 >/dev/null 2>&1")
        h3.cmd(f"arp -s {VICTIM_IP} {VICTIM_MAC}")
        h3.cmd("ping -c 2 10.0.0.2 >/dev/null 2>&1")

        clear_switch_flows()
        time.sleep(0.5)

        pre_loss = ping_loss(h3, VICTIM_IP, count=2)
        h3.cmd("ping -c 1 10.0.0.2 >/dev/null 2>&1")
        time.sleep(0.5)
        pre_outputs = get_s1_outputs_for_victim_mac()

        # Host-location hijacking: h1 spoofs h2's MAC.
        h1.cmd("ip link set dev h1-eth0 down")
        h1.cmd(f"ip link set dev h1-eth0 address {VICTIM_MAC}")
        h1.cmd("ip link set dev h1-eth0 up")
        # Clear dataplane first so spoofed packets must hit controller.
        clear_switch_flows()
        time.sleep(0.3)

        # Deterministic relearn trigger:
        # send ARP-broadcast traffic from spoofed MAC by pinging an unused subnet IP.
        # This does not depend on successful replies.
        h1.cmd("ip neigh flush all >/dev/null 2>&1")
        h1.cmd("ping -c 5 -i 0.05 -W 1 10.0.0.254 >/dev/null 2>&1")
        # Add a short unicast burst too (helps in noisy environments).
        h1.cmd("arp -s 10.0.0.3 00:00:00:00:00:03")
        h1.cmd("ping -c 8 -i 0.05 -W 1 10.0.0.3 >/dev/null 2>&1")
        time.sleep(0.7)

        clear_switch_flows()
        time.sleep(0.5)

        post_loss = ping_loss(h3, VICTIM_IP, count=3)
        h3.cmd("ping -c 1 10.0.0.2 >/dev/null 2>&1")
        time.sleep(0.5)
        post_outputs = get_s1_outputs_for_victim_mac()

    finally:
        net.stop()
        stop_controller(controller)
        subprocess.run(["mn", "-c"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    logs = log_path.read_text(encoding="utf-8", errors="replace")
    host_move_violation = "Violation: Host Move from switch" in logs

    return TrialResult(
        name=name,
        pre_loss=pre_loss,
        post_loss=post_loss,
        attacker_port=attacker_port,
        victim_port=victim_port,
        pre_outputs=pre_outputs,
        post_outputs=post_outputs,
        host_move_violation=host_move_violation,
        log_file=log_path,
    )


def main() -> int:
    if os.geteuid() != 0:
        print("Run with sudo: sudo python3 hlh_auto.py")
        return 2

    baseline = run_trial("baseline", BASELINE_APP)
    topoguard = run_trial("topoguard", TOPOGUARD_APP)

    print("HLH A/B comparison (victim MAC forwarding on s1):")
    print(
        f"baseline: pre_loss={baseline.pre_loss} post_loss={baseline.post_loss} "
        f"pre_outputs={sorted(baseline.pre_outputs)} post_outputs={sorted(baseline.post_outputs)} "
        f"attacker_port={baseline.attacker_port} victim_port={baseline.victim_port} "
        f"host_move_violation={baseline.host_move_violation} log={baseline.log_file}"
    )
    print(
        f"topoguard: pre_loss={topoguard.pre_loss} post_loss={topoguard.post_loss} "
        f"pre_outputs={sorted(topoguard.pre_outputs)} post_outputs={sorted(topoguard.post_outputs)} "
        f"attacker_port={topoguard.attacker_port} victim_port={topoguard.victim_port} "
        f"host_move_violation={topoguard.host_move_violation} log={topoguard.log_file}"
    )

    baseline_pre_ok = baseline.victim_port in baseline.pre_outputs
    baseline_poisoned = baseline.attacker_port in baseline.post_outputs
    baseline_disrupted = baseline.post_loss > (baseline.pre_loss + 5)
    baseline_not_detected = not baseline.host_move_violation
    topoguard_detected = topoguard.host_move_violation

    if baseline_pre_ok and baseline_not_detected and topoguard_detected and (
        baseline_poisoned
    ):
        print("result=PASS")
        print(
            "observed=baseline accepted spoof (no host-move violation) with either "
            "victim-MAC redirection or measurable disruption; topoguard logged host-move violation"
        )
        return 0

    print("result=FAIL")
    print(
        f"baseline_pre_ok={baseline_pre_ok} baseline_poisoned={baseline_poisoned} "
        f"baseline_disrupted={baseline_disrupted} baseline_not_detected={baseline_not_detected} "
        f"topoguard_detected={topoguard_detected}"
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
