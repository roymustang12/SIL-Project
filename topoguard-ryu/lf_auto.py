#!/usr/bin/env python3
"""A/B comparison: insecure baseline vs TopoGuard under LLDP forgery attack.

Runs the same scenario against both controllers and compares reachability from
h3 -> h2 before and after forged LLDP injection from h1.
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

from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, RemoteController

from topology import TopoGuardTopo


ROOT = Path(__file__).resolve().parent
TOPOGUARD_APP = ROOT / "topoguard_ryu.py"
BASELINE_APP = ROOT / "insecure_baseline_ryu.py"
ATTACK_SCRIPT = ROOT / "attacks" / "send_fake_lldp.py"


@dataclass
class TrialResult:
    name: str
    pre_loss: int
    post_loss: int
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
    m = re.search(r"(\d+)%\s+packet loss", ping_output)
    if not m:
        return 100
    return int(m.group(1))


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


def run_trial(name: str, app_path: Path) -> TrialResult:
    setLogLevel("warning")
    subprocess.run(["mn", "-c"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    log_path = ROOT / f"lf_{name}.log"
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

        h1 = net.get("h1")
        h2 = net.get("h2")
        h3 = net.get("h3")

        # Learn host locations/topology in both directions.
        h2.cmd("ping -c 2 10.0.0.3 >/dev/null 2>&1")
        h3.cmd("ping -c 2 10.0.0.2 >/dev/null 2>&1")
        # Pin ARP entries so post-attack probes use unicast and must follow
        # controller-selected inter-switch path (no broadcast fallback).
        h2.cmd("arp -s 10.0.0.3 00:00:00:00:00:03")
        h3.cmd("arp -s 10.0.0.2 00:00:00:00:00:02")

        # Wait for convergence; baseline can need a few packets before stable.
        pre_loss = 100
        for _ in range(4):
            pre_loss = min(pre_loss, ping_loss(h3, "10.0.0.2", count=2))
            if pre_loss == 0:
                break
            time.sleep(1)

        # Forged LLDP poisoning attempt from h1:
        # pretend traffic from s2 should use its host-facing port 1.
        h1.cmd(f"python3 {ATTACK_SCRIPT} h1-eth0 --remote-dpid 2 --remote-port 1")
        time.sleep(0.5)

        # Force fresh forwarding decisions.
        clear_switch_flows()
        time.sleep(1)

        post_loss = ping_loss(h3, "10.0.0.2", count=3)

    finally:
        net.stop()
        stop_controller(controller)
        subprocess.run(["mn", "-c"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    return TrialResult(name=name, pre_loss=pre_loss, post_loss=post_loss, log_file=log_path)


def main() -> int:
    baseline = run_trial("baseline", BASELINE_APP)
    topoguard = run_trial("topoguard", TOPOGUARD_APP)

    print("AB comparison (h3 -> h2 ping packet loss %):")
    print(f"baseline: pre={baseline.pre_loss} post={baseline.post_loss} log={baseline.log_file}")
    print(f"topoguard: pre={topoguard.pre_loss} post={topoguard.post_loss} log={topoguard.log_file}")

    baseline_failed = baseline.pre_loss <= 50 and baseline.post_loss >= 90
    topoguard_survived = topoguard.pre_loss <= 50 and topoguard.post_loss <= 50

    if baseline_failed and topoguard_survived:
        print("result=PASS")
        print("observed=baseline poisoned by forged LLDP, TopoGuard remained reachable")
        return 0

    print("result=FAIL")
    print(
        f"baseline_failed={baseline_failed} topoguard_survived={topoguard_survived} "
        f"(see logs above)"
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())