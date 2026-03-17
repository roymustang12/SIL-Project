#!/usr/bin/env python3
"""Automated TopoGuard safety demonstration.

Run with sudo:
    sudo python3 safety_check.py

It performs:
1. Baseline connectivity (ping)
2. Forged LLDP injection from host port
3. Host move / MAC spoof behavior check

Then it checks controller logs for expected TopoGuard violation messages.
"""

from __future__ import annotations

from datetime import datetime
import os
from pathlib import Path
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
RYU_APP = ROOT / "topoguard_ryu.py"
FAKE_LLDP = ROOT / "attacks" / "send_fake_lldp.py"
LOG_FILE = ROOT / "topoguard_safety.log"


def resolve_ryu_manager() -> str:
    # Under sudo, PATH often drops user-local bin directories.
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


def start_controller() -> subprocess.Popen:
    ryu_manager = resolve_ryu_manager()
    run_cmd = [ryu_manager, str(RYU_APP)]
    if os.geteuid() == 0:
        sudo_user = os.environ.get("SUDO_USER", "yuvraj")
        run_cmd = ["sudo", "-u", sudo_user, "-H"] + run_cmd

    logf = LOG_FILE.open("w", encoding="utf-8")
    proc = subprocess.Popen(
        run_cmd,
        stdout=logf,
        stderr=subprocess.STDOUT,
        cwd=str(ROOT),
    )
    # Keep file handle attached to process object so it stays open.
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


def wait_for_tcp_listener(host: str, port: int, timeout_s: float = 10.0) -> bool:
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


def run_demo() -> tuple[bool, str]:
    setLogLevel("warning")
    # Clean stale Mininet state from previous runs.
    subprocess.run(["mn", "-c"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

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

    controller = start_controller()
    if not wait_for_tcp_listener("127.0.0.1", 6653, timeout_s=12.0):
        stop_controller(controller)
        raise RuntimeError("Controller did not start listening on 127.0.0.1:6653")

    try:
        net.build()
        net.start()
        time.sleep(2)

        h1 = net.get("h1")
        h2 = net.get("h2")
        h3 = net.get("h3")

        # Baseline traffic to populate controller host-port state.
        h1.cmd("ping -c 2 10.0.0.3 >/dev/null 2>&1")

        # Attack 1 (realistic link-fabrication attempt):
        # h1 forges LLDP pretending to be s2:port1 (host-facing side).
        h1.cmd(f"python3 {FAKE_LLDP} h1-eth0 --remote-dpid 2 --remote-port 1")
        time.sleep(1)

        # Attack 2: MAC-move spoof from another host port.
        h2.cmd("ip link set dev h2-eth0 down")
        h2.cmd("ip link set dev h2-eth0 address 00:00:00:00:00:01")
        h2.cmd("ip link set dev h2-eth0 up")
        h2.cmd("ping -c 1 10.0.0.3 >/dev/null 2>&1")
        time.sleep(2)

        # Sanity traffic after attacks.
        h3.cmd("ping -c 1 10.0.0.1 >/dev/null 2>&1")

    finally:
        net.stop()
        stop_controller(controller)
        subprocess.run(["mn", "-c"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    logs = LOG_FILE.read_text(encoding="utf-8", errors="replace")

    checks = {
        "lldp_host_port": "Violation: Receive LLDP packet from HOST port",
        "host_move": "Violation: Host Move from switch",
    }

    missing = [name for name, pattern in checks.items() if pattern not in logs]
    ok = len(missing) == 0

    summary_lines = [
        f"timestamp={datetime.now().isoformat(timespec='seconds')}",
        f"log_file={LOG_FILE}",
    ]
    if ok:
        summary_lines.append("result=PASS")
        summary_lines.append("observed=LLDP host-port + host-move violations")
    else:
        summary_lines.append("result=FAIL")
        summary_lines.append(f"missing_checks={','.join(missing)}")

    return ok, "\n".join(summary_lines)


def main() -> int:
    ok, summary = run_demo()
    print(summary)
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
