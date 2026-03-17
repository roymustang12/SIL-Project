#!/usr/bin/env python3
"""Reusable Mininet topology launcher for TopoGuard-Ryu experiments.

Default topology:
- 2 Open vSwitches (`s1`, `s2`) with fixed DPIDs
- Inter-switch link (`s1` <-> `s2`)
- 3 hosts:
  - `h1`, `h2` on `s1` (edge hosts)
  - `h3` on `s2` (remote host)
- Remote controller at 127.0.0.1:6653
"""

from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import info, setLogLevel
from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, RemoteController
from mininet.topo import Topo


class TopoGuardTopo(Topo):
    def build(self):
        # Fixed DPIDs make LLDP forgery scenarios reproducible.
        s1 = self.addSwitch("s1", dpid="0000000000000001", protocols="OpenFlow13")
        s2 = self.addSwitch("s2", dpid="0000000000000002", protocols="OpenFlow13")

        h1 = self.addHost("h1", ip="10.0.0.1/24", mac="00:00:00:00:00:01")
        h2 = self.addHost("h2", ip="10.0.0.2/24", mac="00:00:00:00:00:02")
        h3 = self.addHost("h3", ip="10.0.0.3/24", mac="00:00:00:00:00:03")

        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s2)
        self.addLink(s1, s2)


def run_topology(controller_ip: str = "127.0.0.1", controller_port: int = 6653) -> None:
    topo = TopoGuardTopo()

    net = Mininet(
        topo=topo,
        controller=None,
        switch=OVSKernelSwitch,
        link=TCLink,
        autoSetMacs=False,
        autoStaticArp=False,
        build=False,
    )

    c0 = RemoteController("c0", ip=controller_ip, port=controller_port)
    net.addController(c0)

    info("*** Building and starting network\n")
    net.build()
    net.start()

    info("*** Topology ready. Useful checks:\n")
    info("***   mininet> pingall\n")
    info("***   mininet> nodes\n")

    CLI(net)

    info("*** Stopping network\n")
    net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    run_topology()
