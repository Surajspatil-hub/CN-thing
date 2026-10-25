#!/usr/bin/env python3
"""Interactive three-host Mininet topology for Segment 2 development."""

from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import info, setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch


def create_topology():
    net = Mininet(
        controller=None,
        switch=OVSSwitch,
        link=TCLink,
        build=False,
    )

    h1 = net.addHost("h1", ip="10.0.0.1/24")
    h2 = net.addHost("h2", ip="10.0.0.2/24")
    h3 = net.addHost("h3", ip="10.0.0.3/24")
    switch = net.addSwitch(
        "s1",
        protocols="OpenFlow13",
        failMode="standalone",
    )

    for host in (h1, h2, h3):
        net.addLink(host, switch)

    try:
        net.build()
        net.start()
        info("\n*** Segment 2 SDN detection topology started\n")
        info("*** Hosts: h1=10.0.0.1, h2=10.0.0.2, h3=10.0.0.3\n")
        info("*** Switch: s1 (standalone mode for detection lab)\n")
        info("*** Run 'pingall' to test connectivity; 'exit' to stop.\n\n")
        CLI(net)
    finally:
        net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    create_topology()
