#!/usr/bin/env python3

from mininet.net import Mininet
from mininet.node import OVSSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel, info
from mininet.cli import CLI


def create_topology():
    net = Mininet(
        controller=None,
        switch=OVSSwitch,
        link=TCLink,
        build=False
    )

    h1 = net.addHost("h1", ip="10.0.0.1/24")
    h2 = net.addHost("h2", ip="10.0.0.2/24")
    h3 = net.addHost("h3", ip="10.0.0.3/24")

    s1 = net.addSwitch(
        "s1",
        protocols="OpenFlow13",
        failMode="standalone"
    )

    for host in (h1, h2, h3):
        net.addLink(host, s1)

    net.build()
    net.start()

    info("\n*** SDN test topology started\n")
    info("*** Hosts: h1, h2, h3\n")
    info("*** Switch: s1\n")
    info("*** IPs: 10.0.0.1, 10.0.0.2, 10.0.0.3\n")
    info("*** Type 'pingall' to test connectivity\n")
    info("*** Type 'exit' to stop the topology\n\n")

    CLI(net)
    net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    create_topology()
