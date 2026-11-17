
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel

from topology.topology import SDNTopo


def run():

    net = Mininet(
        topo=SDNTopo(),
        controller=RemoteController,
        switch=OVSSwitch,
        autoSetMacs=True
    )

    net.start()

    # Configure router r1
    r1 = net.get('r1')
    r1.cmd('ip addr add 10.0.1.1/24 dev r1-eth0')
    r1.cmd('ip addr add 10.0.12.1/30 dev r1-eth1')
    r1.cmd('sysctl -w net.ipv4.ip_forward=1')
    r1.cmd('ip route add 10.0.2.0/24 via 10.0.12.2')

    # Configure router r2
    r2 = net.get('r2')
    r2.cmd('ip addr add 10.0.12.2/30 dev r2-eth0')
    r2.cmd('ip addr add 10.0.2.1/24 dev r2-eth1')
    r2.cmd('sysctl -w net.ipv4.ip_forward=1')
    r2.cmd('ip route add 10.0.1.0/24 via 10.0.12.1')

    # Configure host default gateways
    for host in ['h1', 'h2']:
        net.get(host).cmd('ip route add default via 10.0.1.1')

    for host in ['h3', 'h4']:
        net.get(host).cmd('ip route add default via 10.0.2.1')

    print("\nNetwork is ready. Entering Mininet CLI...\n")

    CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    run()
