from mininet.topo import Topo


class SDNTopo(Topo):

    def build(self):

        # Hosts
        h1 = self.addHost('h1', ip='10.0.1.11/24')
        h2 = self.addHost('h2', ip='10.0.1.66/24')

        h3 = self.addHost('h3', ip='10.0.2.10/24')
        h4 = self.addHost('h4', ip='10.0.2.11/24')

        # Routers (no default IP addresses)
        r1 = self.addHost('r1', ip=None)
        r2 = self.addHost('r2', ip=None)

        # Open vSwitch switches
        s1 = self.addSwitch('s1', protocols='OpenFlow13')
        s2 = self.addSwitch('s2', protocols='OpenFlow13')

        # Subnet A
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(s1, r1)

        # Router-to-router connection
        self.addLink(r1, r2)

        # Subnet C
        self.addLink(r2, s2)
        self.addLink(s2, h3)
        self.addLink(s2, h4)


topos = {
    'sdn': lambda: SDNTopo()
}

