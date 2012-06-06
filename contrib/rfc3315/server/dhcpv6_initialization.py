from contrib.rfc3315.builder import *
from contrib.rfc3315.constants import *
from contrib.rfc3315.dhcpv6 import DHCPv6Helper
from scapy.all import *
from veripy.assertions import *

class DHCPv6InitializationTestCase(DHCPv6Helper):
    """
    DHCPv6 Initialization
    
    Verify that a server can properly interoperate while using DHCPv6.
    
    @private
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 1.1)
    """
    
    def run(self):
        self.logger.info("Building a DHCPv6 Solicit message")
        s = self.build_dhcpv6_solicit(self.node(1))

        self.logger.info("Sending the DHCPv6 Solicit message, to request addressing parameters...")
        self.node(1).send(IPv6(src=str(self.node(1).link_local_ip()), dst=AllDHCPv6RelayAgentsAndServers)/UDP(sport=DHCPv6SourcePort, dport=DHCPv6DestPort)/s)
                            
        self.logger.info("Checking for a DHCPv6 Advertise message...")
        r1 = self.node(1).received(src=str(self.target(1).link_local_ip()), type=DHCP6_Advertise)
        assertEqual(1, len(r1), "expected to receive a DHCPv6 Advertise")
        a = r1[0]

        assertHasLayer(DHCP6OptIA_NA, a, "expected the DHCPv6 Advertise to contain an IA")
        assertHasLayer(DHCP6OptIAAddress, a, "expected the IA to contain an Address")

        self.logger.info("Building a DHCPv6 Request message...")
        q = self.build_dhcpv6_request(a, self.target(1), self.node(1))

        self.logger.info("Sending the DHCPv6 Request message...")
        self.node(1).send(IPv6(src=str(self.node(1).link_local_ip()), dst=AllDHCPv6RelayAgentsAndServers)/UDP(sport=DHCPv6SourcePort, dport=DHCPv6DestPort)/q)

        self.logger.info("Checking for a DHCPv6 Reply message...")
        r2 = self.node(1).received(src=str(self.target(1).link_local_ip()),dst=str(self.node(1).link_local_ip()), type=DHCP6_Reply)
        assertEqual(1, len(r2), "expected to receive a DHCPv6 Reply")
        p = r2[0]

        assertHasLayer(DHCP6OptIA_NA, p, "expected the DHCPv6 Reply to contain an IA")
        assertHasLayer(DHCP6OptIAAddress, p, "expected the IA to contain an Address")
        assertEqual(q[DHCP6OptIAAddress].addr, p[DHCP6OptIAAddress].addr, "expected the IA to contain the requested address")
        