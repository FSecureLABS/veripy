from contrib.rfc3315.constants import *
from contrib.rfc3315.dhcpv6 import DHCPv6Helper
from scapy.all import *
from veripy.assertions import *


class DHCPv6InitializationTestCase(DHCPv6Helper):
    """
    DHCPv6 Initialization
    
    Verify that a device can properly interoperate while using DHCPv6.
    
    @private
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 1.1)
    """
    
    def run(self):
        self.ui.tell("Please restart the UUT's network interface.")
        assertTrue(self.ui.ask("Has the interface restarted?"))

        self.logger.info("Checking for a DHCPv6 Solicit message...")
        r1 = self.node(1).received(src=str(self.target(1).link_local_ip()), dst=AllDHCPv6RelayAgentsAndServers, type=DHCP6_Solicit)
        assertGreaterThanOrEqualTo(1, len(r1), "expected to receive a DHCPv6 Solicit message")
        s = r1[0][UDP]

        self.logger.info("Building a DHCPv6 Advertisement for the client")
        a = self.build_dhcpv6_advertisement(s, self.node(1), self.target(1))

        self.logger.info("Sending the DHCPv6 Advertise message, to offer the client addressing parameters...")
        self.node(1).send(IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()))/UDP(sport=s.dport, dport=s.sport)/a)

        self.logger.info("Waiting for the UUT to respond to the DHCPv6 Advertisement...")
        r2 = self.node(1).received(src=str(self.target(1).link_local_ip()), dst=AllDHCPv6RelayAgentsAndServers, type=DHCP6_Request)
        assertGreaterThanOrEqualTo(1, len(r2), "expected to receive a DHCPv6 Request")
        q = r2[0][UDP]
        
        assertHasLayer(DHCP6OptIA_NA, q, "expected the DHCPv6 Request to contain an IA")
        assertHasLayer(DHCP6OptIAAddress, q, "expected the IA to contain an Address")
        assertEqual(self.target(1).global_ip(), q[DHCP6OptIAAddress].addr, "expected the DHCPv6 Client to request the IP address offered")

        self.logger.info("Building a DHCPv6 Reply message, to confirm the client's addressing parameters...")
        p = self.build_dhcpv6_reply(q, self.node(1), self.target(1))

        self.logger.info("Sending the DHCPv6 Reply message...")
        self.node(1).send(IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()))/UDP(sport=s.dport, dport=s.sport)/p)

        self.logger.info("Waiting for the UUT to configure its network interface...")
        self.ui.wait(5)
        
        self.logger.info("Sending an ICMPv6 Echo Request to confirm the interfaces configuration...")
        self.node(1).send( \
            IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).global_ip()))/
                ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Waiting for a response to the Echo Request...")
        r3 = self.node(1).received(src=str(self.target(1).global_ip()), seq=self.seq(), type=ICMPv6EchoReply)

        assertEqual(1, len(r3), "expected to receive an ICMPv6 Echo Reply")
        