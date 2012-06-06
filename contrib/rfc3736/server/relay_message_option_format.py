from contrib.rfc3736.builder import *
from contrib.rfc3736.constants import *
from contrib.rfc3736.dhcpv6 import DHCPv6Helper
from scapy.all import *
from veripy.assertions import *


class RelayMessageOptionFormatTestCase(DHCPv6Helper):
    """
    Relay Message Option Format
    
    Verify that a server transmits a DHCPv6 Relay Message Option wtih the proper format.
    
    @private
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 8.1.9)
    """
    
    def run(self):
        #self.ui.ask("Restart DHCPv6 on the NUT. Enter 'y' and press enter when you have done this.")
        self.logger.info("Sending an Information Request message from TN1.")

        q = self.build_dhcpv6_information_request(self.node(2))
        q = self.build_dhcpv6_relay_forward(q, self.node(2), self.router(1))
        self.router(1).send(IPv6(src=str(self.router(1).iface(1).link_local_ip()), dst=AllDHCPv6RelayAgentsAndServers)/UDP(sport=DHCPv6SourcePort, dport=DHCPv6DestPort)/q, iface=1)

        self.logger.info("Checking for a DHCPv6 Relay Reply message.")
        r2 = self.node(1).received(src=str(self.target(1).link_local_ip()), dst=str(self.router(1).iface(1).link_local_ip()), type=DHCP6_RelayReply)
        assertEqual(1, len(r2), "expected to receive a DHCPv6 Relay Reply")
        p = r2[0]

        self.logger.info("Checking that DHCPv6 Relay Reply Relay Message Option is properly formatted.")
        assertHasLayer(DHCP6OptRelayMsg, p)
        assertHasLayer(DHCP6_Reply, p[DHCP6OptRelayMsg])
        assertEqual(len(p[DHCP6_Reply]), p.optlen)
