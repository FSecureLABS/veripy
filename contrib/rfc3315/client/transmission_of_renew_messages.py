from contrib.rfc3315.constants import *
from contrib.rfc3315.dhcpv6 import DHCPv6Helper
from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase

class TransmissionOfRenewMessagesTestCase(DHCPv6Helper):
    """
    Transmission of Renew Messages
    
    Verify a client properly handles Renew messages.
    
    @private
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 1.3)
    """
    
    def run(self):
        self.do_dhcpv6_handshake_as_server(self.node(1), self.target(1), T1=50, T2=80)

        self.logger.info("Waiting 50s for the renew timer to expire...")
        self.ui.wait(50)
        
        self.logger.info("Expecting the client to have sent a DHCPv6 Renew message...")
        r1 = self.node(1).received(src=str(self.target(1).link_local_ip()), dst=AllDHCPv6RelayAgentsAndServers, type=DHCP6_Renew)
        
        assertGreaterThanOrEqualTo(1, len(r1), "expected to receive a DHCPv6 Renew message")

        n = r1[0]

        assertHasLayer(DHCP6OptIA_NA, n, "expected the DHCPv6 Renew message to have an IA")
        assertHasLayer(DHCP6OptIAAddress, n, "expected the IA to contain an Address")
        assertEqual(self.target(1).global_ip(), n[DHCP6OptIAAddress].addr, "expected the DHCPv6 Client to request the IP address previously assigned")

        self.logger.info("Sending a DHCPv6 reply to the Renew message...")
        self.node(1).send(self.build_dhcpv6_reply(n, self.node(1), self.target(1), T1=50, T2=80))

        self.logger.info("Waiting for the UUT to configure its interface...")
        self.ui.wait(5)

        self.node(1).clear_received()
        self.logger.info("Sending an ICMPv6 Echo Request to the UUT's renewed address...")
        self.node(1).send( \
            IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).global_ip()))/
                ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking for an ICMPv6 Echo Reply from the UUT...")
        r2 = self.node(1).received(src=str(self.target(1).global_ip()), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(1, len(r2), "expected to receive an ICMPv6EchoReply")
        