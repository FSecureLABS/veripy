from contrib.rfc3315.constants import *
from contrib.rfc3315.dhcpv6 import DHCPv6Helper
from scapy.all import *
from veripy.assertions import *

class TransmissionOfConfirmMessagesTestCase(DHCPv6Helper):
    """
    Client Initiated: Transmission of Confirm Messages
    
    Verify a client properly handles Confirm messages.
    
    @private
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 1.2)
    """
    
    def run(self):
        self.do_dhcpv6_handshake_as_server(self.node(1), self.target(1))

        self.logger.info("Sending an ICMPv6 Echo Request to the UUT's newly configured address...")
        self.node(1).send( \
            IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).global_ip()))/
                ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking for an ICMPv6 Echo Reply from the UUT...")
        r3 = self.node(1).received(src=str(self.target(1).global_ip()), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(1, len(r3), "expected to receive an ICMPv6EchoReply")
        
        self.node(1).clear_received()
        
        self.ui.tell("Disconnect the UUT until it registers a lost connection. Then reconnect it.")
        assertTrue(self.ui.ask("Has the UUT reconfigured its interface?"))

        self.logger.info("Checking for a DHCPv6 Confirm message...")
        r4 = self.node(1).received(src=str(self.target(1).link_local_ip()), dst=AllDHCPv6RelayAgentsAndServers, type=DHCP6_Confirm)
        assertEqual(1, len(r4), "expected to receive a DHCPv6 Confirm")

        assertHasLayer(DHCP6OptIA_NA, r4[0], "expected the DHCPv6 Confirm message to have an IA")
        assertHasLayer(DHCP6OptIAAddress, r4[0], "expected the IA to contain an Address")
        assertEqual(self.target(1).global_ip(), q[DHCP6OptIAAddress].addr, "expected the DHCPv6 Client to request the IP address previously assigned")
        
        self.node(1).clear_received()
        self.logger.info("Sending an ICMPv6 Echo Request to the UUT's reconfigured address...")
        self.node(1).send( \
            IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).global_ip()))/
                ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking for an ICMPv6 Echo Reply from the UUT...")
        r5 = self.node(1).received(src=str(self.target(1).global_ip()), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(1, len(r5), "expected to receive an ICMPv6EchoReply")
        