from contrib.rfc3315.constants import *
from contrib.rfc3315.dhcpv6 import DHCPv6Helper
from scapy.all import *
from veripy.assertions import *

class TransmissionOfAdvertisementWithNoAddrsAvailableTestCase(DHCPv6Helper):
    """
    Transmission of Advertisements with NoAddrsAvailable

    Verify that a client properly handles Advertise messages with a status
    code of 0x002 (NoAddrsAvail).

    @private
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 1.7)
    """

    def run(self):
        self.ui.tell("Please restart the UUT's network interface.")
        assertTrue(self.ui.ask("Has the interface restarted?"))

        self.logger.info("Checking for a DHCPv6 Solicit message...")
        r1 = self.node(1).received(src=str(self.target(1).link_local_ip()), dst=AllDHCPv6RelayAgentsAndServers, type=DHCP6_Solicit)
        assertGreaterThanOrEqualTo(1, len(r1), "expected to receive a DHCPv6 Solicit message")
        s = r1[0][UDP]

        self.logger.info("Building a DHCPv6 Advertisement for the client")
        a = self.build_dhcpv6_advertisement(s, self.node(1), self.target(1), options=False, ias=False)
        self.logger.info("Adding a Status Code of 0x0002 (NoAddrsAvail)")
        a/DHCP6OptStatusCode(statuscode=0x0002)
        
        self.logger.info("Sending the DHCPv6 Advertise message, offering no addressing parameters...")
        self.node(1).send(IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()))/UDP(sport=s.dport, dport=s.sport)/a)

        self.logger.info("Waiting for the UUT to respond to the DHCPv6 Advertisement...")
        r2 = self.node(1).received(src=str(self.target(1).link_local_ip()), dst=AllDHCPv6RelayAgentsAndServers, type=DHCP6_Request)
        assertGreaterThanOrEqualTo(0, len(r2), "did not expect to receive a DHCPv6 Request")
        
        self.logger.info("Waiting for the UUT to configure its interface...")
        self.ui.wait(5)

        self.node(1).clear_received()
        self.logger.info("Sending an ICMPv6 Echo Request to the UUT's released address...")
        self.node(1).send( \
            IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).global_ip()))/
                ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking for an ICMPv6 Echo Reply from the UUT...")
        r2 = self.node(1).received(src=str(self.target(1).global_ip()), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(0, len(r2), "did not expect to receive an ICMPv6 Echo Reply")
