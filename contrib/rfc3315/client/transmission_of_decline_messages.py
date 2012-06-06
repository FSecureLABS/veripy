from contrib.rfc3315.constants import *
from contrib.rfc3315.dhcpv6 import DHCPv6Helper
from scapy.all import *
from veripy.assertions import *

class TransmissionOfDeclineMessagesTestCase(DHCPv6Helper):
    """
    Transmission of Decline Messages

    Verify that a client properly generates a Decline message.

    @private
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 1.6)
    """

    def run(self):
        self.do_dhcpv6_handshake_as_server(self.node(1), self.target(1), wait=False)

        self.logger.info("Waiting for the UUT to perform NS DAD on the assigned address...")
        r1 = self.node(1).received(src="::", dst=self.target(1).global_ip().solicited_node(), type=ICMPv6ND_NS)

        assertGreaterThanOrEqualTo(1, len(r1), "expected the UUT to perform DAD on the assigned address")
        # TODO: we need to respond to the NA faster
        self.logger.info("Sending a Neighbor Advertisement in response to the DAD solicitation...")
        self.node(1).send( \
            IPv6(src=str(self.target(1).global_ip()), dst="ff02::1")/
                ICMPv6ND_NA(tgt=str(self.target(1).global_ip()), R=False, S=True, O=True)/
                    ICMPv6NDOptDstLLAddr(lladdr=self.node(1).iface(0).ll_addr))

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
        