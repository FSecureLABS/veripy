from scapy.all import *
from veripy.assertions import *
from send_helper import SendHelper

class UUTSendsNSFromLinkLocalWithCGAOptionTestCase(SendHelper):
    """
    SEND CGA Option - Neighbor solicitation from link local

    Verify the UUT adds the CGA option to Neighbor solicitations

    @private
    source rfc 3971 5.1.1
    """
    def run(self):
        # Ping it so it sends an NS
        self.node(1).send(IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()))/ICMPv6EchoRequest())

        # Don't care if it replies to ping check for NS
        cga_packets = self.node(1).received(src=self.target(1).link_local_ip(), dst=self.node(1).link_local_ip(), type=ICMPv6ND_NS, timeout=10)
        assertGreaterThanOrEqualTo(1, len(cga_packets), "Expect one NS to be sent" )

        self.logger.info("Received NS")

        self.logger.info("Checking CGA Layer")
        assertHasLayer(ICMPv6NDOptCGA, cga_packets[0], "Expected NS top contain CGA Option")



class UUTSendsNAFromLinkLocalWithCGAOptionTestCase(SendHelper):
    """
    SEND CGA Option - Neighbor Advertisement from link local

    Verify the UUT adds the CGA option to Neighbor Advertisement

    @private
    source rfc 3971 5.1.1
    """
    def run(self):
        packet_to_send = self.construct_valid_sign_ns()
        self.node(1).send(packet_to_send)

        cga_packets = self.node(1).received(src=self.target(1).link_local_ip(), dst=self.cga_ip, type=ICMPv6ND_NA)
        assertGreaterThanOrEqualTo(1, len(cga_packets), "Expect one NA to be sent" )

        self.logger.info("Received NS")
        self.logger.info("Checking CGA Layer")
        assertHasLayer(ICMPv6NDOptCGA, cga_packets[0], "Expected NA top contain CGA Option")

class UUTSendsNSFromUnspecifiedWithCGAOptionTestCase(SendHelper):
    """
    SEND CGA Option - Neighbor Solicitation from ::

    Verify the UUT adds the CGA option to Neighbor Solicitation

    @private
    source rfc 3971 5.1.1
    """
    def run(self):
        self.ui.ask("Please press Y and then restart the interface being tested or restart the UUT. After pressing Y you will have 5 minutes to restart the interface or UUT.")
        ns_packet = self.node(1).received(dst=self.target(1).link_local_ip().solicited_node(), src="::",  type=ICMPv6ND_NS, timeout = 300)

        assertGreaterThanOrEqualTo(1, len(ns_packet), "Expect one NS to be sent" )
        self.logger.info("Received NS")

        self.logger.info("Checking CGA Layer")
        assertHasLayer(ICMPv6NDOptCGA, ns_packet[0], "Expected NS from unspecified to contain CGA Option")

class UUTSendsRSFromLinkLocalWithCGAOptionTestCase(SendHelper):
    """
    SEND CGA Option - Router Solicitation from link local

    Verify the UUT adds the CGA option to Router Solicitation

    @private
    source rfc 3971 5.1.1
    """
    def run(self):
        self.ui.ask("Please press Y and then restart the interface being tested or restart the UUT. After pressing Y you will have 5 minutes to restart the interface or UUT.")
        rs_packet = self.node(1).received(dst="ff02::02", src=self.target(1).link_local_ip(),  type=ICMPv6ND_RS, timeout = 300)

        assertGreaterThanOrEqualTo(1, len(rs_packet), "Expect one RS to be sent" )
        self.logger.info("Received RS")

        self.logger.info("Checking CGA Layer")
        assertHasLayer(ICMPv6NDOptCGA, rs_packet[0], "Expected RS to contain CGA Option")


