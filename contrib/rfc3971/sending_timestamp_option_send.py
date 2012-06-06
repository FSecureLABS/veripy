from scapy.all import *
from veripy.assertions import *
from send_helper import SendHelper

class UUTSendsNSFromLinkLocalWithTimeStampTestCase(SendHelper):
    """
    SEND Timestamp Option - Neighbor solicitation from link local

    Verify the UUT adds the RSA option to Neighbor solicitations

    @private
    source rfc 3971 5.3.3
    """
    def run(self):
        # Ping it so it sends an NS
        self.node(1).send(IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()))/ICMPv6EchoRequest())

        # Don't care if it replies to ping ' check for NS
        cga_packets = self.node(1).received(src=self.target(1).link_local_ip(), dst=self.node(1).link_local_ip(), type=ICMPv6ND_NS, timeout=10)
        assertGreaterThanOrEqualTo(1, len(cga_packets), "Expect one NS to be sent" )

        self.logger.info("Received NS")

        self.logger.info("Checking Timestamp Layer")
        assertHasLayer(ICMPv6NDOptTS, cga_packets[0], "Expected NS to contain Timestamp Option")


class UUTSendsNSFromUnspecifiedWithTimeStampTestCase(SendHelper):
    """
    SEND Timestamp Option - Neighbor solicitation from ::

    Verify the UUT adds the RSA option to Neighbor solicitations

    @private
    source rfc 3971 5.3.3
    """
    def run(self):
        self.ui.ask("Please press Y and then restart the interface being tested or restart the UUT. After pressing Y you will have 5 minutes to restart the interface or UUT.")
        ns_packet = self.node(1).received(dst=self.target(1).link_local_ip().solicited_node(), src="::",  type=ICMPv6ND_NS, timeout = 300)

        assertGreaterThanOrEqualTo(1, len(ns_packet), "Expect one NS to be sent" )
        self.logger.info("Received NS")

        self.logger.info("Checking Timestamp Layer")
        assertHasLayer(ICMPv6NDOptTS, ns_packet[0], "Expected NS top contain Timestamp Option")


class UUTSendsNAFromLinkLocalWithTimeStampOptionTestCase(SendHelper):
    """
    SEND Timestamp Option - Neighbor Advertisement from link local

    Verify the UUT adds the RSA option to Neighbor Advertisement

    @private
    source rfc 3971 5.3.3
    """
    def run(self):
        packet_to_send = self.construct_valid_sign_ns()
        self.node(1).send(packet_to_send)

        # Don't care if it replies to ping ' check for NS
        cga_packets = self.node(1).received(src=self.target(1).link_local_ip(), dst=self.cga_ip, type=ICMPv6ND_NA)
        assertGreaterThanOrEqualTo(1, len(cga_packets), "Expect one NA to be sent" )

        self.logger.info("Received NA")

        self.logger.info("Checking Timestamp Layer")
        assertHasLayer(ICMPv6NDOptTS, cga_packets[0], "Expected NA to contain Timestamp Option")
        
class UUTSendsRSFromLinkLocalWithTimeStampTestCase(SendHelper):
    """
    SEND Timestamp Option - Router solicitation from link local

    Verify the UUT adds the RSA option to Router solicitations

    @private
    source rfc 3971 5.3.3
    """
    def run(self):
        self.ui.ask("Please press Y and then restart the interface being tested or restart the UUT. After pressing Y you will have 5 minutes to restart the interface or UUT.")
        rs_packets = self.node(1).received(dst="ff02::02", src=self.target(1).link_local_ip(),  type=ICMPv6ND_RS, timeout = 300)

        assertGreaterThanOrEqualTo(1, len(rs_packets), "Expect one RS to be sent" )
        self.logger.info("Received RS")

        self.logger.info("Checking Timestamp Layer")
        assertHasLayer(ICMPv6NDOptTS, rs_packets[0], "Expected RS top contain Timestamp Option")

# ROuter Only
class UUTSendsRAFromLinkLocalWithTimeStampOptionTestCase(SendHelper):
    """
    SEND Timestamp Option - Router Advertisement from link local

    Verify the UUT adds the RSA option to Router Advertisement

    @private
    source rfc 3971 5.3.3
    """
    def run(self):
        self.ui.ask("Please configure the router to send Router Advertisements. Press Y to continue")

        # Wait for RA
        cga_packets = self.node(1).received(src=self.target(1).link_local_ip(), dst="FF02::1", type=ICMPv6ND_RA, timeout=60)
        assertGreaterThanOrEqualTo(1, len(cga_packets), "Expect one RA to be sent" )

        self.logger.info("Received RA")

        self.logger.info("Checking Timestamp Layer")
        assertHasLayer(ICMPv6NDOptTS, cga_packets[0], "Expected RA to contain Timestamp Option")


    