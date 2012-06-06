from scapy.all import *
from veripy.assertions import *
from send_helper import SendHelper

class UUTSendsNSFromLinkLocalWithRSAOptionTestCase(SendHelper):
    """
    SEND RSA Option - Neighbor solicitation from link local

    Verify the UUT adds the RSA option to Neighbor solicitations

    @private
    source rfc 3971 5.2.1
    """
    def run(self):
        # Ping it so it sends an NS
        self.node(1).send(IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()))/ICMPv6EchoRequest())

        # Don't care if it replies to ping check for NS
        cga_packets = self.node(1).received(src=self.target(1).link_local_ip(), dst=self.node(1).link_local_ip(), type=ICMPv6ND_NS, timeout=10)
        assertGreaterThanOrEqualTo(1, len(cga_packets), "Expect one NS to be sent" )

        self.logger.info("Received NS")

        self.logger.info("Checking RSA Layer")
        assertHasLayer(ICMPv6NDOptRSA, cga_packets[0], "Expected NS to contain RSA Option")

        self.logger.info("Verifying RSA Signature Option")
        assertEqual(0, cga_packets[0][ICMPv6NDOptRSA].res, "Expect Reserved to be 0")

        self.logger.info("Verifying signature")
        assertEqual(1, self.verify_signature(cga_packets[0], ICMPv6ND_NS))

        self.logger.info("Verifying RSA Option is last layer")
        # Check it is the last option
        assertEqual(0, len(cga_packets[0][ICMPv6NDOptRSA].payload), "Expected RSA signature Option to be last layer")

class UUTSendsNSFromUnspecifiedWithRSAOptionTestCase(SendHelper):
    """
    SEND RSA Option - Neighbor solicitation from ::

    Verify the UUT adds the RSA option to Neighbor solicitations

    @private
    source rfc 3971 5.2.1
    """
    def run(self):
        self.ui.ask("Please press Y and then restart the interface being tested or restart the UUT. After pressing Y you will have 5 minutes to restart the interface or UUT.")
        ns_packets = self.node(1).received(dst=self.target(1).link_local_ip().solicited_node(), src="::",  type=ICMPv6ND_NS, timeout = 300)

        assertGreaterThanOrEqualTo(1, len(ns_packets), "Expect one NS to be sent" )
        self.logger.info("Received NS")

        self.logger.info("Checking RSA Layer")
        assertHasLayer(ICMPv6NDOptRSA, ns_packets[0], "Expected NS to contain RSA Option")

        self.logger.info("Verifying RSA Signature Option")
        assertEqual(0, ns_packets[0][ICMPv6NDOptRSA].res, "Expect Reserved to be 0")

        self.logger.info("Verifying signature")
        assertEqual(1, self.verify_signature(ns_packets[0], ICMPv6ND_NS))

        self.logger.info("Verifying RSA Option is last layer")
        # Check it is the last option
        assertEqual(0, len(ns_packets[0][ICMPv6NDOptRSA].payload), "Expected RSA signature Option to be last layer")

class UUTSendsNAFromLinkLocalWithRSAOptionTestCase(SendHelper):
    """
    SEND RSA Option - Neighbor Advertisement from link local

    Verify the UUT adds the RSA option to Neighbor Advertisement

    @private
    source rfc 3971 5.2.1
    """
    def run(self):
        packet_to_send = self.construct_valid_sign_ns()
        self.node(1).send(packet_to_send)

        cga_packets = self.node(1).received(src=self.target(1).link_local_ip(), dst=self.cga_ip, type=ICMPv6ND_NA)
        assertGreaterThanOrEqualTo(1, len(cga_packets), "Expect one NA to be sent" )

        self.logger.info("Received NA")
        self.logger.info("Checking RSA Layer")
        assertHasLayer(ICMPv6NDOptRSA, cga_packets[0], "Expected NA top contain CGA Option")

        self.logger.info("Verifying signature")
        assertEqual(1, self.verify_signature(cga_packets[0], ICMPv6ND_NA))
        self.logger.info("Verifying RSA Option is last layer")

        # Check it is the last option
        assertEqual(0, len(cga_packets[0][ICMPv6NDOptRSA].payload), "Expected RSA signature Option to be last layer")

#Host only
class UUTSendsRSFromLinkLocalWithRSAOptionTestCase(SendHelper):
    """
    SEND RSA Option - Router Solicitation from link local

    Verify the UUT adds the RSA option to Router Solicitations

    @private
    source rfc 3971 5.2.1
    """
    def run(self):
        self.ui.ask("Please press Y and then restart the interface being tested or restart the UUT. After pressing Y you will have 5 minutes to restart the interface or UUT.")
        rs_packets = self.node(1).received(dst="ff02::02", src=self.target(1).link_local_ip(),  type=ICMPv6ND_RS, timeout = 300)

        assertGreaterThanOrEqualTo(1, len(rs_packets), "Expect one RS to be sent" )
        self.logger.info("Received RS")

        self.logger.info("Checking RSA Layer")
        assertHasLayer(ICMPv6NDOptRSA, rs_packets[0], "Expected RS to contain RSA Option")


class UUTSendsRAFromLinkLocalWithRSAOptionTestCase(SendHelper):
    """
    SEND RSA Option - Router Advertisement from link local

    Verify the UUT adds the RSA option to Router Advertisement

    @private
    source rfc 3971 5.2.1
    """
    def run(self):
        self.ui.ask("Please configure the router to send Router Advertisements. Press Y to continue")

        # Wait for RA
        cga_packets = self.node(1).received(src=self.target(1).link_local_ip(), dst="FF02::1", type=ICMPv6ND_RA, timeout=60)
        assertGreaterThanOrEqualTo(1, len(cga_packets), "Expect one RA to be sent" )

        self.logger.info("Received RA")

        self.logger.info("Checking RSA Layer")
        assertHasLayer(ICMPv6NDOptRSA, cga_packets[0], "Expected RA top contain CGA Option")

        self.logger.info("Verifying RSA Signature Option")
        assertEqual(0, cga_packets[0][ICMPv6NDOptRSA].res, "Expect Reserved to be 0")

        self.logger.info("Verifying signature")
        assertEqual(1, self.verify_signature(cga_packets[0], ICMPv6ND_RA))

        self.logger.info("Verifying RSA Option is last layer")
        assertEqual(0, len(cga_packets[0][ICMPv6NDOptRSA].payload), "Expected RSA signature Option to be last layer")


