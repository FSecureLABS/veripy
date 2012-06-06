from scapy.all import *
from veripy.assertions import *
from send_helper import SendHelper

class UUTSendsNSFromLinkLocalWithNonceTestCase(SendHelper):
    """
    SEND Nonce Option - Neighbor solicitation from link local

    Verify the UUT adds the Nonce option to Neighbor solicitations

    @private
    source rfc 3971 5.3.3
    """
    def run(self):
        # Ping it so it sends an NS
        self.node(1).send(IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()))/ICMPv6EchoRequest())

        # Don't care if it replies to ping check for NS
        ns_packets = self.node(1).received(src=self.target(1).link_local_ip(), dst=self.node(1).link_local_ip(), type=ICMPv6ND_NS, timeout=10)
        assertGreaterThanOrEqualTo(1, len(ns_packets), "Expect one NS to be sent" )

        self.logger.info("Received NS")

        self.logger.info("Checking Nonce Layer")
        assertHasLayer(ICMPv6NDOptNO, ns_packets[0], "Expected NS to contain Nonce Option")

class UUTSendsNSFromUnspecifiedWithNonceTestCase(SendHelper):
    """
    SEND Nonce Option - Neighbor solicitation from ::

    Verify the UUT adds the Nonce option to Neighbor solicitations

    @private
    source rfc 3971 5.3.3
    """
    def run(self):
        self.ui.ask("Please press Y and then restart the interface being tested or restart the UUT. After pressing Y you will have 5 minutes to restart the interface or UUT.")
        ns_packets = self.node(1).received(dst=self.target(1).link_local_ip().solicited_node(), src="::",  type=ICMPv6ND_NS, timeout = 300)

        assertGreaterThanOrEqualTo(1, len(ns_packets), "Expect one NS to be sent" )
        self.logger.info("Received NS")

        self.logger.info("Checking Nonce Layer")
        assertHasLayer(ICMPv6NDOptNO, ns_packets[0], "Expected NS to contain Nonce Option")

class UUTSendsNAFromLinkLocalWithNonceOptionTestCase(SendHelper):
    """
    SEND Nonce Option - Neighbor Advertisement from link local

    Verify the UUT adds the Nonce option to Neighbor Advertisement

    @private
    source rfc 3971 5.3.3
    """
    def run(self):
        packet_to_send = self.construct_valid_sign_ns()
        self.node(1).send(packet_to_send)
        
        na_packets = self.node(1).received(src=self.target(1).link_local_ip(), dst=self.cga_ip, type=ICMPv6ND_NA)
        assertGreaterThanOrEqualTo(1, len(na_packets), "Expect one NA to be sent" )

        self.logger.info("Received NA")

        self.logger.info("Checking Nonce Layer")
        assertHasLayer(ICMPv6NDOptNO, na_packets[0], "Expected NS to contain Nonce Option")

class UUTSendsRSFromLinkLocalWithNonceOptionTestCase(SendHelper):
    """
    SEND Nonce Option - Router solicitation from link local

    Verify the UUT adds the Nonce option to Router solicitations

    @private
    source rfc 3971 5.3.3
    """
    def run(self):
        self.ui.ask("Please press Y and then restart the interface being tested or restart the UUT. After pressing Y you will have 5 minutes to restart the interface or UUT.")
        rs_packet = self.node(1).received(dst="ff02::02", src=self.target(1).link_local_ip(),  type=ICMPv6ND_RS, timeout = 300)

        assertGreaterThanOrEqualTo(1, len(rs_packet), "Expect one RS to be sent" )
        self.logger.info("Received RS")

        self.logger.info("Checking Nonce Layer")
        assertHasLayer(ICMPv6NDOptNA, rs_packet[0], "Expected RS to contain Nonce Option")


class UUTSendsRAFromLinkLocalWithNonceOptionTestCase(SendHelper):
    """
    SEND Nonce Option - Router Advertisements from link local

    Verify the UUT adds the Nonce option to Router Advertisements

    @private
    source rfc 3971 5.3.3
    """
    def run(self):
        rs_packet = self.ipv6_layer/ICMPv6ND_RS()/ICMPv6NDOptSrcLLAddr(lladdr=self.node(1).iface(0).ll_addr)
        rs_packet = self.add_send_options(rs_packet)
        rs_packet = self.sign(rs_packet, ICMPv6ND_RS)
        self.node(1).send(rs_packet)

        # Don't care if it replies to ping check for NS
        ra_packets = self.node(1).received(src=self.target(1).link_local_ip(), dst="FF02::1", type=ICMPv6ND_RA, timeout=10)
        assertGreaterThanOrEqualTo(1, len(ra_packets), "Expect one RA to be sent" )

        self.logger.info("Received RA")

        self.logger.info("Checking Nonce Layer")
        assertHasLayer(ICMPv6NDOptNO, ra_packets[0], "Expected RA to contain Nonce Option")

        self.logger.info("Check NONCE is same as in solicitation")
        assertEqual(rs_packet[ICMPv6NDOptNO].nonce, ra_packets[0][ICMPv6NDOptNO].nonce, "Expected Nonce to be same")
