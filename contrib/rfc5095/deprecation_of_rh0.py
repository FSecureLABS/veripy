from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase


class RH0WithSegmentsLeftEqualToZeroToRUTTestCase(ComplianceTestCase):
    """
    Deprecation of RH0 - Segments Left = 0, sent to UUT

    Verify that if Segments Left is zero, the UUT processes the next
    header.

    @private
    Test Procedure:     1) TN1 sends an ICMPv6 Echo Request to the RUT,
                           with a Routing  header, with type 0 and segments
                           left = 0.
	                2) Observe the packets sent by the RUT.

    Expected Result:    2) The RUT should respond to the Echo Request.

    Possible Problems:  None
    """

    def run(self):
        self.logger.info("Sending ICMPv6 Echo Request with RH0, segments left = 0")
        self.node(1).send( \
            IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()))/
                IPv6ExtHdrRouting(segleft=0, addresses=[])/
                    ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking for reply")
        r1 = self.node(1).received(src=self.target(1).link_local_ip(), seq=self.seq(), type=ICMPv6EchoReply)

        assertEqual(1, len(r1), "expected to receive an ICMPv6 Echo Reply from the UUT")


class RH0WithSegmentsLeftEqualToZeroToTN4TestCase(ComplianceTestCase):
    """
    Deprecation of RH0 - Segments Left = 0, send to TN4

    Verify that if Segments Left is zero, the UUT processes the next
    header.

    @private
    Test Procedure:     1) TN1 sends an ICMPv6 Echo Request to TN4, with
                           a Routing  header, with type 0 and segments
                           left = 0.
	                2) Observe the packets sent by the RUT.

    Expected Result:    2) The RUT should respond to the Echo Request.

    Possible Problems:  None
    """

    def run(self):
        self.logger.info("Sending ICMPv6 Echo Request with RH0, segments left = 0")
        self.node(1).send( \
            IPv6(src=str(self.node(1).global_ip()), dst=str(self.node(4).global_ip()))/
                IPv6ExtHdrRouting(segleft=0, addresses=[])/
                    ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking for reply")
        r1 = self.node(4).received(src=self.node(1).global_ip(), seq=self.seq(), type=ICMPv6EchoRequest)

        assertEqual(1, len(r1), "expected the ICMPv6 Echo Request to be forwarded to TN4")


class RH0WithSegmentsLeftGreaterThanZeroToRUTTestCase(ComplianceTestCase):
    """
    Deprecation of RH0 - Segments Left > 0, send to UUT

    Verify that if Segments Left is greater than zero, the UUT processes
    silently discards the packet, and does not process the next header.

    @private
    Test Procedure:     1) TN1 sends an ICMPv6 Echo Request to the TN4,
                           with a Routing  header, with type 0 and a next
                           hop through the RUT (segments left = 1).
	                2) Observe the packets sent by the RUT.

    Expected Result:    2) The RUT should not respond to the Echo Request,
                           and should send a Parameter Problem with code 0
                           and a pointer to the invalid routing type.

    Possible Problems:  None
    """

    def run(self):
        self.logger.info("Sending ICMPv6 Echo Request with RH0, segments left = 0")
        self.node(1).send( \
            IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()))/
                IPv6ExtHdrRouting(segleft=1, addresses=[str(self.target(1).link_local_ip())])/
                    ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking for reply")
        r1 = self.node(1).received(src=self.target(1).link_local_ip(), seq=self.seq(), type=ICMPv6EchoReply)

        assertEqual(0, len(r1), "did not expect to receive an ICMPv6 Echo Reply from the UUT")


class RH0WithSegmentsLeftGreaterThanZeroToTN4TestCase(ComplianceTestCase):
    """
    Deprecation of RH0 - Segments Left > 0, send to TN4

    Verify that if Segments Left is greater than zero, the UUT processes
    silently discards the packet, and does not process the next header.

    @private
    Test Procedure:     1) TN1 sends an ICMPv6 Echo Request to the TN4,
                           with a Routing  header, with type 0 and a next
                           hop through the RUT (segments left = 1).
	                2) Observe the packets sent by the RUT.

    Expected Result:    2) The RUT should not respond to the Echo Request,
                           and should send a Parameter Problem with code 0
                           and a pointer to the invalid routing type.

    Possible Problems:  None
    """

    def run(self):
        self.logger.info("Sending ICMPv6 Echo Request with RH0, segments left = 0")
        self.node(1).send( \
            IPv6(src=str(self.node(1).global_ip()), dst=str(self.node(4).global_ip()))/
                IPv6ExtHdrRouting(segleft=1, addresses=[str(self.target(1).link_local_ip())])/
                    ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking for reply")
        r1 = self.node(4).received(src=self.node(1).global_ip(), seq=self.seq(), type=ICMPv6EchoRequest)

        assertEqual(0, len(r1), "did not expect the ICMPv6 Echo Request to be forwarded to TN4")
