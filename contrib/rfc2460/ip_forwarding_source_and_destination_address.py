from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase, IPAddressCollection


class RequestSentToGlobalUnicastTestCase(ComplianceTestCase):
    """
    IP Forwarding - Source and Destination Address - Request sent to
    Global Unicast address

    Verifies that a node properly forwards the ICMPv6 Echo Requests.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.1.10a)
    """

    def run(self):
        self.logger.debug("Sending ICMPv6 echo-request")
        self.node(4).send( \
            IPv6(src=str(self.node(4).global_ip()), dst=str(self.node(1).global_ip()))/
                ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking for a forwarded message...")
        r1 = self.node(1).received(src=self.node(4).global_ip(), seq=self.seq(), type=ICMPv6EchoRequest)

        assertEqual(1, len(r1), "expected the ICMPv6 Echo Request to be forwarded (seq: %d)" % (self.seq()))


class RequestSentToGlobalUnicastPrefixEndsInZeroValueFieldsTestCase(ComplianceTestCase):
    """
    IP Forwarding - Source and Destination Address - Request sent to Global
    Unicast address (prefix end in zero-valued fields)

    Verifies that a node properly forwards the ICMPv6 Echo Requests.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.1.10b)
    """

    pass
 
class RequestSentFromUnspecifiedAddressTestCase(ComplianceTestCase):
    """
    IP Forwarding - Source and Destination Address - Request sent to
    Unspecified address

    Verifies that a node properly forwards the ICMPv6 Echo Requests.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.1.10c)
    """

    def run(self):
        self.logger.debug("Sending ICMPv6 echo-request from the Unspecified address (::)")
        self.node(4).send( \
            IPv6(src='::', dst=str(self.node(1).global_ip()))/
                ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking for a forwarded message...")
        r1 = self.node(1).received(seq=self.seq(), type=ICMPv6EchoRequest)
        
        assertEqual(0, len(r1), "did not expect the ICMPv6 Echo Request to be forwarded (seq: %d)" % (self.seq()))


class RequestSentToLoopbackAddressTestCase(ComplianceTestCase):
    """
    IP Forwarding - Source and Destination Address - Request sent to
    Loopback address

    Verifies that a node properly forwards the ICMPv6 Echo Requests.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.1.10d)
    """

    def run(self):
        self.logger.debug("Sending ICMPv6 echo-request to loopback address")
        self.node(4).send( \
            IPv6(src=str(self.node(4).global_ip()), dst='::1')/
                ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking for packets...")
        r1 = self.node(1).received(dst='::1', seq=self.seq(), type=ICMPv6EchoRequest)
        
        assertEqual(0, len(r1), "did not expect the ICMPv6 Echo Request to be forwarded (seq: %d)" % (self.seq()))


class RequestSentFromLinkLocalAddressTestCase(ComplianceTestCase):
    """
    IP Forwarding - Source and Destination Address - Request sent from
    Loopback address

    Verifies that a node properly forwards the ICMPv6 Echo Requests.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.1.10e)
    """

    def run(self):
        self.logger.debug("Sending ICMPv6 echo-request from Link-Local address")
        self.node(4).send( \
            IPv6(src=str(self.node(4).link_local_ip()), dst=str(self.node(1).global_ip()))/
                ICMPv6EchoRequest())

        self.logger.info("Checking for packets...")
        r1 = self.node(1).received(src=self.node(4).link_local_ip(), seq=self.seq(), type=ICMPv6EchoRequest)

        assertEqual(0, len(r1), "did not expect the ICMPv6 Echo Request to be forwarded (seq: %d)" % (self.seq()))


class RequestSentToLinkLocalAddressTestCase(ComplianceTestCase):
    """
    IP Forwarding - Source and Destination Address - Request sent from
    Loopback address

    Verifies that a node properly forwards the ICMPv6 Echo Requests.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.1.10f)
    """

    def run(self):
        self.logger.debug("Sending ICMPv6 echo-request from Link-Local address")
        self.node(4).send( \
            IPv6(src=str(self.node(4).global_ip()), dst=str(self.node(1).link_local_ip()))/
                ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking for packets...")
        r1 = self.node(1).received(src=self.node(4).global_ip(), seq=self.seq(), type=ICMPv6EchoRequest)

        assertEqual(0, len(r1), "did not expect the ICMPv6 Echo Request to be forwarded (seq: %d)" % (self.seq()))


class RequestSentToSiteLocalAddressTestCase(ComplianceTestCase):
    """
    IP Forwarding - Source and Destination Address - Request sent to Site-
    Local address

    Verifies that a node properly forwards the ICMPv6 Echo Requests.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.1.10g)
    """

    def run(self):
        self.logger.debug("Sending ICMPv6 echo-request to Site-Local address")
        self.node(4).send( \
            IPv6(src=str(self.node(4).global_ip()), dst=str(self.node(1).ip(scope=IPAddressCollection.SITELOCAL)))/
                ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking for packets...")
        r1 = self.node(1).received(src=self.node(4).global_ip(), seq=self.seq(), type=ICMPv6EchoRequest)

        assertEqual(1, len(r1), "did not expect the ICMPv6 Echo Request to be forwarded (seq: %d)" % (self.seq()))


class RequestSentToGlobalScopeMulticastAddressTestCase(ComplianceTestCase):
    """
    IP Forwarding - Source and Destination Address - Request sent to Global
    multicast address

    Verifies that a node properly forwards the ICMPv6 Echo Requests.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.1.10h)
    """

    # TODO: this case may need to send an MLD/IGMP packet to register for the
    #       multicast group ff12::1:2
    def run(self):
        if not self.ui.ask("Does the UUT support multicast routing?"):
            assertTrue(True) # test is not required if the UUT does not support
                             # multicast routing
        else:
            self.logger.debug("Sending ICMPv6 echo-request to TN1's Link Local Multicast IP from TN2's Global IP")
            self.node(4).send( \
                IPv6(src=str(self.node(4).global_ip()), dst='ff1e::1:2')/
                    ICMPv6EchoRequest(seq=self.next_seq()))

            self.logger.info("Checking for packets...")
            r1 = self.node(1).received(src=self.node(4).global_ip(), dst='ff1e::1:2', seq=self.seq(), type=ICMPv6EchoRequest)

            assertEqual(1, len(r1), "did not expect the ICMPv6 Echo Request to be forwarded (seq: %d)" % (self.seq()))


class RequestSentToLinkLocalScopeMulticastAddressTestCase(ComplianceTestCase):
    """
    IP Forwarding - Source and Destination Address - Request sent to Link-
    Local multicast address

    Verifies that a node properly forwards the ICMPv6 Echo Requests.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.1.10i)
    """

    # TODO: this case may need to send an MLD/IGMP packet to register for the
    #       multicast group ff12::1:2
    def run(self):
        if not self.ui.ask("Does the UUT support multicast routing?"):
            assertTrue(True) # test is not required if the UUT does not support
                             # multicast routing
        else:
            self.logger.debug("Sending ICMPv6 echo-request to TN1's Link Local Multicast IP from TN2's Global IP")
            self.node(4).send( \
                IPv6(src=str(self.node(4).global_ip()), dst='ff12::1:2')/
                    ICMPv6EchoRequest(seq=self.next_seq()))

            self.logger.info("Checking for packets...")
            r1 = self.node(1).received(src=self.node(4).global_ip(), dst='ff12::1:2', seq=self.seq(), type=ICMPv6EchoRequest)

            assertEqual(0, len(r1), "did not expect the ICMPv6 Echo Request to be forwarded (seq: %d)" % (self.seq()))


class RequestSentToMulticastAddressReservedValue0TestCase(ComplianceTestCase):
    """
    IP Forwarding - Source and Destination Address - Request sent to Multicast
    address (Reserved Value = 0)

    Verifies that a node properly forwards the ICMPv6 Echo Requests.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.1.10j)
    """

    # TODO: this case may need to send an MLD/IGMP packet to register for the
    #       multicast group ff10::1:2
    def run(self):
        if not self.ui.ask("Does the UUT support multicast routing?"):
            assertTrue(True) # test is not required if the UUT does not support
                             # multicast routing
        else:
            self.logger.debug("Sending ICMPv6 echo-request to Multicast IP from TN2's Global IP")
            self.node(4).send( \
                IPv6(src=str(self.node(4).global_ip()), dst='ff10::1:2')/
                    ICMPv6EchoRequest(seq=self.next_seq()))

            self.logger.info("Checking for packets...")
            r1 = self.node(1).received(src=self.node(4).global_ip(), dst='ff10::1:2', seq=self.seq(), type=ICMPv6EchoRequest)

            assertEqual(0, len(r1), "did not expect the ICMPv6 Echo Request to be forwarded (seq: %d)" % (self.seq()))


class RequestSentToMulticastAddressReservedValueFTestCase(ComplianceTestCase):
    """
    IP Forwarding - Source and Destination Address - Request sent to Multicast
    address (Reserved Value = F)

    Verifies that a node properly forwards the ICMPv6 Echo Requests.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.1.10k)
    """

    # TODO: this case may need to send an MLD/IGMP packet to register for the
    #       multicast group ff1f::1:2
    def run(self):
        if not self.ui.ask("Does the UUT support multicast routing?"):
            assertTrue(True) # test is not required if the UUT does not support
                             # multicast routing
        else:
            self.logger.debug("Sending ICMPv6 echo-request to Multicast IP from TN2's Global IP")
            self.node(4).send( \
                IPv6(src=str(self.node(4).global_ip()), dst='ff1f::1:2')/
                    ICMPv6EchoRequest(seq=self.next_seq()))

            self.logger.info("Checking for packets...")
            r1 = self.node(1).received(src=self.node(4).global_ip(), dst='ff1f::1:2', seq=self.seq(), type=ICMPv6EchoRequest)

            assertEqual(0, len(r1), "did not expect the ICMPv6 Echo Request to be forwarded (seq: %d)" % (self.seq()))
