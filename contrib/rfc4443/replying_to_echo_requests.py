from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase, IPv6Address


class RequestSentToLinkLocalAddressTestCase(ComplianceTestCase):
    """
    Replying to Echo Requests - Request sent to Link-Local address
    
    Verify that a node properly replies to ICMPv6 Echo Requests.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Test v6LC.5.1.2a
    """

    def run(self):
        self.logger.info("Sending Echo request to NUT link local address")
        self.node(1).send( \
            IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()))/
                ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking for reply")
        r1 = self.node(1).received(src=self.target(1).link_local_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        
        assertEqual(1, len(r1), "expected to receive an ICMPv6 Echo Reply")
        
        assertEqual(self.node(1).link_local_ip(), r1[0].getlayer(IPv6).dst, "expected dst to be TN1's link-local address")
        
        self.logger.info("Check packet has valid checksum")
        p1 = IPv6(r1[0].build())
        p1.getlayer(ICMPv6EchoReply).cksum = None
        p1 = IPv6(p1.build())

        assertEqual(p1.getlayer(ICMPv6EchoReply).cksum, r1[0].getlayer(ICMPv6EchoReply).cksum, "expected the Echo Reply to have a valid checksum")


class RequestSentToGlobalAddressTestCase(ComplianceTestCase):
    """
    Replying to Echo Requests - Request sent to Global address

    Verify that a node properly replies to ICMPv6 Echo Requests.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Test v6LC.5.1.2b
    """

    def run(self):
        self.logger.info("Sending Echo request to NUT global address")
        self.node(1).send( \
            IPv6(src=str(self.node(1).global_ip()), dst=str(self.target(1).global_ip()))/
                ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking for reply")
        r1 = self.node(1).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)

        assertEqual(1, len(r1), "expected to receive an ICMPv6 Echo Reply")
        
        self.logger.info("Check packets dst is TN1s global address")
        assertEqual(self.node(1).global_ip(), r1[0].getlayer(IPv6).dst, "expected dst to be TN1's global address")
        
        self.logger.info("Check packet has valid checksum")
        p1 = IPv6(r1[0].build())
        p1.getlayer(ICMPv6EchoReply).cksum = None
        p1 = IPv6(p1.build())

        assertEqual(p1.getlayer(ICMPv6EchoReply).cksum, r1[0].getlayer(ICMPv6EchoReply).cksum, "expected the Echo Reply to have a valid checksum")


class RequestSentToAllNodesMulticastAddressTestCase(ComplianceTestCase):
    """
    Replying to Echo Requests - Request sent to Multicast address - All
    Nodes address

    Verify that a node properly replies to ICMPv6 Echo Requests.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Test v6LC.5.1.2c
    """

    def run(self):
        self.logger.info("Sending Echo request to link local multicast")
        self.node(1).send( \
            IPv6(src=str(self.node(1).link_local_ip()), dst="ff02::1")/
                ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking for reply with correct layer src and dst")
        r1 = self.node(1).received(src=self.target(1).link_local_ip(), seq=self.seq(), type=ICMPv6EchoReply)

        assertEqual(1, len(r1), "expected to receive an ICMPv6 Echo Reply")

        self.logger.info("Check packets dst is TN1s link local address")
        assertEqual(self.node(1).link_local_ip(), r1[0].getlayer(IPv6).dst, "expected dst to be TN1's global address")
        
        self.logger.info("Check packet has valid checksum")
        p1 = IPv6(r1[0].build())
        p1.getlayer(ICMPv6EchoReply).cksum = None
        p1 = IPv6(p1.build())

        assertEqual(p1.getlayer(ICMPv6EchoReply).cksum, r1[0].getlayer(ICMPv6EchoReply).cksum, "expected the Echo Reply to have a valid checksum")


class RequestSentToAllRoutersMulticastAddressTestCase(ComplianceTestCase):
    """
    Replying to Echo Requests - Request sent to Multicast address - All Routers
    Address

    Verify that a node properly replies to ICMPv6 Echo Requests.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Test v6LC.5.1.2d
    """

    def run(self):
        self.logger.info("Sending Echo request to link local router multicast")
        self.node(1).send( \
            IPv6(src=str(self.node(1).link_local_ip()), dst="ff02::2")/
                ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking for reply with correct layer src and dst")
        r1 = self.node(1).received(src=self.target(1).link_local_ip(), seq=self.seq(), type=ICMPv6EchoReply)

        assertEqual(1, len(r1), "expected to receive an ICMPv6 Echo Reply")

        self.logger.info("Check packets dst is TN1s link local address")
        assertEqual(self.node(1).link_local_ip(), r1[0].getlayer(IPv6).dst, "expected dst to be TN1's global address")

        self.logger.info("Check packet has valid checksum")
        p1 = IPv6(r1[0].build())
        p1.getlayer(ICMPv6EchoReply).cksum = None
        p1 = IPv6(p1.build())

        assertEqual(p1.getlayer(ICMPv6EchoReply).cksum, r1[0].getlayer(ICMPv6EchoReply).cksum, "expected the Echo Reply to have a valid checksum")


class RequestSentToUnspecifiedAddressTestCase(ComplianceTestCase):
    """
    Replying to Echo Requests - Request sent to Unspecified address

    Verify that a node properly replies to ICMPv6 Echo Requests.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Test v6LC.5.1.2e
    """

    def run(self):
        self.logger.info("Sending Echo request to unspecified address")
        self.node(1).send( \
            IPv6(src=str(self.node(1).link_local_ip()), dst="::")/
                ICMPv6EchoRequest(seq=self.next_seq()))
        
        
        self.logger.info("Checking for reply with correct layer src and dst")
        r1 = self.node(1).received(src=self.target(1).link_local_ip(), seq=self.seq(), type=ICMPv6EchoReply)

        assertEqual(0, len(r1), "did not expect to receive an ICMPv6 Echo Reply")


class RequestSentToLoopbackAddressTestCase(ComplianceTestCase):
    """
    Replying to Echo Requests - Request sent to Loopback address

    Verify that a node properly replies to ICMPv6 Echo Requests.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Test v6LC.5.1.2f
    """

    def run(self):
        self.logger.info("Sending Echo request to unspecified address")
        self.node(1).send( \
            IPv6(src=str(self.node(1).link_local_ip()), dst="::1")/
                ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking for reply with correct layer src and dst")
        r1 = self.node(1).received(src=self.target(1).link_local_ip(), seq=self.seq(), type=ICMPv6EchoReply)

        assertEqual(0, len(r1), "did not expect to receive an ICMPv6 Echo Reply")


class RequestSentToSiteLocalAddressEndNodeTestCase(ComplianceTestCase):
    """
    Replying to Echo Requests - Request sent to Site-Local address

    Verify that a node properly replies to ICMPv6 Echo Requests.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Test v6LC.5.1.2g (End Node)
    """

    def run(self):
        self.logger.info("Sending RA for Site-Local prefix")
        self.logger.info("Send Router advertisement with site local prefix FEC0::/10")
        self.router(1).send( \
            IPv6(src=str(self.router(1).link_local_ip(iface=1)), dst="ff02::1")/
                ICMPv6ND_RA(routerlifetime=90, reachabletime=10, retranstimer=1)/
                    ICMPv6NDOptSrcLLAddr(lladdr=self.router(1).iface(1).ll_addr)/
                    ICMPv6NDOptMTU(mtu=self.router(1).iface(1).ll_protocol.mtu)/
                    ICMPv6NDOptPrefixInfo(validlifetime=90, preferredlifetime=90, prefix="fec0::", prefixlen=64), iface=1)
        # TODO: review the use of the prefix length 64, technically it should
        #       be 10, but this results in an error stating the prefix is
        #       invalid
        
        self.logger.info("Requesting user to enter the address")
        site_local_ip = IPv6Address(self.ui.read("What is the NUT's Site Local address? (starting fec0:)"))

        assertNotNone(site_local_ip, "expected a valid site-local IPv6 address to be assigned")
        
        self.logger.info("Sending Echo request to NUT site local address")
        self.node(1).send( \
            IPv6(src=str(self.node(1).link_local_ip()), dst=str(site_local_ip))/
                ICMPv6EchoRequest(seq=self.next_seq()))
        
        self.logger.info("Checking for reply")
        r1 = self.node(1).received(src=site_local_ip, seq=self.seq(), type=ICMPv6EchoReply)

        assertEqual(1, len(r1), "expected a reply to the ICMPv6 Echo Request")
        
        self.logger.info("Check packets dst is TN1s link local address")
        assertEqual(self.node(1).link_local_ip(), r1[0].getlayer(IPv6).dst, "expected dst to be TN1's link-local address")

        self.logger.info("Check packet has valid checksum")
        p1 = IPv6(r1[0].build())
        p1.getlayer(ICMPv6EchoReply).cksum = None
        p1 = IPv6(p1.build())

        assertEqual(p1.getlayer(ICMPv6EchoReply).cksum, r1[0].getlayer(ICMPv6EchoReply).cksum, "expected the Echo Reply to have a valid checksum")


class RequestSentToSiteLocalAddressIntermediateNodeTestCase(ComplianceTestCase):
    """
    Replying to Echo Requests - Request sent to Site-Local address

    Verify that a node properly replies to ICMPv6 Echo Requests.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Test v6LC.5.1.2g (Intermediate Node)
    """

    def run(self):
        self.ui.tell("Ensure the RUT transmits a Router Advertisement with the site-local prefix FEC0::/10, and configure a site-local address on ifx.")
        
        self.logger.info("Requesting user to enter the address")
        site_local_ip = IPv6Address(self.ui.read("What is the NUT's Site Local address? (starting fec0:)"))

        assertNotNone(site_local_ip, "expected a valid site-local IPv6 address to be assigned")

        self.logger.info("Sending Echo request to NUT site local address")
        self.node(1).send( \
            IPv6(src=str(self.node(1).link_local_ip()), dst=str(site_local_ip))/
                ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking for reply")
        r1 = self.node(1).received(src=site_local_ip, seq=self.seq(), type=ICMPv6EchoReply)

        assertEqual(1, len(r1), "expected a reply to the ICMPv6 Echo Request")

        self.logger.info("Check packets dst is TN1s link local address")
        assertEqual(self.node(1).link_local_ip(), r1[0].getlayer(IPv6).dst, "expected dst to be TN1's link-local address")

        self.logger.info("Check packet has valid checksum")
        p1 = IPv6(r1[0].build())
        p1.getlayer(ICMPv6EchoReply).cksum = None
        p1 = IPv6(p1.build())

        assertEqual(p1.getlayer(ICMPv6EchoReply).cksum, r1[0].getlayer(ICMPv6EchoReply).cksum, "expected the Echo Reply to have a valid checksum")
