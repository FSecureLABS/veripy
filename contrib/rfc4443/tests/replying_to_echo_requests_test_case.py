from contrib.rfc4443 import replying_to_echo_requests as suite
from scapy.all import *
from veripy.testability import ComplianceTestTestCase

class RequestSentToLinkLocalAddressTestCase(ComplianceTestTestCase):
    
    def test_link_local_valid(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply(), expect=ICMPv6EchoRequest)

        o = self.get_outcome(suite.RequestSentToLinkLocalAddressTestCase)

        self.assertCheckPasses(o)
        
    def test_link_local_no_reply(self):        
        o = self.get_outcome(suite.RequestSentToLinkLocalAddressTestCase)

        self.assertCheckFails(o)
        
    def test_link_local_invalid_checksum(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())

        o = self.get_outcome(suite.RequestSentToLinkLocalAddressTestCase)

        self.assertCheckFails(o)
        
    def test_link_local_invalid_src(self):
        self.ifx.replies_with(IPv6(src="::", dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())

        o = self.get_outcome(suite.RequestSentToLinkLocalAddressTestCase)

        self.assertCheckFails(o)
    
    def test_link_local_invalid_dst(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst="::")/ICMPv6EchoReply())

        o = self.get_outcome(suite.RequestSentToLinkLocalAddressTestCase)

        self.assertCheckFails(o)


class RequestSentToGlobalAddressTestCase(ComplianceTestTestCase):

    def test_global_valid(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())

        o = self.get_outcome(suite.RequestSentToGlobalAddressTestCase)

        self.assertCheckPasses(o)

    def test_global_no_reply(self):
        o = self.get_outcome(suite.RequestSentToGlobalAddressTestCase)

        self.assertCheckFails(o)

    def test_global_invalid_checksum(self):
        self.ifx.replies_with(self.break_checksum(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply()))

        o = self.get_outcome(suite.RequestSentToGlobalAddressTestCase)

        self.assertCheckFails(o)

    def test_global_invalid_src(self):
        self.ifx.replies_with(IPv6(src="::", dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())

        o = self.get_outcome(suite.RequestSentToGlobalAddressTestCase)

        self.assertCheckFails(o)

    def test_global_invalid_dst(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst="::")/ICMPv6EchoReply())

        o = self.get_outcome(suite.RequestSentToGlobalAddressTestCase)

        self.assertCheckFails(o)


class RequestSentToAllNodesMulticastAddressTestCase(ComplianceTestTestCase):

    def test_multicast_valid(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())

        o = self.get_outcome(suite.RequestSentToAllNodesMulticastAddressTestCase)

        self.assertCheckPasses(o)

    def test_multicast_no_reply(self):
        o = self.get_outcome(suite.RequestSentToAllNodesMulticastAddressTestCase)

        self.assertCheckFails(o)

    def test_multicast_invalid_checksum(self):
        self.ifx.replies_with(self.break_checksum(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply()))

        o = self.get_outcome(suite.RequestSentToAllNodesMulticastAddressTestCase)

        self.assertCheckFails(o)

    def test_multicast_invalid_src(self):
        self.ifx.replies_with(IPv6(src="::", dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())

        o = self.get_outcome(suite.RequestSentToAllNodesMulticastAddressTestCase)

        self.assertCheckFails(o)

    def test_multicast_invalid_dst(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst="::")/ICMPv6EchoReply())

        o = self.get_outcome(suite.RequestSentToAllNodesMulticastAddressTestCase)

        self.assertCheckFails(o)


class RequestSentToAllRoutersMulticastAddressTestCase(ComplianceTestTestCase):

    def test_multicast_router_valid(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())

        o = self.get_outcome(suite.RequestSentToAllRoutersMulticastAddressTestCase)

        self.assertCheckPasses(o)

    def test_multicast_router_no_reply(self):
        o = self.get_outcome(suite.RequestSentToAllRoutersMulticastAddressTestCase)

        self.assertCheckFails(o)

    def test_multicast_router_invalid_checksum(self):
        self.ifx.replies_with(self.break_checksum(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply()))

        o = self.get_outcome(suite.RequestSentToAllRoutersMulticastAddressTestCase)

        self.assertCheckFails(o)

    def test_multicast_router_invalid_src(self):
        self.ifx.replies_with(IPv6(src="::", dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())

        o = self.get_outcome(suite.RequestSentToAllRoutersMulticastAddressTestCase)

        self.assertCheckFails(o)

    def test_multicast_router_invalid_dst(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst="::")/ICMPv6EchoReply())

        o = self.get_outcome(suite.RequestSentToAllRoutersMulticastAddressTestCase)

        self.assertCheckFails(o)


class RequestSentToUnspecifiedAddressTestCase(ComplianceTestTestCase):

    def test_unspecified_address_valid(self):
        o = self.get_outcome(suite.RequestSentToUnspecifiedAddressTestCase)

        self.assertCheckPasses(o)

    def test_unspecified_address_reply(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())

        o = self.get_outcome(suite.RequestSentToUnspecifiedAddressTestCase)

        self.assertCheckFails(o)


class RequestSentToLoopbackAddressTestCase(ComplianceTestTestCase):

    def test_loopback_valid(self):
        o = self.get_outcome(suite.RequestSentToLoopbackAddressTestCase)

        self.assertCheckPasses(o)

    def test_loopback_reply(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())

        o = self.get_outcome(suite.RequestSentToLoopbackAddressTestCase)

        self.assertCheckFails(o)


class RequestSentToSiteLocalAddressEndNodeTestCase(ComplianceTestTestCase):

    def setUp(self):
        super(RequestSentToSiteLocalAddressEndNodeTestCase, self).setUp()

        self.site_local_ip = "fec0::50"
        
        self.ui.inputs.append(self.site_local_ip)
        

    def test_site_local_valid(self):
        self.ifx.replies_with(IPv6(src=str(self.site_local_ip), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())

        o = self.get_outcome(suite.RequestSentToSiteLocalAddressEndNodeTestCase)

        self.assertCheckPasses(o)

    def test_site_local_no_reply(self):
        o = self.get_outcome(suite.RequestSentToSiteLocalAddressEndNodeTestCase)

        self.assertCheckFails(o)

    def test_site_local_invalid_src(self):
        self.ifx.replies_with(IPv6(src="::", dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())

        o = self.get_outcome(suite.RequestSentToSiteLocalAddressEndNodeTestCase)

        self.assertCheckFails(o)

    def test_site_local_invalid_dst(self):
        self.ifx.replies_with(IPv6(src=str(self.site_local_ip), dst="::")/ICMPv6EchoReply())

        o = self.get_outcome(suite.RequestSentToSiteLocalAddressEndNodeTestCase)

        self.assertCheckFails(o)

    def test_site_local_invalid_cksum(self):
        self.ifx.replies_with(self.break_checksum(IPv6(src=str(self.site_local_ip), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply()))

        o = self.get_outcome(suite.RequestSentToSiteLocalAddressEndNodeTestCase)

        self.assertCheckFails(o)


class RequestSentToSiteLocalAddressIntermediateNodeTestCase(ComplianceTestTestCase):

    def setUp(self):
        super(RequestSentToSiteLocalAddressIntermediateNodeTestCase, self).setUp()

        self.site_local_ip = "fec0::50"

        self.ui.inputs.append(self.site_local_ip)
        

    def test_site_local_valid(self):
        self.ifx.replies_with(IPv6(src=str(self.site_local_ip), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())

        o = self.get_outcome(suite.RequestSentToSiteLocalAddressIntermediateNodeTestCase)

        self.assertCheckPasses(o)

    def test_site_local_no_reply(self):
        o = self.get_outcome(suite.RequestSentToSiteLocalAddressIntermediateNodeTestCase)

        self.assertCheckFails(o)

    def test_site_local_invalid_src(self):
        self.ifx.replies_with(IPv6(src="::", dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())

        o = self.get_outcome(suite.RequestSentToSiteLocalAddressIntermediateNodeTestCase)

        self.assertCheckFails(o)

    def test_site_local_invalid_dst(self):
        self.ifx.replies_with(IPv6(src=str(self.site_local_ip), dst="::")/ICMPv6EchoReply())

        o = self.get_outcome(suite.RequestSentToSiteLocalAddressIntermediateNodeTestCase)

        self.assertCheckFails(o)

    def test_site_local_invalid_cksum(self):
        self.ifx.replies_with(self.break_checksum(IPv6(src=str(self.site_local_ip), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply()))

        o = self.get_outcome(suite.RequestSentToSiteLocalAddressIntermediateNodeTestCase)

        self.assertCheckFails(o)
        