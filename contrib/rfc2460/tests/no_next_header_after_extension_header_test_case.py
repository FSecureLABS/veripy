from contrib.rfc2460 import no_next_header_after_extension_header as suite
from scapy.all import *
from veripy.testability import ComplianceTestTestCase


class NoNextHeaderAfterExtensionHeaderEndNodeTestCase(ComplianceTestTestCase):

    def test_no_next_header_after_extension_header(self):
        o = self.get_outcome(suite.NoNextHeaderAfterExtensionHeaderEndNodeTestCase)
        
        self.assertCheckPasses(o)
    
    def test_no_next_header_after_extension_header_reply(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        
        o = self.get_outcome(suite.NoNextHeaderAfterExtensionHeaderEndNodeTestCase)

        self.assertCheckFails(o)


class NoNextHeaderAfterExtensionHeaderIntermediateNodeTestCase(ComplianceTestTestCase):

    def test_packet_forwarded_intact(self):
        self.ify.replies_with(IPv6(src=str(self.tn4.global_ip()), dst=str(self.tn1.global_ip()))/IPv6ExtHdrDestOpt(nh=59, len=0, options=[PadN(otype='PadN', optlen=4)])/ICMPv6EchoRequest(), to=self.ifx)

        o = self.get_outcome(suite.NoNextHeaderAfterExtensionHeaderIntermediateNodeTestCase)

        self.assertCheckPasses(o)

    def test_packet_not_forwarded_on_link_b(self):
        o = self.get_outcome(suite.NoNextHeaderAfterExtensionHeaderIntermediateNodeTestCase)

        self.assertCheckFails(o)

    def test_packet_forwarded_but_octects_after_header_changed(self):
        self.ify.replies_with(IPv6(src=str(self.tn4.global_ip()), dst=str(self.tn1.global_ip()))/IPv6ExtHdrDestOpt(nh=59, len=0, options=[PadN(otype='PadN', optlen=4)])/ICMPv6EchoReply(data='IPv6'), to=self.ifx)

        o = self.get_outcome(suite.NoNextHeaderAfterExtensionHeaderIntermediateNodeTestCase)

        self.assertCheckFails(o)
