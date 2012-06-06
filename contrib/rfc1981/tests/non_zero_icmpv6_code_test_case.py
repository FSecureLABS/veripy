from contrib.rfc1981 import non_zero_icmpv6_code as suite
from scapy.all import *
from veripy import util
from veripy.testability import ComplianceTestTestCase


class NonZeroICMPv6CodeTestCase(ComplianceTestTestCase):

    def test_all_replies_with_fragmentation(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6EchoReply())
        self.ifx.replies_with(None)
        self.ifx.replies_with(fragment6(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoReply(), 1500, True), 1280))

        o = self.get_outcome(suite.NonZeroICMPv6CodeTestCase)

        self.assertCheckPasses(o)
    
    def test_no_reply_to_first_echo_request(self):
        o = self.get_outcome(suite.NonZeroICMPv6CodeTestCase)

        self.assertCheckFails(o)

    def test_no_fragmented_reply(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6EchoReply())
        self.ifx.replies_with(None)

        o = self.get_outcome(suite.NonZeroICMPv6CodeTestCase)

        self.assertCheckFails(o)

    def test_second_reply_not_fragmented(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6EchoReply())
        self.ifx.replies_with(None)
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6EchoReply())

        o = self.get_outcome(suite.NonZeroICMPv6CodeTestCase)

        self.assertCheckFails(o)
        