from contrib.rfc1981 import reduce_pmtu_off_link as suite
from scapy.all import *
from veripy import util
from veripy.testability import ComplianceTestTestCase


class ReducePMTUOffLinkTestCase(ComplianceTestTestCase):

    def test_all_replies_with_fragmentation(self):
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoReply(), 1500, True))
        self.ifx.replies_with(None)
        self.ifx.replies_with(fragment6(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoReply(), 1500, True), 1400))
        self.ifx.replies_with(None)
        self.ifx.replies_with(fragment6(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoReply(), 1500, True), 1280))

        o = self.get_outcome(suite.ReducePMTUOffLinkTestCase)

        self.assertCheckPasses(o)

    def test_all_replies_with_small_fragments(self):
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoReply(), 1500, True))
        self.ifx.replies_with(None)
        self.ifx.replies_with(fragment6(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoReply(), 1500, True), 1000))
        self.ifx.replies_with(None)
        self.ifx.replies_with(fragment6(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoReply(), 1500, True), 1000))
         
        o = self.get_outcome(suite.ReducePMTUOffLinkTestCase)

        self.assertCheckPasses(o)
    
    def test_no_reply(self):
        o = self.get_outcome(suite.ReducePMTUOffLinkTestCase)

        self.assertCheckFails(o)

    def test_first_reply_only(self):
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoReply(), 1500, True))

        o = self.get_outcome(suite.ReducePMTUOffLinkTestCase)

        self.assertCheckFails(o)

    def test_first_and_second_no_fragmentation(self):
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoReply(), 1500, True))
        self.ifx.replies_with(None)
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoReply(), 1500, True))

        o = self.get_outcome(suite.ReducePMTUOffLinkTestCase)

        self.assertCheckFails(o)

    def test_first_and_second_with_fragmentation(self):
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoReply(), 1500, True))
        self.ifx.replies_with(None)
        self.ifx.replies_with(fragment6(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoReply(), 1500, True), 1000))

        o = self.get_outcome(suite.ReducePMTUOffLinkTestCase)

        self.assertCheckFails(o)

    def test_all_replies_with_large_fragments(self):
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoReply(), 1500, True))
        self.ifx.replies_with(None)
        self.ifx.replies_with(fragment6(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoReply(), 1500, True), 1400))
        self.ifx.replies_with(None)
        self.ifx.replies_with(fragment6(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoReply(), 1500, True), 1300))

        o = self.get_outcome(suite.ReducePMTUOffLinkTestCase)

        self.assertCheckFails(o)
        