from contrib.rfc1981 import router_advertisement_with_mtu_option as suite
from scapy.all import *
from veripy import util
from veripy.testability import ComplianceTestTestCase


class RouterAdvertisementWithMTUOptionTestCase(ComplianceTestTestCase):

    def test_valid(self):
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6EchoReply(), 1500, True))
        self.ifx.replies_with(fragment6(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoReply(), 1500, True), 1280))

        o = self.get_outcome(suite.RouterAdvertisementWithMTUOptionTestCase)

        self.assertCheckPasses(o)
    
    def test_no_reply(self):
        o = self.get_outcome(suite.RouterAdvertisementWithMTUOptionTestCase)

        self.assertCheckFails(o)

    def test_first_reply_only(self):
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6EchoReply(), 1500, True))

        o = self.get_outcome(suite.RouterAdvertisementWithMTUOptionTestCase)

        self.assertCheckFails(o)

    def test_second_reply_not_fragmented(self):
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6EchoReply(), 1500, True))
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6EchoReply(), 1500, True))

        o = self.get_outcome(suite.RouterAdvertisementWithMTUOptionTestCase)

        self.assertCheckFails(o)

    def test_second_reply_fragmented_too_large(self):
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6EchoReply(), 1500, True))
        self.ifx.replies_with(fragment6(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoReply(), 1500, True), 1300))

        o = self.get_outcome(suite.RouterAdvertisementWithMTUOptionTestCase)

        self.assertCheckFails(o)
        