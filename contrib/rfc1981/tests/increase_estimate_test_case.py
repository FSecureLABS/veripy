from contrib.rfc1981 import increase_estimate as suite
from scapy.all import *
from veripy import util
from veripy.testability import ComplianceTestTestCase


class MTUIncreaseTestCase(ComplianceTestTestCase):

    def test_valid(self):
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6EchoReply(), 1500, True))
        self.ifx.replies_with(None)
        self.ifx.replies_with(fragment6(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoReply(), 1500, True), 1304))
        self.ifx.replies_with(None)
        self.ifx.replies_with(fragment6(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoReply(), 1500, True), 1304))

        o = self.get_outcome(suite.MTUIncreaseTestCase)

        self.assertCheckPasses(o)

    def test_no_reply_to_first_echo_request(self):
        o = self.get_outcome(suite.MTUIncreaseTestCase)
        
        self.assertCheckFails(o)
    
    def test_no_reply_to_second_echo_request(self):
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6EchoReply(), 1500, True))
        self.ifx.replies_with(None)
        
        o = self.get_outcome(suite.MTUIncreaseTestCase)
        
        self.assertCheckFails(o)
    
    def test_second_reply_is_not_fragmented(self):
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6EchoReply(), 1500, True))
        self.ifx.replies_with(None)
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoReply(), 1500, True))

        o = self.get_outcome(suite.MTUIncreaseTestCase)
        
        self.assertCheckFails(o)
    
    def test_no_reply_to_third_echo_request(self):
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6EchoReply(), 1500, True))
        self.ifx.replies_with(None)
        self.ifx.replies_with(fragment6(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoReply(), 1500, True), 1304))
        
        o = self.get_outcome(suite.MTUIncreaseTestCase)
        
        self.assertCheckFails(o)
    
    def test_third_reply_is_not_fragmented(self):
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6EchoReply(), 1500, True))
        self.ifx.replies_with(None)
        self.ifx.replies_with(fragment6(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoReply(), 1500, True), 1304))
        self.ifx.replies_with(None)
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoReply(), 1500, True))

        o = self.get_outcome(suite.MTUIncreaseTestCase)

        self.assertCheckFails(o)

    def test_third_reply_fragmented_size_increased(self):
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6EchoReply(), 1500, True))
        self.ifx.replies_with(None)
        self.ifx.replies_with(fragment6(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoReply(), 1500, True), 1304))
        self.ifx.replies_with(None)
        self.ifx.replies_with(fragment6(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoReply(), 1500, True), 1500))

        o = self.get_outcome(suite.MTUIncreaseTestCase)

        self.assertCheckFails(o)


class MTUEqualTo0x1ffffffTestCase(ComplianceTestTestCase):

    def test_valid(self):
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6EchoReply(), 1500, True))
        self.ifx.replies_with(None)
        self.ifx.replies_with(fragment6(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoReply(), 1500, True), 1304))
        self.ifx.replies_with(None)
        self.ifx.replies_with(fragment6(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoReply(), 1500, True), 1304))

        o = self.get_outcome(suite.MTUEqualTo0x1ffffffTestCase)

        self.assertCheckPasses(o)

    def test_no_reply_to_first_echo_request(self):
        o = self.get_outcome(suite.MTUEqualTo0x1ffffffTestCase)

        self.assertCheckFails(o)

    def test_no_reply_to_second_echo_request(self):
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6EchoReply(), 1500, True))
        self.ifx.replies_with(None)

        o = self.get_outcome(suite.MTUEqualTo0x1ffffffTestCase)

        self.assertCheckFails(o)

    def test_second_reply_is_not_fragmented(self):
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6EchoReply(), 1500, True))
        self.ifx.replies_with(None)
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoReply(), 1500, True))

        o = self.get_outcome(suite.MTUEqualTo0x1ffffffTestCase)

        self.assertCheckFails(o)

    def test_no_reply_to_third_echo_request(self):
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6EchoReply(), 1500, True))
        self.ifx.replies_with(None)
        self.ifx.replies_with(fragment6(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoReply(), 1500, True), 1304))

        o = self.get_outcome(suite.MTUEqualTo0x1ffffffTestCase)

        self.assertCheckFails(o)

    def test_third_reply_is_not_fragmented(self):
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6EchoReply(), 1500, True))
        self.ifx.replies_with(None)
        self.ifx.replies_with(fragment6(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoReply(), 1500, True), 1304))
        self.ifx.replies_with(None)
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoReply(), 1500, True))

        o = self.get_outcome(suite.MTUEqualTo0x1ffffffTestCase)

        self.assertCheckFails(o)

    def test_third_reply_fragmented_size_increased(self):
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6EchoReply(), 1500, True))
        self.ifx.replies_with(None)
        self.ifx.replies_with(fragment6(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoReply(), 1500, True), 1304))
        self.ifx.replies_with(None)
        self.ifx.replies_with(fragment6(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoReply(), 1500, True), 1500))

        o = self.get_outcome(suite.MTUEqualTo0x1ffffffTestCase)

        self.assertCheckFails(o)
        