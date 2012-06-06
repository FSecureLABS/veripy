from contrib.rfc1981 import receiving_mtu_below_ipv6_minimum as suite
from scapy.all import *
from veripy import util
from veripy.testability import ComplianceTestTestCase


class MTUEqualTo56TestCase(ComplianceTestTestCase):

    def test_valid_fragmentation(self): # or lack thereof
	self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6EchoReply(), 1280, True))
	self.ifx.replies_with(None)
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoReply(), 1280, True))

        o = self.get_outcome(suite.MTUEqualTo56TestCase)
        
        self.assertCheckPasses(o)
    
    def test_no_reply_to_first_echo(self):
        o = self.get_outcome(suite.MTUEqualTo56TestCase)
        
        self.assertCheckFails(o)
    
    def test_no_reply_to_second_echo(self):
	self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6EchoReply(), 1280, True))
	self.ifx.replies_with(None)

        o = self.get_outcome(suite.MTUEqualTo56TestCase)

        self.assertCheckFails(o)

    def test_fragmented_below_minimum_mtu(self):
	self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6EchoReply(), 1280, True))
	self.ifx.replies_with(None)
        self.ifx.replies_with(fragment6(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoReply(), 1280, True), 56))

        o = self.get_outcome(suite.MTUEqualTo56TestCase)

        self.assertCheckFails(o)

    def test_unfragmented_reply_without_fragmentation_header(self):
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6EchoReply(), 1280, True))
	self.ifx.replies_with(None)
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6EchoReply(), 1280, True))

        o = self.get_outcome(suite.MTUEqualTo56TestCase)

        self.assertCheckFails(o)


class MTUEqualTo1279TestCase(ComplianceTestTestCase):

    def test_valid_fragmentation(self): # or lack thereof
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6EchoReply(), 1280, True))
	self.ifx.replies_with(None)
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoReply(), 1280, True))

        o = self.get_outcome(suite.MTUEqualTo1279TestCase)

        self.assertCheckPasses(o)
    
    def test_no_reply_to_first_echo(self):
        o = self.get_outcome(suite.MTUEqualTo1279TestCase)

        self.assertCheckFails(o)
    
    def test_no_reply_to_second_echo(self):
	self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6EchoReply(), 1280, True))
	self.ifx.replies_with(None)

        o = self.get_outcome(suite.MTUEqualTo1279TestCase)

        self.assertCheckFails(o)

    def test_fragmented_below_minimum_mtu(self):
	self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6EchoReply(), 1280, True))
	self.ifx.replies_with(None)
        self.ifx.replies_with(fragment6(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoReply(), 1280, True), 1279))

        o = self.get_outcome(suite.MTUEqualTo1279TestCase)

        self.assertCheckFails(o)

    def test_unfragmented_reply_without_fragmentation_header(self):
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6EchoReply(), 1280, True))
	self.ifx.replies_with(None)
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6EchoReply(), 1280, True))

        o = self.get_outcome(suite.MTUEqualTo1279TestCase)

        self.assertCheckFails(o)
        