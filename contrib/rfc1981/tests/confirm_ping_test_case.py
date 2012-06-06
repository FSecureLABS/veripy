from contrib.rfc1981 import confirm_ping as suite
from scapy.all import *
from veripy import util
from veripy.testability import ComplianceTestTestCase


class ICMPv6EchoRequest64OctetsTestCase(ComplianceTestTestCase):

    def test_echo_reply_correct_size(self):
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6EchoReply(), 64, True))

        o = self.get_outcome(suite.ICMPv6EchoRequest64OctetsTestCase)

        self.assertCheckPasses(o)
    
    def test_no_reply(self):
        o = self.get_outcome(suite.ICMPv6EchoRequest64OctetsTestCase)

        self.assertCheckFails(o)

    def test_echo_reply_wrong_size(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6EchoReply())

        o = self.get_outcome(suite.ICMPv6EchoRequest64OctetsTestCase)

        self.assertCheckFails(o)


class ICMPv6EchoRequest1280OctetsTestCase(ComplianceTestTestCase):

    def test_echo_reply_correct_size(self):
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6EchoReply(), 1280, True))

        o = self.get_outcome(suite.ICMPv6EchoRequest1280OctetsTestCase)

        self.assertCheckPasses(o)
    
    def test_no_reply(self):
        o = self.get_outcome(suite.ICMPv6EchoRequest1280OctetsTestCase)

        self.assertCheckFails(o)

    def test_echo_reply_wrong_size(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6EchoReply())

        o = self.get_outcome(suite.ICMPv6EchoRequest1280OctetsTestCase)

        self.assertCheckFails(o)


class ICMPv6EchoRequest1500OctetsTestCase(ComplianceTestTestCase):

    def test_echo_reply_correct_size(self):
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6EchoReply(), 1500, True))

        o = self.get_outcome(suite.ICMPv6EchoRequest1500OctetsTestCase)

        self.assertCheckPasses(o)
    
    def test_no_reply(self):
        o = self.get_outcome(suite.ICMPv6EchoRequest1500OctetsTestCase)

        self.assertCheckFails(o)

    def test_echo_reply_wrong_size(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6EchoReply())

        o = self.get_outcome(suite.ICMPv6EchoRequest1500OctetsTestCase)

        self.assertCheckFails(o)
        