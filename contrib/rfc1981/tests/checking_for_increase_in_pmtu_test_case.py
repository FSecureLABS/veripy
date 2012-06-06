from contrib.rfc1981 import checking_for_increase_in_pmtu as suite
from scapy.all import *
from veripy import util
from veripy.testability import ComplianceTestTestCase


class CheckingForIncreaseInPMTUTestCase(ComplianceTestTestCase):

    def test_valid(self):
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6EchoReply(), 1500, True))
        self.ifx.replies_with(None)
        for i in range(0, 11):
            self.ifx.replies_with(fragment6(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoReply(), 1500, True), 1304))

        o = self.get_outcome(suite.CheckingForIncreaseInPMTUTestCase)

        self.assertCheckPasses(o)
    
    def test_no_reply_to_first_echo(self):
        o = self.get_outcome(suite.CheckingForIncreaseInPMTUTestCase)

        self.assertCheckFails(o)

    def test_no_fragmented_replies(self):
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6EchoReply(), 1500, True))
        self.ifx.replies_with(None)

        o = self.get_outcome(suite.CheckingForIncreaseInPMTUTestCase)

        self.assertCheckFails(o)

    def test_second_reply_not_fragmented(self):
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6EchoReply(), 1500, True))
        self.ifx.replies_with(None)
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6EchoReply(), 1500, True))

        o = self.get_outcome(suite.CheckingForIncreaseInPMTUTestCase)

        self.assertCheckFails(o)

    def test_no_subsequent_replies(self):
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6EchoReply(), 1500, True))
        self.ifx.replies_with(None)
        self.ifx.replies_with(fragment6(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoReply(), 1500, True), 1304))

        o = self.get_outcome(suite.CheckingForIncreaseInPMTUTestCase)

        self.assertCheckFails(o)

    def test_pmtu_increase_too_early(self):
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6EchoReply(), 1500, True))
        self.ifx.replies_with(None)
        for i in range(0, 5):
            self.ifx.replies_with(fragment6(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoReply(), 1500, True), 1304))
        for i in range(5, 6):
            self.ifx.replies_with(fragment6(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoReply(), 1500, True), 1500))

        o = self.get_outcome(suite.CheckingForIncreaseInPMTUTestCase)

        self.assertCheckFails(o)
