from contrib.rfc1981 import reduce_pmtu_on_link as suite
from scapy.all import *
from veripy import util
from veripy.testability import ComplianceTestTestCase

class ReducePMTUOnLinkLinkLocalTestCase(ComplianceTestTestCase):

    def test_all_replies(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())
        self.ifx.replies_with(None)
        self.ifx.replies_with(fragment6(util.pad(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoReply(), 1500, True), 1280))

        o = self.get_outcome(suite.ReducePMTUOnLinkLinkLocalTestCase)

        self.assertCheckPasses(o)
    
    def test_no_reply(self):
        o = self.get_outcome(suite.ReducePMTUOnLinkLinkLocalTestCase)

        self.assertCheckFails(o)

    def test_first_reply_only(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())

        o = self.get_outcome(suite.ReducePMTUOnLinkLinkLocalTestCase)

        self.assertCheckFails(o)

    def test_all_replies_no_fragmentation(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())
        self.ifx.replies_with(None)
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())

        o = self.get_outcome(suite.ReducePMTUOnLinkLinkLocalTestCase)

        self.assertCheckFails(o)
    
    def test_all_replies_round1_with_fragmentation(self):
        self.ifx.replies_with(fragment6(util.pad(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoReply(), 1500, True), 1280))

        o = self.get_outcome(suite.ReducePMTUOnLinkLinkLocalTestCase)

        self.assertCheckFails(o)


class ReducePMTUOnLinkGlobalTestCase(ComplianceTestTestCase):

    def test_all_replies(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        self.ifx.replies_with(None)
        self.ifx.replies_with(fragment6(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoReply(), 1500, True), 1280))

        o = self.get_outcome(suite.ReducePMTUOnLinkGlobalTestCase)

        self.assertCheckPasses(o)

    def test_no_reply(self):
        o = self.get_outcome(suite.ReducePMTUOnLinkGlobalTestCase)

        self.assertCheckFails(o)

    def test_first_reply_only(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())

        o = self.get_outcome(suite.ReducePMTUOnLinkGlobalTestCase)

        self.assertCheckFails(o)

    def test_all_replies_no_fragmentation(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        self.ifx.replies_with(None)
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())

        o = self.get_outcome(suite.ReducePMTUOnLinkGlobalTestCase)

        self.assertCheckFails(o)

    def test_all_replies_round1_with_fragmentation(self):
        self.ifx.replies_with(fragment6(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoReply(), 1500, True), 1280))

        o = self.get_outcome(suite.ReducePMTUOnLinkGlobalTestCase)

        self.assertCheckFails(o)
        