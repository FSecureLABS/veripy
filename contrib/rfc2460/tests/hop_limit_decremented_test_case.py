from contrib.rfc2460 import hop_limit_decremented as suite
from scapy.all import *
from veripy.testability import ComplianceTestTestCase


class HopLimitDecrementedTestCase(ComplianceTestTestCase):

    def test_correct_hop_limit(self):
        self.ifx.replies_with(IPv6(src=str(self.tn1.global_ip()), dst=str(self.tn4.global_ip()), hlim=14)/ICMPv6EchoRequest(), to=self.ify)

        o = self.get_outcome(suite.HopLimitDecrementTestCase)

        self.assertCheckPasses(o)

    def test_unchanged_hop_limit(self):
        self.ifx.replies_with(IPv6(src=str(self.tn1.global_ip()), dst=str(self.tn4.global_ip()), hlim=15)/ICMPv6EchoRequest(), to=self.ify)

        o = self.get_outcome(suite.HopLimitDecrementTestCase)

        self.assertCheckFails(o)

    def test_incorrect_hop_limit(self):
        self.ifx.replies_with(IPv6(src=str(self.tn1.global_ip()), dst=str(self.tn4.global_ip()), hlim=1)/ICMPv6EchoRequest(), to=self.ify)

        o = self.get_outcome(suite.HopLimitDecrementTestCase)

        self.assertCheckFails(o)

    def test_zero_hop_limit(self):
        self.ifx.replies_with(IPv6(src=str(self.tn1.global_ip()), dst=str(self.tn4.global_ip()), hlim=0)/ICMPv6EchoRequest(), to=self.ify)

        o = self.get_outcome(suite.HopLimitDecrementTestCase)

        self.assertCheckFails(o)

    def test_negative_hop_limit(self):
        self.ifx.replies_with(IPv6(src=str(self.tn1.global_ip()), dst=str(self.tn4.global_ip()), hlim=-14)/ICMPv6EchoRequest(), to=self.ify)

        o = self.get_outcome(suite.HopLimitDecrementTestCase)

        self.assertCheckFails(o)
        