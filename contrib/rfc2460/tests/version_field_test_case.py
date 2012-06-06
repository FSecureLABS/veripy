from contrib.rfc2460 import version_field as suite
from scapy.all import *
from veripy.testability import ComplianceTestTestCase


class VersionFieldTestCase(ComplianceTestTestCase):

    def test_version_field_v0(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        
        o = self.get_outcome(suite.VersionFieldV00TestCase)

        self.assertCheckPasses(o)
    
    def test_version_field_v4(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())

        o = self.get_outcome(suite.VersionFieldV04TestCase)

        self.assertCheckPasses(o)

    def test_version_field_v5(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())

        o = self.get_outcome(suite.VersionFieldV05TestCase)

        self.assertCheckPasses(o)
    
    def test_version_field_v7(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())

        o = self.get_outcome(suite.VersionFieldV07TestCase)

        self.assertCheckPasses(o)

    def test_version_field_v15(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())

        o = self.get_outcome(suite.VersionFieldV15TestCase)

        self.assertCheckPasses(o)
    
    def test_version_field_v0_no_reply(self):
        o = self.get_outcome(suite.VersionFieldV00TestCase)

        self.assertCheckFails(o)

    def test_version_field_v4_no_reply(self):
        o = self.get_outcome(suite.VersionFieldV04TestCase)
        
        self.assertCheckFails(o)
    
    def test_version_field_v5_no_reply(self):
        o = self.get_outcome(suite.VersionFieldV05TestCase)

        self.assertCheckFails(o)

    def test_version_field_v7_no_reply(self):
        o = self.get_outcome(suite.VersionFieldV07TestCase)
        
        self.assertCheckFails(o)
        
    def test_version_field_v15_no_reply(self):
        o = self.get_outcome(suite.VersionFieldV15TestCase)

        self.assertCheckFails(o)
        