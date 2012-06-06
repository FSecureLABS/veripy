from contrib.rfc2460 import stub_fragment_header as suite
from scapy.all import *
from veripy.testability import ComplianceTestTestCase

class StubFragmentHeaderTestCaseTestCase(ComplianceTestTestCase):

    def test_stub_fragment_header(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        
        o = self.get_outcome(suite.StubFragmentHeaderTestCase)
        
        self.assertCheckPasses(o)
    
    def test_stub_fragment_header_no_reply(self):
        o = self.get_outcome(suite.StubFragmentHeaderTestCase)

        self.assertCheckFails(o)

    def test_stub_fragment_header_fragment_header(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply()/IPv6ExtHdrFragment())

        o = self.get_outcome(suite.StubFragmentHeaderTestCase)

        self.assertCheckFails(o)
