from contrib.rfc4443 import unknown_informational_message_type as suite
from scapy.all import *
from veripy.testability import ComplianceTestTestCase


class UnknownInformationalMessageTypeTestCase(ComplianceTestTestCase):
    
    def test_unrecognized_next_header_valid(self):
        o = self.get_outcome(suite.UnknownInformationalMessageTypeTestCase)

        self.assertCheckPasses(o)
    
    def test_unrecognized_next_header_reply(self):   
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        
        o = self.get_outcome(suite.UnknownInformationalMessageTypeTestCase)
        
        self.assertCheckFails(o)
        