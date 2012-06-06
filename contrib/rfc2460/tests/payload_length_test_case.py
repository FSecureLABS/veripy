from contrib.rfc2460 import payload_length as suite
from scapy.all import *
from veripy.testability import ComplianceTestTestCase

class PayloadLengthTestCaseTestCase(ComplianceTestTestCase):

    def test_payload_length_odd(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        
        o = self.get_outcome(suite.PayloadLengthOddTestCase)
        
        self.assertCheckPasses(o)

    def test_payload_length_odd_no_reply(self):
        o = self.get_outcome(suite.PayloadLengthOddTestCase)
        
        self.assertCheckFails(o)
        
    def test_payload_length_even(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        
        o = self.get_outcome(suite.PayloadLengthEvenTestCase)

        self.assertCheckPasses(o)
    
    def test_payload_length_even_no_reply(self):
        o = self.get_outcome(suite.PayloadLengthEvenTestCase)
        
        self.assertCheckFails(o)

class RUTForwardsPayloadLengthOddTestCase(ComplianceTestTestCase):

    def test_echo_request_forwarded(self):
        self.ify.replies_with(IPv6(src=str(self.tn4.global_ip()), dst=str(self.tn1.global_ip()), plen=0x33, nh=58)/ICMPv6EchoRequest(), to=self.ifx)

        o = self.get_outcome(suite.RUTForwardsPayloadLengthOddTestCase)

        self.assertCheckPasses(o)

    def test_echo_request_not_forwarded(self):
        o = self.get_outcome(suite.RUTForwardsPayloadLengthOddTestCase)

        self.assertCheckFails(o)
        