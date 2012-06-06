from contrib.rfc2460 import fragment_header_mbit_set_payload_length_invalid as suite
from scapy.all import *
from veripy.testability import ComplianceTestTestCase


class FragmentHeaderMBitSetPayloadLengthInvalidTestCase(ComplianceTestTestCase):
    
    def test_fragment_header_m_bit_set_payload_length_invalid(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ParamProblem(code=0, ptr=4))
        
        o = self.get_outcome(suite.FragmentHeaderMBitSetPayloadLengthInvalidTestCase)
        
        self.assertCheckPasses(o)
    
    def test_fragment_header_m_bit_set_payload_length_invalid_incorrect_code(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ParamProblem(code=5, ptr=4))

        o = self.get_outcome(suite.FragmentHeaderMBitSetPayloadLengthInvalidTestCase)

        self.assertCheckFails(o)

    def test_fragment_header_m_bit_set_payload_length_invalid_incorrect_pointer(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ParamProblem(code=0, ptr=2))

        o = self.get_outcome(suite.FragmentHeaderMBitSetPayloadLengthInvalidTestCase)

        self.assertCheckFails(o)
        
    def test_fragment_header_m_bit_set_payload_length_invalid_reply(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())

        o = self.get_outcome(suite.FragmentHeaderMBitSetPayloadLengthInvalidTestCase)

        self.assertCheckFails(o)
