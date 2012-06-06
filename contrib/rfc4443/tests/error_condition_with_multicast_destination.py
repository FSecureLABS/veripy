from contrib.rfc4443 import error_condition_with_multicast_destination as suite
from scapy.all import *
from veripy.testability import ComplianceTestTestCase


class UDPPortUnreachableTestCase(ComplianceTestTestCase):

    def test_port_unreachable_valid_reply(self):
        self.ui.inputs.append('n')

        o = self.get_outcome(suite.UDPPortUnreachableTestCase)

        self.assertCheckPasses(o)
        
        
    def test_port_unreachable_invalid_user_response(self):
        self.ui.inputs.append('y')
        
        o = self.get_outcome(suite.UDPPortUnreachableTestCase)

        self.assertCheckFails(o)
        
        
    def test_port_unreachable_dest_unreachable_reply(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6DestUnreach())
        self.ui.inputs.append('n')
        
        o = self.get_outcome(suite.UDPPortUnreachableTestCase)

        self.assertCheckFails(o)
        

class EchoRequestReassemblyTimeoutTestCase(ComplianceTestTestCase):

    def test_reassembly_timeout_valid_reply(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())

        o = self.get_outcome(suite.EchoRequestReassemblyTimeoutTestCase)

        self.assertCheckPasses(o)
        
    
    def test_reassembly_timeout_invalid_reply(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6TimeExceeded())
        
        o = self.get_outcome(suite.EchoRequestReassemblyTimeoutTestCase)

        self.assertCheckFails(o)
        