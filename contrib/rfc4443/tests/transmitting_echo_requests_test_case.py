from contrib.rfc4443 import transmitting_echo_requests as suite
from scapy.all import *
from veripy.testability import ComplianceTestTestCase


class TransmittingEchoRequestsTestCase(ComplianceTestTestCase):
    
    def test_passive_node(self):
        self.ui.inputs.append('y')
        
        o = self.get_outcome(suite.TransmittingEchoRequestsTestCase)

        self.assertCheckFails(o)
    
    def test_valid_request(self):
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoRequest(), 0)
        self.ui.inputs.append('n')
        self.ui.inputs.append('y')
        
        o = self.get_outcome(suite.TransmittingEchoRequestsTestCase)

        self.assertCheckPasses(o)
    
    def test_address_invalid(self):
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoRequest(), 0)
        self.ui.inputs.append('n')
        self.ui.inputs.append('y')
        
        o = self.get_outcome(suite.TransmittingEchoRequestsTestCase)

        self.assertCheckFails(o)
    
    def test_code_invalid(self):
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoRequest(code=1), 0)
        self.ui.inputs.append('n')
        self.ui.inputs.append('y')
        
        o = self.get_outcome(suite.TransmittingEchoRequestsTestCase)

        self.assertCheckFails(o)
    
    def test_checksum_invalid(self):
        self.ifx.sends(self.break_checksum(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoRequest()), 0)
        self.ui.inputs.append('n')
        self.ui.inputs.append('y')
        
        o = self.get_outcome(suite.TransmittingEchoRequestsTestCase)

        self.assertCheckFails(o)
    
    def test_type_invalid(self):
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoRequest(type=127), 0)
        self.ui.inputs.append('n')
        self.ui.inputs.append('y')
        
        o = self.get_outcome(suite.TransmittingEchoRequestsTestCase)

        self.assertCheckFails(o)
        
    def test_user_response_invalid(self):
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoRequest(), 0)
        self.ui.inputs.append('n')
        self.ui.inputs.append('n')
        
        o = self.get_outcome(suite.TransmittingEchoRequestsTestCase)

        self.assertCheckFails(o)
        
    def test_no_reply(self):
        self.ui.inputs.append('n')
        self.ui.inputs.append('y')
        
        o = self.get_outcome(suite.TransmittingEchoRequestsTestCase)

        self.assertCheckFails(o)
    