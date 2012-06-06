from contrib.rfc2711 import unrecognized_value as suite
from scapy.all import *
from veripy.testability import ComplianceTestTestCase


class UnrecognizedValueTestCase(ComplianceTestTestCase):

    def test_rut_does_not_forward_the_echo_request(self):
        o = self.get_outcome(suite.UnrecognizedValueTestCase)
        
        self.assertCheckPasses(o)
    
    def test_rut_forwards_the_echo_request(self):
        self.ifx.replies_with(IPv6(src=str(self.tn1.global_ip()), dst="ff02::4")/ICMPv6EchoRequest(), to=self.ify)

        o = self.get_outcome(suite.UnrecognizedValueTestCase)

        self.assertCheckFails(o)
        