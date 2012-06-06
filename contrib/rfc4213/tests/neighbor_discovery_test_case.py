from contrib.rfc4213 import neighbor_discovery as suite
from scapy.all import *
from veripy.testability import ComplianceTestTestCase


class RespondsToNUDProbeTestCase(ComplianceTestTestCase):
    def setUp(self):
        super(RespondsToNUDProbeTestCase, self).setUp()

        self.tn1.iface(0).ips.append("192.168.0.1")
        self.tn1.iface(0).ips.append("2002:c0a8:1::1")
        self.ifx.ips.append("192.168.0.5")
        self.ifx.ips.append("2002:c0a8:5::1")
        
        self.e = IP((IP(src=str(self.ifx.ip(type="v4")), dst=str(self.tn1.ip(type="v4")))/
                    IPv6(src=str(self.ifx.ip(type="6in4")), dst=str(self.tn1.ip(type="6in4")))/
                        ICMPv6ND_NA()).build())
    
    def test_response_to_nud_probe(self):
        self.ifx.replies_with(self.e)
        
        o = self.get_outcome(suite.RespondsToNUDProbeTestCase)
        
        self.assertCheckPasses(o)
    
    def test_no_response_to_nud_probe(self):
        o = self.get_outcome(suite.RespondsToNUDProbeTestCase)

        self.assertCheckFails(o)
        