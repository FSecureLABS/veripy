from contrib.rfc4213 import static_tunnel_fragmentation as suite
from scapy.all import *
from veripy import util
from veripy.testability import ComplianceTestTestCase


class ReassemblesTo1500TestCase(ComplianceTestTestCase):

    def setUp(self):
        super(ReassemblesTo1500TestCase, self).setUp()

        self.tn1.iface(0).ips.append("192.168.0.1")
        self.tn1.iface(0).ips.append("2002:c0a8:1::1")
        self.ifx.ips.append("192.168.0.5")
        self.ifx.ips.append("2002:c0a8:5::1")
    
    def test_reassembles_to_1500(self):
        u1, u2, u3 = fragment6( \
                        util.pad( \
                            IPv6(src=str(self.ifx.ip(type="6in4")), dst=str(self.tn1.ip(type="6in4")))/
                                IPv6ExtHdrFragment()/
                                    ICMPv6EchoReply(), 1500, True), 600)
        e1, e2, e3 = map(lambda x: IP(src=str(self.ifx.ip(type="v4")), dst=(self.tn1.ip(type="v4")))/x, [u1, u2, u3])

        self.ifx.replies_with(e1)
        self.ifx.replies_with(e2)
        self.ifx.replies_with(e3)
        
        o = self.get_outcome(suite.ReassemblesTo1500TestCase)
        
        self.assertCheckPasses(o)
    
    def test_reassembles_to_1500_no_reply(self):
        o = self.get_outcome(suite.ReassemblesTo1500TestCase)

        self.assertCheckFails(o)

                
class DontFragmentBitNotSetTestCase(ComplianceTestTestCase):

    def setUp(self):
        super(DontFragmentBitNotSetTestCase, self).setUp()

        self.tn1.iface(0).ips.append("192.168.0.1")
        self.tn1.iface(0).ips.append("2002:c0a8:1::1")
        self.ifx.ips.append("192.168.0.5")
        self.ifx.ips.append("2002:c0a8:5::1")

    def test_dont_fragment_bit_is_not_set(self):
        u1, u2, u3 = fragment6( \
                        util.pad( \
                            IPv6(src=str(self.ifx.ip(type="6in4")), dst=str(self.tn1.ip(type="6in4")))/
                                IPv6ExtHdrFragment()/
                                    ICMPv6EchoReply(), 1500, True), 600)
        e1, e2, e3 = map(lambda x: IP(src=str(self.ifx.ip(type="v4")), dst=(self.tn1.ip(type="v4")))/x, [u1, u2, u3])

        self.ifx.replies_with(e1)
        self.ifx.replies_with(e2)
        self.ifx.replies_with(e3)
        
        o = self.get_outcome(suite.DontFragmentBitNotSetTestCase)
        
        self.assertCheckPasses(o)
    
    def test_dont_fragment_bit_is_set(self):
        u1, u2, u3 = fragment6( \
                        util.pad( \
                            IPv6(src=str(self.ifx.ip(type="6in4")), dst=str(self.tn1.ip(type="6in4")))/
                                IPv6ExtHdrFragment()/
                                    ICMPv6EchoReply(), 1500, True), 600)
        e1, e2, e3 = map(lambda x: IP(src=str(self.ifx.ip(type="v4")), dst=(self.tn1.ip(type="v4")), flags=2)/x, [u1, u2, u3])

        self.ifx.replies_with(e1)
        self.ifx.replies_with(e2)
        self.ifx.replies_with(e3)

        o = self.get_outcome(suite.DontFragmentBitNotSetTestCase)

        self.assertCheckFails(o)
