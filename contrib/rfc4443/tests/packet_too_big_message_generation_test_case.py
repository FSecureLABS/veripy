from contrib.rfc4443 import packet_too_big_message_generation as suite
from scapy.all import *
from veripy.testability import ComplianceTestTestCase


class UnicastDestinationTestCase(ComplianceTestTestCase):
    
    def test_unicast_valid(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6PacketTooBig(code=0))

        o = self.get_outcome(suite.UnicastDestinationTestCase)

        self.assertCheckPasses(o)
    
    def test_unicast_no_reply(self):   
        o = self.get_outcome(suite.UnicastDestinationTestCase)

        self.assertCheckFails(o)
        
    def test_unicast_invalid_mtu_flag(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6PacketTooBig(code=0, mtu=1))

        o = self.get_outcome(suite.UnicastDestinationTestCase)

        self.assertCheckFails(o)
        
    def test_unicast_invalid_src(self):
        self.ifx.replies_with(IPv6(src="::", dst=str(self.tn1.global_ip()))/ICMPv6PacketTooBig(code=0))

        o = self.get_outcome(suite.UnicastDestinationTestCase)

        self.assertCheckFails(o)
        
    def test_unicast_invalid_dst(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst="::")/ICMPv6PacketTooBig(code=0))

        o = self.get_outcome(suite.UnicastDestinationTestCase)

        self.assertCheckFails(o)
        
    def test_unicast_invalid_layer(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip())))

        o = self.get_outcome(suite.UnicastDestinationTestCase)

        self.assertCheckFails(o)
        
    def test_unicast_invalid_code(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6PacketTooBig(code=1))

        o = self.get_outcome(suite.UnicastDestinationTestCase)

        self.assertCheckFails(o)
        
    def test_unicast_invalid_mtu(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6PacketTooBig(code=0)/Raw(load="a" * 1300))

        o = self.get_outcome(suite.UnicastDestinationTestCase)

        self.assertCheckFails(o)


class MulticastDestinationTestCase(ComplianceTestTestCase):

    def test_multicast_valid(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6PacketTooBig(code=0))
        self.ui.inputs.append('y')
        
        o = self.get_outcome(suite.MulticastDestinationTestCase)

        self.assertCheckPasses(o)
        
    def test_multicast_valid_not_multicast_router(self):        
        self.ui.inputs.append('n')
        
        o = self.get_outcome(suite.MulticastDestinationTestCase)

        self.assertCheckFails(o)
        
    def test_multicast_no_reply(self):   
        self.ui.inputs.append('y')
        
        o = self.get_outcome(suite.MulticastDestinationTestCase)

        self.assertCheckFails(o)
        
    def test_multicast_invalid_mtu_flag(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6PacketTooBig(code=0, mtu=1))
        self.ui.inputs.append('y')

        o = self.get_outcome(suite.MulticastDestinationTestCase)

        self.assertCheckFails(o)
        
    def test_multicast_invalid_src(self):
        self.ifx.replies_with(IPv6(src="::", dst=str(self.tn1.global_ip()))/ICMPv6PacketTooBig(code=0))
        self.ui.inputs.append('y')

        o = self.get_outcome(suite.MulticastDestinationTestCase)

        self.assertCheckFails(o)
        
    def test_multicast_invalid_dst(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst="::")/ICMPv6PacketTooBig(code=0))
        self.ui.inputs.append('y')

        o = self.get_outcome(suite.MulticastDestinationTestCase)

        self.assertCheckFails(o)
        
    def test_multicast_invalid_layer(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip())))
        self.ui.inputs.append('y')

        o = self.get_outcome(suite.MulticastDestinationTestCase)

        self.assertCheckFails(o)
        
    def test_multicast_invalid_code(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6PacketTooBig(code=1))
        self.ui.inputs.append('y')

        o = self.get_outcome(suite.MulticastDestinationTestCase)

        self.assertCheckFails(o)
        
    def test_multicast_invalid_mtu(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6PacketTooBig(code=0)/Raw(load="a" * 1300))
        self.ui.inputs.append('y')

        o = self.get_outcome(suite.MulticastDestinationTestCase)

        self.assertCheckFails(o)