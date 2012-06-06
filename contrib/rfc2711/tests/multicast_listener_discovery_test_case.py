from contrib.rfc2711 import multicast_listener_discovery as suite
from scapy.all import *
from veripy.testability import ComplianceTestTestCase

class MulticastListenerDiscoveryTestCase(ComplianceTestTestCase):

    def test_rut_forwards_echo_request_and_reply(self):
        self.ifx.replies_with(None)
        self.ify.replies_with(None)
        self.ifx.replies_with(IPv6(src=str(self.tn1.global_ip()), dst="ff02::3")/ICMPv6EchoRequest(), to=self.ify)
        self.ify.replies_with(IPv6(src=str(self.tn4.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply(), to=self.ifx)

        o = self.get_outcome(suite.MulticastListenerDiscoveryTestCase)

        self.assertCheckPasses(o)

    def test_rut_forwards_echo_request_before_the_mld_report(self):
        self.ifx.replies_with(IPv6(src=str(self.tn1.global_ip()), dst="ff02::3")/ICMPv6EchoRequest(), to=self.ify)

        o = self.get_outcome(suite.MulticastListenerDiscoveryTestCase)

        self.assertCheckFails(o)

    def test_rut_does_not_forward_echo_request(self):
        self.ifx.replies_with(None)
        self.ify.replies_with(None)

        o = self.get_outcome(suite.MulticastListenerDiscoveryTestCase)
        
        self.assertCheckFails(o)
    
    def test_rut_does_not_forward_echo_reply(self):
        self.ifx.replies_with(None)
        self.ify.replies_with(None)
        self.ifx.replies_with(IPv6(src=str(self.tn1.global_ip()), dst="ff02::3")/ICMPv6EchoRequest(), to=self.ify)
        
        o = self.get_outcome(suite.MulticastListenerDiscoveryTestCase)

        self.assertCheckFails(o)
    
    def test_rut_forwards_echo_reply_with_invalid_src(self):
        self.ifx.replies_with(None)
        self.ify.replies_with(None)
        self.ifx.replies_with(IPv6(src=str(self.tn1.global_ip()), dst="ff02::3")/ICMPv6EchoRequest(), to=self.ify)
        self.ify.replies_with(IPv6(src="ff02::3", dst=str(self.tn1.global_ip()))/ICMPv6EchoReply(), to=self.ifx)

        o = self.get_outcome(suite.MulticastListenerDiscoveryTestCase)

        self.assertCheckFails(o)
    
    def test_rut_forwards_echo_reply_with_invalid_dst(self):
        self.ifx.replies_with(None)
        self.ify.replies_with(None)
        self.ifx.replies_with(IPv6(src=str(self.tn1.global_ip()), dst="ff02::3")/ICMPv6EchoRequest(), to=self.ify)
        self.ify.replies_with(IPv6(src=str(self.tn4.global_ip()), dst="ff02::3")/ICMPv6EchoReply(), to=self.ifx)

        o = self.get_outcome(suite.MulticastListenerDiscoveryTestCase)

        self.assertCheckFails(o)
