from contrib.rfc4862 import address_autoconfiguration_and_dad as suite
from scapy.all import *
from veripy.testability import ComplianceTestTestCase


class AddressAutoconfigurationAndDadTestCaseTestCase(ComplianceTestTestCase):
    def test_sends_neighbor_solicitation(self):
        solicited_node_multicast = inet_ntop(socket.AF_INET6, in6_getnsma(inet_pton(socket.AF_INET6, str(self.ifx.link_local_ip()))))
        
        self.ifx.sends(IPv6(src="::", dst=solicited_node_multicast)/ICMPv6ND_NS(tgt=str(self.ifx.link_local_ip())),1)
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply()) # reply to ping
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1",)/ICMPv6ND_NA(),7)
        
        self.ui.inputs.append('y') # is dad supported?
        self.ui.inputs.append('y') # restart the interface
        o = self.get_outcome(suite.AddressAutoConfigurationAndDadTestCase)
        self.assertCheckPasses(o)

    def test_doesnt_sends_neighbor_solicitation(self):
        solicited_node_multicast = inet_ntop(socket.AF_INET6, in6_getnsma(inet_pton(socket.AF_INET6, str(self.ifx.link_local_ip()))))

        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply()) # reply to ping
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1",)/ICMPv6ND_NA(),7)

        self.ui.inputs.append('y') # is dad supported?
        self.ui.inputs.append('y') # restart the interface
        o = self.get_outcome(suite.AddressAutoConfigurationAndDadTestCase)
        self.assertCheckFails(o)

    def test_doesnt_sends_neighbor_advertisement(self):
        solicited_node_multicast = inet_ntop(socket.AF_INET6, in6_getnsma(inet_pton(socket.AF_INET6, str(self.ifx.link_local_ip()))))

        self.ifx.sends(IPv6(src="::", dst=solicited_node_multicast)/ICMPv6ND_NS(tgt=str(self.ifx.link_local_ip())),1)
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply()) # reply to ping


        self.ui.inputs.append('y') # is dad supported?
        self.ui.inputs.append('y') # restart the interface
        o = self.get_outcome(suite.AddressAutoConfigurationAndDadTestCase)
        self.assertCheckFails(o)
