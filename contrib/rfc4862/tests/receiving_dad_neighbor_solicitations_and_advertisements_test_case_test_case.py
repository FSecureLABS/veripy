from contrib.rfc4862 import receiving_dad_neighbor_solicitations_and_advertisements as suite
from scapy.all import *
from veripy.testability import ComplianceTestTestCase


class ReceivingDadNeighborSolicitationsAndAdvertisementsTestCaseTestCase(ComplianceTestTestCase):

#
# DAD NS target is not UUT
#

    def test_dad_ns_target_is_not_uut_responds_with_both_nas(self):
        solicited_node_multicast = inet_ntop(socket.AF_INET6, in6_getnsma(inet_pton(socket.AF_INET6, str(self.ifx.link_local_ip()))))

        self.ifx.sends(IPv6(src="::", dst=solicited_node_multicast)/ICMPv6ND_NS(tgt=str(self.ifx.link_local_ip())),1)

        self.ifx.replies_with(None) # Don't reply to NS
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply()) # reply to ping
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1")/ICMPv6ND_NA()) # NA in response to UUT ip NS sent by veripy
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1")/ICMPv6ND_NA()) # NA in response to UUT ip NS sent by veripy

        self.ui.inputs.append('y') # is dad supported?
        self.ui.inputs.append('y') # restart the interface

        o = self.get_outcome(suite.ReceivesDadNsTargetIsNotUutTestCase)
        self.assertCheckPasses(o)
#
    def test_dad_ns_target_is_not_uut_responds_with_first_nas(self):
        solicited_node_multicast = inet_ntop(socket.AF_INET6, in6_getnsma(inet_pton(socket.AF_INET6, str(self.ifx.link_local_ip()))))

        self.ifx.sends(IPv6(src="::", dst=solicited_node_multicast)/ICMPv6ND_NS(tgt=str(self.ifx.link_local_ip())),1)

        self.ifx.replies_with(None) # Don't reply to NS
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply()) # reply to ping
        self.ifx.replies_with(IPv6(src=self.ifx.link_local_ip(), dst="ff02::1")/ICMPv6ND_NA()) # NA in response to UUT ip NS sent by veripy
        self.ifx.replies_with(None) # No NA in response to UUT ip NS sent by veripy

        self.ui.inputs.append('y') # is dad supported?
        self.ui.inputs.append('y') # restart the interface
        o = self.get_outcome(suite.ReceivesDadNsTargetIsNotUutTestCase)
        self.assertCheckFails(o)

    def test_dad_ns_target_is_not_uut_responds_with_second_nas(self):
        solicited_node_multicast = inet_ntop(socket.AF_INET6, in6_getnsma(inet_pton(socket.AF_INET6, str(self.ifx.link_local_ip()))))

        self.ifx.sends(IPv6(src="::", dst=solicited_node_multicast)/ICMPv6ND_NS(tgt=str(self.ifx.link_local_ip())),1)

        self.ifx.replies_with(None) # Don't reply to NS
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply()) # reply to ping
        self.ifx.replies_with(None) # NO NA in response to UUT ip NS sent by veripy
        self.ifx.replies_with(IPv6(src=self.ifx.link_local_ip(), dst="ff02::1")/ICMPv6ND_NA()) # NA in response to UUT ip NS sent by veripy

        self.ui.inputs.append('y') # is dad supported?
        self.ui.inputs.append('y') # restart the interface

        o = self.get_outcome(suite.ReceivesDadNsTargetIsNotUutTestCase)
        self.assertCheckFails(o)

    def test_dad_ns_target_is_not_uut_responds_with_to_initial_ns(self):
        solicited_node_multicast = inet_ntop(socket.AF_INET6, in6_getnsma(inet_pton(socket.AF_INET6, str(self.ifx.link_local_ip()))))

        self.ifx.sends(IPv6(src="::", dst=solicited_node_multicast)/ICMPv6ND_NS(tgt=str(self.ifx.link_local_ip())),1)

        self.ifx.replies_with(IPv6(src=self.ifx.link_local_ip(), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NA()) #Replies to NS
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply()) # reply to ping
        self.ifx.replies_with(IPv6(src=self.ifx.link_local_ip(), dst="ff02::1")/ICMPv6ND_NA()) # NA in response to UUT ip NS sent by veripy
        self.ifx.replies_with(IPv6(src=self.ifx.link_local_ip(), dst="ff02::1")/ICMPv6ND_NA()) # NA in response to UUT ip NS sent by veripy


        self.ui.inputs.append('y') # is dad supported?
        self.ui.inputs.append('y') # restart the interface
        o = self.get_outcome(suite.ReceivesDadNsTargetIsNotUutTestCase)
        self.assertCheckFails(o)

#
# DAD NS target is UUT
#
    def test_dad_ns_target_is_uut_responds_with_no_nas(self):
        solicited_node_multicast = inet_ntop(socket.AF_INET6, in6_getnsma(inet_pton(socket.AF_INET6, str(self.ifx.link_local_ip()))))

        self.ifx.sends(IPv6(src="::", dst=solicited_node_multicast)/ICMPv6ND_NS(tgt=str(self.ifx.link_local_ip())),1)

        self.ifx.replies_with(None)
        self.ifx.replies_with(None) # reply to ping
        self.ifx.replies_with(None) # NA in response to UUT ip NS sent by veripy
        self.ifx.replies_with(None) # NA in response to UUT ip NS sent by veripy

        self.ui.inputs.append('y') # is dad supported?
        self.ui.inputs.append('y') # restart the interface

        o = self.get_outcome(suite.ReceivesDadNsTargetIsUutTestCase)
        self.assertCheckPasses(o)

    def test_dad_ns_target_is_uut_responds_replies_with_ping(self):
        solicited_node_multicast = inet_ntop(socket.AF_INET6, in6_getnsma(inet_pton(socket.AF_INET6, str(self.ifx.link_local_ip()))))

        self.ifx.sends(IPv6(src="::", dst=solicited_node_multicast)/ICMPv6ND_NS(tgt=str(self.ifx.link_local_ip())),1)

        self.ifx.replies_with(None)
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply()) # reply to ping
        self.ifx.replies_with(None) # NA in response to UUT ip NS sent by veripy
        self.ifx.replies_with(None) # NA in response to UUT ip NS sent by veripy

        self.ui.inputs.append('y') # is dad supported?
        self.ui.inputs.append('y') # restart the interface

        o = self.get_outcome(suite.ReceivesDadNsTargetIsUutTestCase)
        self.assertCheckFails(o)

    def test_dad_ns_target_is_uut_responds_sends_router_solicitation(self):
        solicited_node_multicast = inet_ntop(socket.AF_INET6, in6_getnsma(inet_pton(socket.AF_INET6, str(self.ifx.link_local_ip()))))

        self.ifx.sends(IPv6(src="::", dst=solicited_node_multicast)/ICMPv6ND_NS(tgt=str(self.ifx.link_local_ip())),1)

        self.ifx.replies_with(None)
        self.ifx.replies_with(None) # reply to ping
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::2" )/ICMPv6ND_RS(),6) # sends out router solicit
        self.ifx.replies_with(None) # NA in response to UUT ip NS sent by veripy
        self.ifx.replies_with(None) # NA in response to UUT ip NS sent by veripy

        self.ui.inputs.append('y') # is dad supported?
        self.ui.inputs.append('y') # restart the interface

        o = self.get_outcome(suite.ReceivesDadNsTargetIsUutTestCase)
        self.assertCheckFails(o)

    def test_dad_ns_target_is_uut_responds_sends_neighbor_advertisement_1(self):
        solicited_node_multicast = inet_ntop(socket.AF_INET6, in6_getnsma(inet_pton(socket.AF_INET6, str(self.ifx.link_local_ip()))))

        self.ifx.sends(IPv6(src="::", dst=solicited_node_multicast)/ICMPv6ND_NS(tgt=str(self.ifx.link_local_ip())),1)

        self.ifx.replies_with(None)
        self.ifx.replies_with(None) # reply to ping
        self.ifx.replies_with(IPv6(src=self.ifx.link_local_ip(), dst="ff02::1")/ICMPv6ND_NA()) # NA in response to UUT ip NS sent by veripy
        self.ifx.replies_with(None) # NA in response to UUT ip NS sent by veripy

        self.ui.inputs.append('y') # is dad supported?
        self.ui.inputs.append('y') # restart the interface

        o = self.get_outcome(suite.ReceivesDadNsTargetIsUutTestCase)
        self.assertCheckFails(o)

    def test_dad_ns_target_is_uut_responds_sends_neighbor_advertisement_2(self):
        solicited_node_multicast = inet_ntop(socket.AF_INET6, in6_getnsma(inet_pton(socket.AF_INET6, str(self.ifx.link_local_ip()))))

        self.ifx.sends(IPv6(src="::", dst=solicited_node_multicast)/ICMPv6ND_NS(tgt=str(self.ifx.link_local_ip())),1)

        self.ifx.replies_with(None)
        self.ifx.replies_with(None) # reply to ping
        self.ifx.replies_with(None) # NA in response to UUT ip NS sent by veripy
        self.ifx.replies_with(IPv6(src=self.ifx.link_local_ip(), dst="ff02::1")/ICMPv6ND_NA()) # NA in response to UUT ip NS sent by veripy

        self.ui.inputs.append('y') # is dad supported?
        self.ui.inputs.append('y') # restart the interface

        o = self.get_outcome(suite.ReceivesDadNsTargetIsUutTestCase)
        self.assertCheckFails(o)

##
# DAD NA target is NOT UUT
#
    def test_dad_na_target_is_not_uut_responds_with_both_nas(self):
        solicited_node_multicast = inet_ntop(socket.AF_INET6, in6_getnsma(inet_pton(socket.AF_INET6, str(self.ifx.link_local_ip()))))

        self.ifx.sends(IPv6(src="::", dst=solicited_node_multicast)/ICMPv6ND_NS(tgt=str(self.ifx.link_local_ip())),1)

        self.ifx.replies_with(None) # Don't reply to NS
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply()) # reply to ping
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1")/ICMPv6ND_NA()) # NA in response to UUT ip NS sent by veripy
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1")/ICMPv6ND_NA()) # NA in response to UUT ip NS sent by veripy

        self.ui.inputs.append('y') # is dad supported?
        self.ui.inputs.append('y') # restart the interface

        o = self.get_outcome(suite.ReceivesDadNaTargetIsNotUutTestCase)
        self.assertCheckPasses(o)

    def test_dad_na_target_is_not_uut_responds_with_first_nas(self):
        solicited_node_multicast = inet_ntop(socket.AF_INET6, in6_getnsma(inet_pton(socket.AF_INET6, str(self.ifx.link_local_ip()))))

        self.ifx.sends(IPv6(src="::", dst=solicited_node_multicast)/ICMPv6ND_NS(tgt=str(self.ifx.link_local_ip())),1)

        self.ifx.replies_with(None) # Don't reply to NS
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply()) # reply to ping
        self.ifx.replies_with(IPv6(src=self.ifx.link_local_ip(), dst="ff02::1")/ICMPv6ND_NA()) # NA in response to UUT ip NS sent by veripy
        self.ifx.replies_with(None) # No NA in response to UUT ip NS sent by veripy

        self.ui.inputs.append('y') # is dad supported?
        self.ui.inputs.append('y') # restart the interface
        o = self.get_outcome(suite.ReceivesDadNaTargetIsNotUutTestCase)
        self.assertCheckFails(o)

    def test_dad_na_target_is_not_uut_responds_with_second_nas(self):
        solicited_node_multicast = inet_ntop(socket.AF_INET6, in6_getnsma(inet_pton(socket.AF_INET6, str(self.ifx.link_local_ip()))))

        self.ifx.sends(IPv6(src="::", dst=solicited_node_multicast)/ICMPv6ND_NS(tgt=str(self.ifx.link_local_ip())),1)

        self.ifx.replies_with(None) # Don't reply to NS
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply()) # reply to ping
        self.ifx.replies_with(None) # NO NA in response to UUT ip NS sent by veripy
        self.ifx.replies_with(IPv6(src=self.ifx.link_local_ip(), dst="ff02::1")/ICMPv6ND_NA()) # NA in response to UUT ip NS sent by veripy

        self.ui.inputs.append('y') # is dad supported?
        self.ui.inputs.append('y') # restart the interface

        o = self.get_outcome(suite.ReceivesDadNaTargetIsNotUutTestCase)
        self.assertCheckFails(o)

#    def test_dad_na_target_is_not_uut_responds_with_to_initial_na(self):
#        solicited_node_multicast = inet_ntop(socket.AF_INET6, in6_getnsma(inet_pton(socket.AF_INET6, str(self.ifx.link_local_ip()))))
#
#        self.ifx.sends(IPv6(src="::", dst=solicited_node_multicast)/ICMPv6ND_NS(tgt=str(self.ifx.link_local_ip())),1)
#
#        self.ifx.replies_with(IPv6(src=self.ifx.link_local_ip(), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NA()) #Replies to NS
#        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply()) # reply to ping
#        self.ifx.replies_with(IPv6(src=self.ifx.link_local_ip(), dst=solicited_node_multicast)/ICMPv6ND_NA()) # NA in response to UUT ip NS sent by veripy
#        self.ifx.replies_with(IPv6(src=self.ifx.link_local_ip(), dst=solicited_node_multicast)/ICMPv6ND_NA()) # NA in response to UUT ip NS sent by veripy
#
#
#        self.ui.inputs.append('y') # is dad supported?
#        self.ui.inputs.append('y') # restart the interface
#        o = self.get_outcome(suite.ReceivesDadNaTargetIsNotUutTestCase)
#        self.assertCheckFails(o)


#
# DAD NA target is UUT
#

    def test_dad_na_target_is_uut_responds_with_no_nas(self):
        solicited_node_multicast = inet_ntop(socket.AF_INET6, in6_getnsma(inet_pton(socket.AF_INET6, str(self.ifx.link_local_ip()))))

        self.ifx.sends(IPv6(src="::", dst=solicited_node_multicast)/ICMPv6ND_NS(tgt=str(self.ifx.link_local_ip())),1)

        #self.ifx.replies_with(None)
        self.ifx.replies_with(None) # reply to ping
        self.ifx.replies_with(None) # NA in response to UUT ip NS sent by veripy
        self.ifx.replies_with(None) # NA in response to UUT ip NS sent by veripy

        self.ui.inputs.append('y') # is dad supported?
        self.ui.inputs.append('y') # restart the interface

        o = self.get_outcome(suite.ReceivesDadNaTargetIsUutTestCase)
        self.assertCheckPasses(o)

#    def test_dad_na_target_is_uut_responds_replies_with_ping(self):
#        solicited_node_multicast = inet_ntop(socket.AF_INET6, in6_getnsma(inet_pton(socket.AF_INET6, str(self.ifx.link_local_ip()))))
#
#        self.ifx.sends(IPv6(src="::", dst=solicited_node_multicast)/ICMPv6ND_NS(tgt=str(self.ifx.link_local_ip())),1)
#
#        self.ifx.replies_with(None)
#        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply()) # reply to ping
#        self.ifx.replies_with(None) # NA in response to UUT ip NS sent by veripy
#        self.ifx.replies_with(None) # NA in response to UUT ip NS sent by veripy
#
#        self.ui.inputs.append('y') # is dad supported?
#        self.ui.inputs.append('y') # restart the interface
#
#        o = self.get_outcome(suite.ReceivesDadNaTargetIsUutTestCase)
#        self.assertCheckFails(o)
#
#    def test_dad_na_target_is_uut_responds_sends_router_solicitation(self):
#        solicited_node_multicast = inet_ntop(socket.AF_INET6, in6_getnsma(inet_pton(socket.AF_INET6, str(self.ifx.link_local_ip()))))
#
#        self.ifx.sends(IPv6(src="::", dst=solicited_node_multicast)/ICMPv6ND_NS(tgt=str(self.ifx.link_local_ip())),1)
#
#        self.ifx.replies_with(None)
#        self.ifx.replies_with(None) # reply to ping
#        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::2" )/ICMPv6ND_RS(),6) # sends out router solicit
#        self.ifx.replies_with(None) # NA in response to UUT ip NS sent by veripy
#        self.ifx.replies_with(None) # NA in response to UUT ip NS sent by veripy
#
#        self.ui.inputs.append('y') # is dad supported?
#        self.ui.inputs.append('y') # restart the interface
#
#        o = self.get_outcome(suite.ReceivesDadNaTargetIsUutTestCase)
#        self.assertCheckFails(o)
#
#    def test_dad_na_target_is_uut_responds_sends_neighbor_advertisement_1(self):
#        solicited_node_multicast = inet_ntop(socket.AF_INET6, in6_getnsma(inet_pton(socket.AF_INET6, str(self.ifx.link_local_ip()))))
#
#        self.ifx.sends(IPv6(src="::", dst=solicited_node_multicast)/ICMPv6ND_NS(tgt=str(self.ifx.link_local_ip())),1)
#
#        self.ifx.replies_with(None)
#        self.ifx.replies_with(None) # reply to ping
#        self.ifx.replies_with(IPv6(src=self.ifx.link_local_ip(), dst=solicited_node_multicast)/ICMPv6ND_NA()) # NA in response to UUT ip NS sent by veripy
#        self.ifx.replies_with(None) # NA in response to UUT ip NS sent by veripy
#
#        self.ui.inputs.append('y') # is dad supported?
#        self.ui.inputs.append('y') # restart the interface
#
#        o = self.get_outcome(suite.ReceivesDadNaTargetIsUutTestCase)
#        self.assertCheckFails(o)
#
#    def test_dad_na_target_is_uut_responds_sends_neighbor_advertisement_2(self):
#        solicited_node_multicast = inet_ntop(socket.AF_INET6, in6_getnsma(inet_pton(socket.AF_INET6, str(self.ifx.link_local_ip()))))
#
#        self.ifx.sends(IPv6(src="::", dst=solicited_node_multicast)/ICMPv6ND_NS(tgt=str(self.ifx.link_local_ip())),1)
#
#        self.ifx.replies_with(None)
#        self.ifx.replies_with(None) # reply to ping
#        self.ifx.replies_with(None) # NA in response to UUT ip NS sent by veripy
#        self.ifx.replies_with(IPv6(src=self.ifx.link_local_ip(), dst=solicited_node_multicast)/ICMPv6ND_NA()) # NA in response to UUT ip NS sent by veripy
#
#        self.ui.inputs.append('y') # is dad supported?
#        self.ui.inputs.append('y') # restart the interface
#
#        o = self.get_outcome(suite.ReceivesDadNaTargetIsUutTestCase)
#        self.assertCheckFails(o)
        