from contrib.rfc4862 import validation_of_dad_neighbor_solicitations as suite
from scapy.all import *
from veripy.testability import ComplianceTestTestCase


class UutReceivesInvalidDadNsLength16TestCase(ComplianceTestTestCase):

    def setUp(self):
        super(UutReceivesInvalidDadNsLength16TestCase, self).setUp()
        
        self.solicited_node_multicast = inet_ntop(socket.AF_INET6, in6_getnsma(inet_pton(socket.AF_INET6, str(self.ifx.link_local_ip()))))
        self.initial_ns = IPv6(src="::", dst=self.solicited_node_multicast)/ICMPv6ND_NS(tgt=str(self.ifx.link_local_ip()))
        self.reply_to_ping = IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply()
        self.na_local_response = IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NA()
        self.na_multicast_response = IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1")/ICMPv6ND_NA()

        self.ui.inputs.append('y') # is dad supported?
        self.ui.inputs.append('y') # restart the interface

        self.test_case = suite.UutReceiveInvalidDadNsLength16TestCase

    def test_receives_solicited_na(self):
        self.ifx.sends(self.initial_ns, 0)

        self.ifx.replies_with(None)
        self.ifx.replies_with(self.reply_to_ping)
        self.ifx.replies_with(self.na_multicast_response)
        self.ifx.replies_with(self.na_local_response)

        o = self.get_outcome(self.test_case)
        self.assertCheckPasses(o)

    def test_only_receives_first_solicited_na(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(self.reply_to_ping)
        self.ifx.replies_with(self.na_multicast_response)
        self.ifx.replies_with(None)

        o = self.get_outcome(self.test_case)
        self.assertCheckFails(o)

    def test_only_receives_second_solicited_na(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(self.reply_to_ping)
        self.ifx.replies_with(None)
        self.ifx.replies_with(self.na_multicast_response)

        o = self.get_outcome(self.test_case)
        self.assertCheckFails(o)

    def test_receives_doesnt_reply_to_ping(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(None)
        self.ifx.replies_with(self.na_multicast_response)
        self.ifx.replies_with(self.na_local_response)

        o = self.get_outcome(self.test_case)
        self.assertCheckFails(o)

    def test_receives_stay_silent(self):
        self.ifx.replies_with(self.na_multicast_response)
        self.ifx.replies_with(None)
        self.ifx.replies_with(self.na_multicast_response)
        self.ifx.replies_with(self.na_local_response)

        o = self.get_outcome(self.test_case)
        self.assertCheckFails(o)

class UutReceivesInvalidDadNsHopLimit254TestCase(ComplianceTestTestCase):

    def setUp(self):
        super(UutReceivesInvalidDadNsHopLimit254TestCase, self).setUp()

        self.solicited_node_multicast = inet_ntop(socket.AF_INET6, in6_getnsma(inet_pton(socket.AF_INET6, str(self.ifx.link_local_ip()))))
        self.initial_ns = IPv6(src="::", dst=self.solicited_node_multicast)/ICMPv6ND_NS(tgt=str(self.ifx.link_local_ip()))
        self.reply_to_ping = IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply()
        self.na_local_response = IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NA()
        self.na_multicast_response = IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1")/ICMPv6ND_NA()

        self.ui.inputs.append('y') # is dad supported?
        self.ui.inputs.append('y') # restart the interface

        self.test_case = suite.UutReceivesInvalidDadNsHopLimit254TestCase

    def test_receives_solicited_na(self):
        self.ifx.sends(self.initial_ns, 0)

        self.ifx.replies_with(None)
        self.ifx.replies_with(self.reply_to_ping)
        self.ifx.replies_with(self.na_multicast_response)
        self.ifx.replies_with(self.na_local_response)

        o = self.get_outcome(self.test_case)
        self.assertCheckPasses(o)

    def test_only_receives_first_solicited_na(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(self.reply_to_ping)
        self.ifx.replies_with(self.na_multicast_response)
        self.ifx.replies_with(None)

        o = self.get_outcome(self.test_case)
        self.assertCheckFails(o)

    def test_only_receives_second_solicited_na(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(self.reply_to_ping)
        self.ifx.replies_with(None)
        self.ifx.replies_with(self.na_local_response)

        o = self.get_outcome(self.test_case)
        self.assertCheckFails(o)

    def test_receives_doesnt_reply_to_ping(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(None)
        self.ifx.replies_with(self.na_multicast_response)
        self.ifx.replies_with(self.na_local_response)

        o = self.get_outcome(self.test_case)
        self.assertCheckFails(o)

    def test_receives_stay_silent(self):
        self.ifx.replies_with(self.na_multicast_response)
        self.ifx.replies_with(None)
        self.ifx.replies_with(self.na_multicast_response)
        self.ifx.replies_with(self.na_local_response)

        o = self.get_outcome(self.test_case)
        self.assertCheckFails(o)

class UutReceivesInvalidDadNsDstIsUutTentTestCase(ComplianceTestTestCase):

    def setUp(self):
        super(UutReceivesInvalidDadNsDstIsUutTentTestCase, self).setUp()

        self.solicited_node_multicast = inet_ntop(socket.AF_INET6, in6_getnsma(inet_pton(socket.AF_INET6, str(self.ifx.link_local_ip()))))
        self.initial_ns = IPv6(src="::", dst=self.solicited_node_multicast)/ICMPv6ND_NS(tgt=str(self.ifx.link_local_ip()))
        self.reply_to_ping = IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply()
        self.na_local_response = IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NA()
        self.na_multicast_response = IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1")/ICMPv6ND_NA()

        self.ui.inputs.append('y') # is dad supported?
        self.ui.inputs.append('y') # restart the interface

        self.test_case = suite.UutReceivesInvalidDadNsDstIsUutTentTestCase

    def test_receives_solicited_na(self):
        self.ifx.sends(self.initial_ns, 0)

        self.ifx.replies_with(None)
        self.ifx.replies_with(self.reply_to_ping)
        self.ifx.replies_with(self.na_multicast_response)
        self.ifx.replies_with(self.na_local_response)

        o = self.get_outcome(self.test_case)
        self.assertCheckPasses(o)

    def test_only_receives_first_solicited_na(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(self.reply_to_ping)
        self.ifx.replies_with(self.na_multicast_response)
        self.ifx.replies_with(None)

        o = self.get_outcome(self.test_case)
        self.assertCheckFails(o)

    def test_only_receives_second_solicited_na(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(self.reply_to_ping)
        self.ifx.replies_with(None)
        self.ifx.replies_with(self.na_local_response)

        o = self.get_outcome(self.test_case)
        self.assertCheckFails(o)

    def test_receives_doesnt_reply_to_ping(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(None)
        self.ifx.replies_with(self.na_multicast_response)
        self.ifx.replies_with(self.na_local_response)

        o = self.get_outcome(self.test_case)
        self.assertCheckFails(o)

    def test_receives_stay_silent(self):
        self.ifx.replies_with(self.na_multicast_response)
        self.ifx.replies_with(None)
        self.ifx.replies_with(self.na_multicast_response)
        self.ifx.replies_with(self.na_local_response)

        o = self.get_outcome(self.test_case)
        self.assertCheckFails(o)

class UutReceivesInvalidDadNsDstIsAllNodeTestCase(ComplianceTestTestCase):

    def setUp(self):
        super(UutReceivesInvalidDadNsDstIsAllNodeTestCase, self).setUp()

        self.solicited_node_multicast = inet_ntop(socket.AF_INET6, in6_getnsma(inet_pton(socket.AF_INET6, str(self.ifx.link_local_ip()))))
        self.initial_ns = IPv6(src="::", dst=self.solicited_node_multicast)/ICMPv6ND_NS(tgt=str(self.ifx.link_local_ip()))
        self.reply_to_ping = IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply()
        self.na_local_response = IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NA()
        self.na_multicast_response = IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1")/ICMPv6ND_NA()

        self.ui.inputs.append('y') # is dad supported?
        self.ui.inputs.append('y') # restart the interface

        self.test_case = suite.UutReceivesInvalidDadNsDstIsAllNodeTestCase

    def test_receives_solicited_na(self):
        self.ifx.sends(self.initial_ns, 0)

        self.ifx.replies_with(None)
        self.ifx.replies_with(self.reply_to_ping)
        self.ifx.replies_with(self.na_multicast_response)
        self.ifx.replies_with(self.na_local_response)

        o = self.get_outcome(self.test_case)
        self.assertCheckPasses(o)

    def test_only_receives_first_solicited_na(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(self.reply_to_ping)
        self.ifx.replies_with(self.na_multicast_response)
        self.ifx.replies_with(None)

        o = self.get_outcome(self.test_case)
        self.assertCheckFails(o)

    def test_only_receives_second_solicited_na(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(self.reply_to_ping)
        self.ifx.replies_with(None)
        self.ifx.replies_with(self.na_local_response)

        o = self.get_outcome(self.test_case)
        self.assertCheckFails(o)

    def test_receives_doesnt_reply_to_ping(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(None)
        self.ifx.replies_with(self.na_multicast_response)
        self.ifx.replies_with(self.na_multicast_response)

        o = self.get_outcome(self.test_case)
        self.assertCheckFails(o)

    def test_receives_stay_silent(self):
        self.ifx.replies_with(self.na_multicast_response)
        self.ifx.replies_with(None)
        self.ifx.replies_with(self.na_multicast_response)
        self.ifx.replies_with(self.na_local_response)

        o = self.get_outcome(self.test_case)
        self.assertCheckFails(o)

class UutReceivesInvalidDadNsICMPCode1TestCase(ComplianceTestTestCase):

    def setUp(self):
        super(UutReceivesInvalidDadNsICMPCode1TestCase, self).setUp()

        self.solicited_node_multicast = inet_ntop(socket.AF_INET6, in6_getnsma(inet_pton(socket.AF_INET6, str(self.ifx.link_local_ip()))))
        self.initial_ns = IPv6(src="::", dst=self.solicited_node_multicast)/ICMPv6ND_NS(tgt=str(self.ifx.link_local_ip()))
        self.reply_to_ping = IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply()
        self.na_local_response = IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NA()
        self.na_multicast_response = IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1")/ICMPv6ND_NA()

        self.ui.inputs.append('y') # is dad supported?
        self.ui.inputs.append('y') # restart the interface

        self.test_case = suite.UutReceivesInvalidDadNsICMPCode1TestCase

    def test_receives_solicited_na(self):
        self.ifx.sends(self.initial_ns, 0)

        self.ifx.replies_with(None)
        self.ifx.replies_with(self.reply_to_ping)
        self.ifx.replies_with(self.na_multicast_response)
        self.ifx.replies_with(self.na_local_response)

        o = self.get_outcome(self.test_case)
        self.assertCheckPasses(o)

    def test_only_receives_first_solicited_na(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(self.reply_to_ping)
        self.ifx.replies_with(self.na_multicast_response)
        self.ifx.replies_with(None)

        o = self.get_outcome(self.test_case)
        self.assertCheckFails(o)

    def test_only_receives_second_solicited_na(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(self.reply_to_ping)
        self.ifx.replies_with(None)
        self.ifx.replies_with(self.na_local_response)

        o = self.get_outcome(self.test_case)
        self.assertCheckFails(o)

    def test_receives_doesnt_reply_to_ping(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(None)
        self.ifx.replies_with(self.na_multicast_response)
        self.ifx.replies_with(self.na_local_response)

        o = self.get_outcome(self.test_case)
        self.assertCheckFails(o)

    def test_receives_stay_silent(self):
        self.ifx.replies_with(self.na_multicast_response)
        self.ifx.replies_with(None)
        self.ifx.replies_with(self.na_multicast_response)
        self.ifx.replies_with(self.na_local_response)

        o = self.get_outcome(self.test_case)
        self.assertCheckFails(o)

class UutReceivesInvalidDadNsInvalidChecksumTestCase(ComplianceTestTestCase):

    def setUp(self):
        super(UutReceivesInvalidDadNsInvalidChecksumTestCase, self).setUp()

        self.solicited_node_multicast = inet_ntop(socket.AF_INET6, in6_getnsma(inet_pton(socket.AF_INET6, str(self.ifx.link_local_ip()))))
        self.initial_ns = IPv6(src="::", dst=self.solicited_node_multicast)/ICMPv6ND_NS(tgt=str(self.ifx.link_local_ip()))
        self.reply_to_ping = IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply()
        self.na_local_response = IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NA()
        self.na_multicast_response = IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1")/ICMPv6ND_NA()

        self.ui.inputs.append('y') # is dad supported?
        self.ui.inputs.append('y') # restart the interface

        self.test_case = suite.UutReceivesInvalidDadNsInvalidChecksumTestCase

    def test_receives_solicited_na(self):
        self.ifx.sends(self.initial_ns, 0)

        self.ifx.replies_with(None)
        self.ifx.replies_with(self.reply_to_ping)
        self.ifx.replies_with(self.na_multicast_response)
        self.ifx.replies_with(self.na_local_response)

        o = self.get_outcome(self.test_case)
        self.assertCheckPasses(o)

    def test_only_receives_first_solicited_na(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(self.reply_to_ping)
        self.ifx.replies_with(self.na_multicast_response)
        self.ifx.replies_with(None)

        o = self.get_outcome(self.test_case)
        self.assertCheckFails(o)

    def test_only_receives_second_solicited_na(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(self.reply_to_ping)
        self.ifx.replies_with(None)
        self.ifx.replies_with(self.na_local_response)

        o = self.get_outcome(self.test_case)
        self.assertCheckFails(o)

    def test_receives_doesnt_reply_to_ping(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(None)
        self.ifx.replies_with(self.na_multicast_response)
        self.ifx.replies_with(self.na_local_response)

        o = self.get_outcome(self.test_case)
        self.assertCheckFails(o)

    def test_receives_stay_silent(self):
        self.ifx.replies_with(self.na_multicast_response)
        self.ifx.replies_with(None)
        self.ifx.replies_with(self.na_multicast_response)
        self.ifx.replies_with(self.na_local_response)

        o = self.get_outcome(self.test_case)
        self.assertCheckFails(o)

class UutReceivesInvalidDadNsTargetMulticastTestCase(ComplianceTestTestCase):

    def setUp(self):
        super(UutReceivesInvalidDadNsTargetMulticastTestCase, self).setUp()

        self.solicited_node_multicast = inet_ntop(socket.AF_INET6, in6_getnsma(inet_pton(socket.AF_INET6, str(self.ifx.link_local_ip()))))
        self.initial_ns = IPv6(src="::", dst=self.solicited_node_multicast)/ICMPv6ND_NS(tgt=str(self.ifx.link_local_ip()))
        self.reply_to_ping = IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply()
        self.na_local_response = IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NA()
        self.na_multicast_response = IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1")/ICMPv6ND_NA()

        self.ui.inputs.append('y') # is dad supported?
        self.ui.inputs.append('y') # restart the interface

        self.test_case = suite.UutReceivesInvalidDadNsTargetMulticastTestCase

    def test_receives_solicited_na(self):
        self.ifx.sends(self.initial_ns, 0)

        self.ifx.replies_with(None)
        self.ifx.replies_with(self.reply_to_ping)
        self.ifx.replies_with(self.na_multicast_response)
        self.ifx.replies_with(self.na_local_response)

        o = self.get_outcome(self.test_case)
        self.assertCheckPasses(o)

    def test_only_receives_first_solicited_na(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(self.reply_to_ping)
        self.ifx.replies_with(self.na_multicast_response)
        self.ifx.replies_with(None)

        o = self.get_outcome(self.test_case)
        self.assertCheckFails(o)

    def test_only_receives_second_solicited_na(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(self.reply_to_ping)
        self.ifx.replies_with(None)
        self.ifx.replies_with(self.na_local_response)

        o = self.get_outcome(self.test_case)
        self.assertCheckFails(o)

    def test_receives_doesnt_reply_to_ping(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(None)
        self.ifx.replies_with(self.na_multicast_response)
        self.ifx.replies_with(self.na_local_response)

        o = self.get_outcome(self.test_case)
        self.assertCheckFails(o)

    def test_receives_stay_silent(self):
        self.ifx.replies_with(self.na_multicast_response)
        self.ifx.replies_with(None)
        self.ifx.replies_with(self.na_multicast_response)
        self.ifx.replies_with(self.na_local_response)

        o = self.get_outcome(self.test_case)
        self.assertCheckFails(o)

class UutReceivesInvalidDadNsContainsSLLTestCase(ComplianceTestTestCase):

    def setUp(self):
        super(UutReceivesInvalidDadNsContainsSLLTestCase, self).setUp()

        self.solicited_node_multicast = inet_ntop(socket.AF_INET6, in6_getnsma(inet_pton(socket.AF_INET6, str(self.ifx.link_local_ip()))))
        self.initial_ns = IPv6(src="::", dst=self.solicited_node_multicast)/ICMPv6ND_NS(tgt=str(self.ifx.link_local_ip()))
        self.reply_to_ping = IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply()
        self.na_local_response = IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NA()
        self.na_multicast_response = IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1")/ICMPv6ND_NA()

        self.ui.inputs.append('y') # is dad supported?
        self.ui.inputs.append('y') # restart the interface

        self.test_case = suite.UutReceivesInvalidDadNsContainsSLLTestCase

    def test_receives_solicited_na(self):
        self.ifx.sends(self.initial_ns, 0)

        self.ifx.replies_with(None)
        self.ifx.replies_with(self.reply_to_ping)
        self.ifx.replies_with(self.na_multicast_response)
        self.ifx.replies_with(self.na_local_response)

        o = self.get_outcome(self.test_case)
        self.assertCheckPasses(o)

    def test_only_receives_first_solicited_na(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(self.reply_to_ping)
        self.ifx.replies_with(self.na_multicast_response)
        self.ifx.replies_with(None)

        o = self.get_outcome(self.test_case)
        self.assertCheckFails(o)

    def test_only_receives_second_solicited_na(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(self.reply_to_ping)
        self.ifx.replies_with(None)
        self.ifx.replies_with(self.na_multicast_response)

        o = self.get_outcome(self.test_case)
        self.assertCheckFails(o)

    def test_receives_doesnt_reply_to_ping(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(None)
        self.ifx.replies_with(self.na_multicast_response)
        self.ifx.replies_with(self.na_local_response)

        o = self.get_outcome(self.test_case)
        self.assertCheckFails(o)

    def test_receives_stay_silent(self):
        self.ifx.replies_with(self.na_multicast_response)
        self.ifx.replies_with(None)
        self.ifx.replies_with(self.na_multicast_response)
        self.ifx.replies_with(self.na_local_response)

        o = self.get_outcome(self.test_case)
        self.assertCheckFails(o)



class UutReceivesValidDadNsContainsReservedFieldTestCase(ComplianceTestTestCase):

    def setUp(self):
        super(UutReceivesValidDadNsContainsReservedFieldTestCase, self).setUp()

        self.solicited_node_multicast = inet_ntop(socket.AF_INET6, in6_getnsma(inet_pton(socket.AF_INET6, str(self.ifx.link_local_ip()))))
        self.initial_ns = IPv6(src="::", dst=self.solicited_node_multicast)/ICMPv6ND_NS(tgt=str(self.ifx.link_local_ip()))
        self.reply_to_ping = IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply()
        self.na_local_response = IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NA()
        self.na_multicast_response = IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1")/ICMPv6ND_NA()

        self.ui.inputs.append('y') # is dad supported?
        self.ui.inputs.append('y') # restart the interface

        self.test_case = suite.UutReceivesValidDadNsContainsReservedFieldTestCase

    def test_receives_solicited_na(self):
        self.ifx.sends(self.initial_ns, 0)

        self.ifx.replies_with(None)
        self.ifx.replies_with(None)
        self.ifx.replies_with(None)
        self.ifx.replies_with(None)

        o = self.get_outcome(self.test_case)
        self.assertCheckPasses(o)

    def test_only_receives_first_solicited_na(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(self.reply_to_ping)
        self.ifx.replies_with(self.na_multicast_response)
        self.ifx.replies_with(None)

        o = self.get_outcome(self.test_case)
        self.assertCheckFails(o)

    def test_only_receives_second_solicited_na(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(self.reply_to_ping)
        self.ifx.replies_with(None)
        self.ifx.replies_with(self.na_local_response)

        o = self.get_outcome(self.test_case)
        self.assertCheckFails(o)

    def test_receives_doesnt_reply_to_ping(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(None)
        self.ifx.replies_with(self.na_multicast_response)
        self.ifx.replies_with(self.na_local_response)

        o = self.get_outcome(self.test_case)
        self.assertCheckFails(o)

    def test_receives_stay_silent(self):
        self.ifx.replies_with(self.na_multicast_response)
        self.ifx.replies_with(None)
        self.ifx.replies_with(self.na_multicast_response)
        self.ifx.replies_with(self.na_local_response)

        o = self.get_outcome(self.test_case)
        self.assertCheckFails(o)

class UutReceivesValidDadNsContainsTLLTestCase(ComplianceTestTestCase):

    def setUp(self):
        super(UutReceivesValidDadNsContainsTLLTestCase, self).setUp()

        self.solicited_node_multicast = inet_ntop(socket.AF_INET6, in6_getnsma(inet_pton(socket.AF_INET6, str(self.ifx.link_local_ip()))))
        self.initial_ns = IPv6(src="::", dst=self.solicited_node_multicast)/ICMPv6ND_NS(tgt=str(self.ifx.link_local_ip()))
        self.reply_to_ping = IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply()
        self.na_local_response = IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NA()
        self.na_multicast_response = IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1")/ICMPv6ND_NA()

        self.ui.inputs.append('y') # is dad supported?
        self.ui.inputs.append('y') # restart the interface

        self.test_case = suite.UutReceivesValidDadNsContainsTLLTestCase

    def test_receives_solicited_na(self):
        self.ifx.sends(self.initial_ns, 0)

        self.ifx.replies_with(None)
        self.ifx.replies_with(None)
        self.ifx.replies_with(None)
        self.ifx.replies_with(None)

        o = self.get_outcome(self.test_case)
        self.assertCheckPasses(o)

    def test_only_receives_first_solicited_na(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(self.reply_to_ping)
        self.ifx.replies_with(self.na_multicast_response)
        self.ifx.replies_with(None)

        o = self.get_outcome(self.test_case)
        self.assertCheckFails(o)

    def test_only_receives_second_solicited_na(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(self.reply_to_ping)
        self.ifx.replies_with(None)
        self.ifx.replies_with(self.na_local_response)

        o = self.get_outcome(self.test_case)
        self.assertCheckFails(o)

    def test_receives_doesnt_reply_to_ping(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(None)
        self.ifx.replies_with(self.na_multicast_response)
        self.ifx.replies_with(self.na_local_response)

        o = self.get_outcome(self.test_case)
        self.assertCheckFails(o)

    def test_receives_stay_silent(self):
        self.ifx.replies_with(self.na_multicast_response)
        self.ifx.replies_with(None)
        self.ifx.replies_with(self.na_multicast_response)
        self.ifx.replies_with(self.na_local_response)

        o = self.get_outcome(self.test_case)
        self.assertCheckFails(o)



