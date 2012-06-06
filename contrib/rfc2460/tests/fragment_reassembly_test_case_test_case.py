from contrib.rfc2460 import fragment_reassembly as suite
from scapy.all import *
from veripy.testability import ComplianceTestTestCase


class FragmentReassemblyTestCaseTestCase(ComplianceTestTestCase):

    def setUp(self):
        super(FragmentReassemblyTestCaseTestCase, self).setUp()

        suite.fragment6 = self.fragment
    
    def fragment(self, packets, size):
        fragments = fragment6(packets, size)
        for f in fragments: f.id = 291

        return fragments

    def test_all_fragments_valid(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(None)
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply(id=291))

        o = self.get_outcome(suite.FragmentReassemblyAllFragmentsValidTestCase)
        
        self.assertCheckPasses(o)
    
    def test_all_fragments_valid_no_reply(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(None)
        self.ifx.replies_with(None)
        
        o = self.get_outcome(suite.FragmentReassemblyAllFragmentsValidTestCase)

        self.assertCheckFails(o)

    def test_all_fragments_valid_reply_after_packet_1(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply(id=291))
        self.ifx.replies_with(None)
        self.ifx.replies_with(None)

        o = self.get_outcome(suite.FragmentReassemblyAllFragmentsValidTestCase)

        self.assertCheckFails(o)

    def test_all_fragments_valid_reply_after_packet_2(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply(id=291))
        self.ifx.replies_with(None)

        o = self.get_outcome(suite.FragmentReassemblyAllFragmentsValidTestCase)

        self.assertCheckFails(o)
    
    def test_all_fragments_valid_in_reverse_order(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(None)
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply(id=291))

        o = self.get_outcome(suite.FragmentReassemblyAllFragmentsValidInReverseOrderTestCase)

        self.assertCheckPasses(o)

    def test_all_fragments_valid_in_reverse_order_no_reply(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(None)
        self.ifx.replies_with(None)
        
        o = self.get_outcome(suite.FragmentReassemblyAllFragmentsValidInReverseOrderTestCase)
        
        self.assertCheckFails(o)

    def test_all_fragments_valid_in_reverse_order_reply_after_packet_1(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply(id=291))
        self.ifx.replies_with(None)
        self.ifx.replies_with(None)

        o = self.get_outcome(suite.FragmentReassemblyAllFragmentsValidInReverseOrderTestCase)

        self.assertCheckFails(o)

    def test_all_fragments_valid_in_reverse_order_reply_after_packet_2(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply(id=291))
        self.ifx.replies_with(None)

        o = self.get_outcome(suite.FragmentReassemblyAllFragmentsValidInReverseOrderTestCase)

        self.assertCheckFails(o)

    def test_fragment_ids_differ_between_fragments(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(None)
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.ip()))/ICMPv6TimeExceeded())
        
        o = self.get_outcome(suite.FragmentReassemblyFragmentIDsDifferBetweenFragmentsTestCase)

        self.assertCheckPasses(o)

    def test_fragment_ids_differ_between_fragments_reply(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(None)
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.ip()))/ICMPv6EchoReply(id=291))

        o = self.get_outcome(suite.FragmentReassemblyFragmentIDsDifferBetweenFragmentsTestCase)

        self.assertCheckFails(o)

    def test_fragment_ids_differ_between_fragments_reply_after_packet_1(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.ip()))/ICMPv6EchoReply(id=291))
        self.ifx.replies_with(None)
        self.ifx.replies_with(None)

        o = self.get_outcome(suite.FragmentReassemblyFragmentIDsDifferBetweenFragmentsTestCase)

        self.assertCheckFails(o)

    def test_fragment_ids_differ_between_fragments_reply_after_packet_2(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.ip()))/ICMPv6EchoReply(id=291))
        self.ifx.replies_with(None)

        o = self.get_outcome(suite.FragmentReassemblyFragmentIDsDifferBetweenFragmentsTestCase)

        self.assertCheckFails(o)

    def test_fragment_ids_differ_between_fragments_no_time_exceeded_message(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(None)
        self.ifx.replies_with(None)

        o = self.get_outcome(suite.FragmentReassemblyFragmentIDsDifferBetweenFragmentsTestCase)

        self.assertCheckFails(o)
    
    def test_source_addresses_differ_between_fragments(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(None)
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.ip()))/ICMPv6TimeExceeded())

        o = self.get_outcome(suite.FragmentReassemblySourceAddressesDifferBetweenFragmentsTestCase)

        self.assertCheckPasses(o)

    def test_source_addresses_differ_between_fragments_reply(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(None)
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.ip()))/ICMPv6EchoReply())

        o = self.get_outcome(suite.FragmentReassemblySourceAddressesDifferBetweenFragmentsTestCase)

        self.assertCheckFails(o)

    def test_source_addresses_differ_between_fragments_reply_after_packet_1(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.ip()))/ICMPv6EchoReply())
        self.ifx.replies_with(None)
        self.ifx.replies_with(None)

        o = self.get_outcome(suite.FragmentReassemblySourceAddressesDifferBetweenFragmentsTestCase)

        self.assertCheckFails(o)

    def test_source_addresses_differ_between_fragments_reply_after_packet_2(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.ip()))/ICMPv6EchoReply())
        self.ifx.replies_with(None)

        o = self.get_outcome(suite.FragmentReassemblySourceAddressesDifferBetweenFragmentsTestCase)

        self.assertCheckFails(o)
    
    def test_source_addresses_differ_between_fragments_no_time_exceeded_message(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(None)
        self.ifx.replies_with(None)

        o = self.get_outcome(suite.FragmentReassemblySourceAddressesDifferBetweenFragmentsTestCase)

        self.assertCheckFails(o)

    def test_destination_addresses_differ_between_fragments(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(None)
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6TimeExceeded())

        o = self.get_outcome(suite.FragmentReassemblyDestinationAddressesDifferBetweenFragmentsTestCase)

        self.assertCheckPasses(o)
    
    def test_destination_addresses_differ_between_fragments_reply(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(None)
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.ip()))/ICMPv6EchoReply())

        o = self.get_outcome(suite.FragmentReassemblyDestinationAddressesDifferBetweenFragmentsTestCase)

        self.assertCheckFails(o)
    
    def test_destination_addresses_differ_between_fragments_no_time_exceeded_message(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(None)
        self.ifx.replies_with(None)

        o = self.get_outcome(suite.FragmentReassemblyDestinationAddressesDifferBetweenFragmentsTestCase)

        self.assertCheckFails(o)
    
    def test_reassemble_to_1500(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.ip()))/ICMPv6EchoReply())
        self.ifx.replies_with(None)
        self.ifx.replies_with(None)
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.ip()))/ICMPv6EchoReply(id=291))
        
        o = self.get_outcome(suite.FragmentReassemblyReassembleTo1500TestCase)
        
        self.assertCheckPasses(o)

    def test_reassemble_to_1500_no_first_reply(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(None)
        self.ifx.replies_with(None)
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.ip()))/ICMPv6EchoReply(id=291))

        o = self.get_outcome(suite.FragmentReassemblyReassembleTo1500TestCase)

        self.assertCheckFails(o)
    
    def test_reassemble_to_1500_no_second_reply(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.ip()))/ICMPv6EchoReply())
        self.ifx.replies_with(None)
        self.ifx.replies_with(None)
        self.ifx.replies_with(None)

        o = self.get_outcome(suite.FragmentReassemblyReassembleTo1500TestCase)

        self.assertCheckFails(o)

    def test_reassemble_to_1500_second_reply_after_packet_1(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.ip()))/ICMPv6EchoReply())
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.ip()))/ICMPv6EchoReply(id=291))
        self.ifx.replies_with(None)
        self.ifx.replies_with(None)

        o = self.get_outcome(suite.FragmentReassemblyReassembleTo1500TestCase)

        self.assertCheckFails(o)

    def test_reassemble_to_1500_second_reply_after_packet_2(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.ip()))/ICMPv6EchoReply())
        self.ifx.replies_with(None)
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.ip()))/ICMPv6EchoReply(id=291))
        self.ifx.replies_with(None)

        o = self.get_outcome(suite.FragmentReassemblyReassembleTo1500TestCase)
        
        self.assertCheckFails(o)
