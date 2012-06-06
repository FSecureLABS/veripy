from contrib.rfc2460 import reassembly_time_exceeded as suite
from scapy.all import *
from veripy.testability import ComplianceTestTestCase


class ReassemblyTimeExceededTestCase(ComplianceTestTestCase):

    def setUp(self):
        super(ReassemblyTimeExceededTestCase, self).setUp()

        suite.fragment6 = self.fragment
    
    def fragment(self, packets, size):
        fragments = fragment6(packets, size)
        for f in fragments: f.id = 291
        
        return fragments

    def test_time_elapsed_between_fragments_less_than_sixty_seconds(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(None)
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply(id=291))
        
        o = self.get_outcome(suite.ReassemblyTimeExceededTimeElapsedBetweenFragmentsLessThanSixtySecondsTestCase)

        self.assertCheckPasses(o)
    
    def test_time_elapsed_between_fragments_less_than_sixty_seconds_no_reply(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(None)
        self.ifx.replies_with(None)

        o = self.get_outcome(suite.ReassemblyTimeExceededTimeElapsedBetweenFragmentsLessThanSixtySecondsTestCase)

        self.assertCheckFails(o)

    def test_time_exceeded_before_last_fragments_arrive(self):
        self.ifx.sends(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6TimeExceeded(code=1, unused=0), 60)
        
        o = self.get_outcome(suite.ReassemblyTimeExceededTimeElapsedBeforeLastFragmentsArriveTestCase)

        self.assertCheckPasses(o)
    
    def test_time_exceeded_before_last_fragments_arrive_reply(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(None)
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply(id=291))

        o = self.get_outcome(suite.ReassemblyTimeExceededTimeElapsedBeforeLastFragmentsArriveTestCase)

        self.assertCheckFails(o)
    
    def test_time_exceeded_before_last_fragments_arrive_no_time_exceeded_message(self):
        o = self.get_outcome(suite.ReassemblyTimeExceededTimeElapsedBeforeLastFragmentsArriveTestCase)

        self.assertCheckFails(o)
    
    def test_time_exceeded_before_last_fragments_arrive_incorrect_source(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(None)
        self.ifx.replies_with(IPv6(src=str(self.tn1.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6TimeExceeded(code=1, unused=0))

        o = self.get_outcome(suite.ReassemblyTimeExceededTimeElapsedBeforeLastFragmentsArriveTestCase)

        self.assertCheckFails(o)

    def test_time_exceeded_before_last_fragments_arrive_incorrect_destination(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(None)
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.ifx.global_ip()))/ICMPv6TimeExceeded(code=1, unused=0))
        
        o = self.get_outcome(suite.ReassemblyTimeExceededTimeElapsedBeforeLastFragmentsArriveTestCase)

        self.assertCheckFails(o)
    
    def test_time_exceeded_before_last_fragments_arrive_exceed_minimum_mtu(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(None)
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6TimeExceeded(code=1, unused=0)/("\0" * 3000))

        o = self.get_outcome(suite.ReassemblyTimeExceededTimeElapsedBeforeLastFragmentsArriveTestCase)

        self.assertCheckFails(o)
    
    def test_global_time_exceeded_only_first_fragment_received(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6TimeExceeded(code=1, unused=0))

        o = self.get_outcome(suite.ReassemblyTimeExceededGlobalTimeExceededOnlyFirstFragmentReceivedTestCase)

        self.assertCheckPasses(o)
    
    def test_global_time_exceeded_only_first_fragment_received_reply(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        
        o = self.get_outcome(suite.ReassemblyTimeExceededGlobalTimeExceededOnlyFirstFragmentReceivedTestCase)
        
        self.assertCheckFails(o)

    def test_global_time_exceeded_only_first_fragment_received_no_time_exceeded_message(self):
        o = self.get_outcome(suite.ReassemblyTimeExceededGlobalTimeExceededOnlyFirstFragmentReceivedTestCase)

        self.assertCheckFails(o)

    def test_global_time_exceeded_only_first_fragment_received_incorrect_unused_field(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6TimeExceeded(code=1, unused=5))
        
        o = self.get_outcome(suite.ReassemblyTimeExceededGlobalTimeExceededOnlyFirstFragmentReceivedTestCase)

        self.assertCheckFails(o)
    
    def test_global_time_exceeded_only_first_fragment_received_incorrect_source(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(IPv6(src=str(self.tn1.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6TimeExceeded(code=1, unused=0))

        o = self.get_outcome(suite.ReassemblyTimeExceededGlobalTimeExceededOnlyFirstFragmentReceivedTestCase)

        self.assertCheckFails(o)
    
    def test_global_time_exceeded_only_first_fragment_received_incorrect_destination(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.ifx.global_ip()))/ICMPv6TimeExceeded(code=1, unused=0))

        o = self.get_outcome(suite.ReassemblyTimeExceededGlobalTimeExceededOnlyFirstFragmentReceivedTestCase)

        self.assertCheckFails(o)
    
    def test_global_time_exceeded_only_first_fragment_received_exceed_minimum_mtu(self):
        self.ifx.replies_with(None)
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6TimeExceeded(code=1, unused=0)/("\0" * 3000))
        
        o = self.get_outcome(suite.ReassemblyTimeExceededGlobalTimeExceededOnlyFirstFragmentReceivedTestCase)

        self.assertCheckFails(o)
    
    def test_link_local_time_exceeded_only_first_fragment_received(self):
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6TimeExceeded(code=1, unused=0), 60)
        
        o = self.get_outcome(suite.ReassemblyTimeExceededLinkLocalTimeExceededOnlyFirstFragmentReceivedTestCase)
        
        self.assertCheckPasses(o)
    
    def test_link_local_time_exceeded_only_first_fragment_received_reply(self):
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply(), 60)

        o = self.get_outcome(suite.ReassemblyTimeExceededLinkLocalTimeExceededOnlyFirstFragmentReceivedTestCase)

        self.assertCheckFails(o)

    def test_link_local_time_exceeded_only_first_fragment_received_no_time_exceeded_message(self):
        o = self.get_outcome(suite.ReassemblyTimeExceededLinkLocalTimeExceededOnlyFirstFragmentReceivedTestCase)

        self.assertCheckFails(o)
    
    def test_link_local_time_exceeded_only_first_fragment_received_incorrect_unused_field(self):
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6TimeExceeded(code=1, unused=5), 60)

        o = self.get_outcome(suite.ReassemblyTimeExceededLinkLocalTimeExceededOnlyFirstFragmentReceivedTestCase)

        self.assertCheckFails(o)

    def test_link_local_time_exceeded_only_first_fragment_received_incorrect_source(self):
        self.ifx.sends(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6TimeExceeded(code=1, unused=0), 60)

        o = self.get_outcome(suite.ReassemblyTimeExceededLinkLocalTimeExceededOnlyFirstFragmentReceivedTestCase)

        self.assertCheckFails(o)

    def test_link_local_time_exceeded_only_first_fragment_received_incorrect_destination(self):
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.global_ip()))/ICMPv6TimeExceeded(code=1, unused=0), 60)

        o = self.get_outcome(suite.ReassemblyTimeExceededLinkLocalTimeExceededOnlyFirstFragmentReceivedTestCase)

        self.assertCheckFails(o)

    def test_link_local_time_exceeded_only_first_fragment_received_exceed_minimum_mtu(self):
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6TimeExceeded(code=1, unused=0)/("\0" * 3000), 60)

        o = self.get_outcome(suite.ReassemblyTimeExceededLinkLocalTimeExceededOnlyFirstFragmentReceivedTestCase)

        self.assertCheckFails(o)
    
    def test_time_exceeded_only_second_fragment_received(self):
        o = self.get_outcome(suite.ReassemblyTimeExceededTimeExceededOnlySecondFragmentReceivedTestCase)

        self.assertCheckPasses(o)
    
    def test_time_exceeded_only_second_fragment_received_reply(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        
        o = self.get_outcome(suite.ReassemblyTimeExceededTimeExceededOnlySecondFragmentReceivedTestCase)
        
        self.assertCheckFails(o)
    
    def test_time_exceeded_only_second_fragment_received_time_exceeded_message(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6TimeExceeded(code=1, unused=0))

        o = self.get_outcome(suite.ReassemblyTimeExceededTimeExceededOnlySecondFragmentReceivedTestCase)

        self.assertCheckFails(o)
        