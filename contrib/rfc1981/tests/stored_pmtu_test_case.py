from contrib.rfc1981 import stored_pmtu as suite
from scapy.all import *
from veripy import util
from veripy.testability import ComplianceTestTestCase



class StoredPMTUTestCase(ComplianceTestTestCase):

    def test_all_replies(self):
        # Step 14: We expect the NUT to respond to echo requests from TN1, TN2
        #          and TN3 with fragmented packets, because we have changed the
        #          MTU on the links.
        
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply(), 1500, True))
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6EchoReply(), 1500, True))
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn3.global_ip()))/ICMPv6EchoReply(), 1500, True))

        # Step 5: we have sent a Packet Too Big message from TN2, it gets no
        #         reply
        self.ifx.replies_with(None)
        
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply(), 1500, True))
        self.ifx.replies_with(fragment6(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoReply(), 1500, True), 1400))
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn3.global_ip()))/ICMPv6EchoReply(), 1500, True))

        # Step 10: we have sent a Packet Too Big message from TN3, it gets no
        #          reply
        self.ifx.replies_with(None)
        
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply(), 1500, True))
        self.ifx.replies_with(fragment6(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoReply(), 1500, True), 1400))
        self.ifx.replies_with(fragment6(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn3.global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoReply(), 1500, True), 1280))

        o = self.get_outcome(suite.StoredPMTUTestCase)

        self.assertCheckPasses(o)

    def test_all_replies_all_fragment_to_smallest_pmtu(self):
        # Step 14: We expect the NUT to respond to echo requests from TN1, TN2
        #          and TN3 with fragmented packets, because we have changed the
        #          MTU on the links.
        #          The NUT may use the smallest MTU for all destinations, so we
        #          should account for that too.

        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply(), 1500, True))
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6EchoReply(), 1500, True))
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn3.global_ip()))/ICMPv6EchoReply(), 1500, True))

        # Step 5: we have sent a Packet Too Big message from TN2, it gets no
        #         reply
        self.ifx.replies_with(None)

        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply(), 1500, True))
        self.ifx.replies_with(fragment6(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoReply(), 1500, True), 1400))
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn3.global_ip()))/ICMPv6EchoReply(), 1500, True))

        # Step 10: we have sent a Packet Too Big message from TN3, it gets no
        #          reply
        self.ifx.replies_with(None)

        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply(), 1500, True))
        self.ifx.replies_with(fragment6(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoReply(), 1500, True), 1280))
        self.ifx.replies_with(fragment6(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn3.global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoReply(), 1500, True), 1280))

        o = self.get_outcome(suite.StoredPMTUTestCase)

        self.assertCheckPasses(o)

    def test_no_replies(self):
        o = self.get_outcome(suite.StoredPMTUTestCase)

        self.assertCheckFails(o)
              
    def test_first_reply_from_tn2_missing(self):
        # Step  4: We expect the NUT to respond to echo requests from TN1, TN2
        #       and TN3.
        #       We actually, only deliver the reply from TN1.

        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply(), 1500, True))

        o = self.get_outcome(suite.StoredPMTUTestCase)

        self.assertCheckFails(o)

    def test_first_reply_from_tn3_missing(self):
        # Step  4: We expect the NUT to respond to echo requests from TN1, TN2
        #       and TN3.
        #       We actually, only deliver the replies from TN1 and TN2.

        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply(), 1500, True))
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6EchoReply(), 1500, True))

        o = self.get_outcome(suite.StoredPMTUTestCase)

        self.assertCheckFails(o)

    def test_second_reply_from_tn1_missing(self):
        # Step  9: We expect the NUT to respond to echo requests from TN1, TN2
        #          and TN3 a second time.
        #          We do not deliver any of the second round of packets.

        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply(), 1500, True))
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6EchoReply(), 1500, True))
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn3.global_ip()))/ICMPv6EchoReply(), 1500, True))

        # Step 5: we have sent a Packet Too Big message from TN2, it gets no
        #         reply
        self.ifx.replies_with(None)

        o = self.get_outcome(suite.StoredPMTUTestCase)

        self.assertCheckFails(o)

    def test_all_replies_fragments_too_large(self):
        # Step  9: We expect the NUT to respond to echo requests from TN1, TN2
        #          and TN3 a second time, with packets from TN2 fragmented
        #          because we have changed the MTU on the links.
        #          We actually, deliver fragments that are too large.

        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply(), 1500, True))
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6EchoReply(), 1500, True))
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn3.global_ip()))/ICMPv6EchoReply(), 1500, True))

        # Step 5: we have sent a Packet Too Big message from TN2, it gets no
        #         reply
        self.ifx.replies_with(None)

        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply(), 1500, True))
        self.ifx.replies_with(fragment6(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoReply(), 1500, True), 1450))
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn3.global_ip()))/ICMPv6EchoReply(), 1500, True))

        # Step 10: we have sent a Packet Too Big message from TN3, it gets no
        #          reply
        self.ifx.replies_with(None)

        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply(), 1500, True))
        self.ifx.replies_with(fragment6(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoReply(), 1500, True), 1400))
        self.ifx.replies_with(fragment6(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn3.global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoReply(), 1500, True), 1280))

        o = self.get_outcome(suite.StoredPMTUTestCase)

        self.assertCheckFails(o)

    def test_all_replies_fragmented_to_maximum_mtu(self):
        # Step 14: We expect the NUT to respond to echo requests from TN1, TN2
        #          and TN3 a second time, with packets from TN2 fragmented
        #          because we have changed the MTU on the links.
        #          We actually, deliver fragments that are too large.

        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply(), 1500, True))
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6EchoReply(), 1500, True))
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn3.global_ip()))/ICMPv6EchoReply(), 1500, True))

        # Step 5: we have sent a Packet Too Big message from TN2, it gets no
        #         reply
        self.ifx.replies_with(None)

        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply(), 1500, True))
        self.ifx.replies_with(fragment6(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoReply(), 1500, True), 1400))
        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn3.global_ip()))/ICMPv6EchoReply(), 1500, True))

        # Step 10: we have sent a Packet Too Big message from TN3, it gets no
        #          reply
        self.ifx.replies_with(None)

        self.ifx.replies_with(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply(), 1500, True))
        self.ifx.replies_with(fragment6(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoReply(), 1500, True), 1400))
        self.ifx.replies_with(fragment6(util.pad(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn3.global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoReply(), 1500, True), 1400))

        o = self.get_outcome(suite.StoredPMTUTestCase)

        self.assertCheckFails(o)
