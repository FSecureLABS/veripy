from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase


class ReassemblyTimeExceededTimeElapsedBetweenFragmentsLessThanSixtySecondsTestCase(ComplianceTestCase):
    """
    Reassembly Time Exceeded - Time Elapsed Between Fragments less than Sixty Seconds
    
    Verify that a node takes the proper actions when the reassembly time has
    been exceeded for a packet.
    
    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.3.1a)
    """
    
    def run(self):
        self.logger.info("Constructing a fragmented IPv6 packet.")
        p = IPv6(src=str(self.node(1).global_ip()), dst=str(self.target(1).global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoRequest(seq=self.next_seq())/Raw("\0"*80)
        f1, f2, f3 = fragment6(p, 80)
        
        self.logger.info("Sending fragmented packet.")
        self.node(1).send(f1)
        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(0, len(r1), "did not expect a reply to a packet fragment (1 of 3")
        
        self.ui.wait(45)

        self.logger.info("Sending fragmented packet.")
        self.node(1).send(f2)
        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(0, len(r1), "did not expect a reply to a packet fragment (2 of 3")

        self.logger.info("Sending fragmented packet.")
        self.node(1).send(f3)
        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(1, len(r1), "expected to receive an ICMPv6 Echo Reply")


class ReassemblyTimeExceededTimeElapsedBeforeLastFragmentsArriveTestCase(ComplianceTestCase):
    """
    Reassembly Time Exceeded - Time Exceeded Before Last Fragments Arrive
    
    Verify that a node takes the proper actions when the reassembly time has
    been exceeded for a packet.
    
    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.3.1b)
    """
    
    def run(self):
        self.logger.info("Constructing a fragmented IPv6 packet.")
	p = IPv6(src=str(self.node(1).global_ip()), dst=str(self.target(1).global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoRequest(seq=self.next_seq())/Raw("\0"*80)
        f1, f2, f3 = fragment6(p, 80)

        self.logger.info("Sending fragmented packet.")
        self.node(1).send(f1)
        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(0, len(r1), "did not expect a reply to a packet fragment (1 of 3")

        self.ui.wait(65)

        self.logger.info("Sending fragmented packet.")
        self.node(1).send(f2)
        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(0, len(r1), "did not expect a reply to a packet fragment (2 of 3")

        self.logger.info("Sending fragmented packet.")
        self.node(1).send(f3)
        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(0, len(r1), "did not expect a reply to a packet fragment (3 of 3")

        r1 = self.node(1).received(src=self.target(1).global_ip(), type=ICMPv6TimeExceeded)
        assertEqual(1, len(r1), "expected to receive an ICMPv6 Time Exceeded message")
	assertLessThanOrEqualTo(1280, len(r1[0].getlayer(IPv6)), "expected the Time Exceeded packet to be smaller than the minimum MTU")
        assertEqual(1, r1[0].getlayer(ICMPv6TimeExceeded).code, "expected the Time Exceeded message to have a Code Field of 1")
        assertEqual(0, r1[0].getlayer(ICMPv6TimeExceeded).unused, "expected the Time Exceeded message to have an unused value of 0")


class ReassemblyTimeExceededGlobalTimeExceededOnlyFirstFragmentReceivedTestCase(ComplianceTestCase):
    """
    Reassembly Time Exceeded - Time Exceeded (Global), Only First Fragment Received
    
    Verify that a node takes the proper actions when the reassembly time has
    been exceeded for a packet.
    
    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.3.1c)
    """

    def run(self):
        self.logger.info("Constructing a fragmented IPv6 packet.")
	p = IPv6(src=str(self.node(1).global_ip()), dst=str(self.target(1).global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoRequest(seq=self.next_seq())/Raw("\0"*80)
        f1, f2, f3 = fragment6(p, 80)

        self.logger.info("Sending fragmented packet.")
        self.node(1).send(f1)
        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(0, len(r1), "did not expect a reply to a packet fragment (1 of 3")

        self.ui.wait(55)

        self.logger.info("Sending fragmented packet.")
        self.node(1).send(f2)
        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(0, len(r1), "did not expect a reply to a packet fragment (2 of 3")

        self.ui.wait(10)

        self.logger.info("Sending fragmented packet.")
        self.node(1).send(f3)
        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(0, len(r1), "did not expect a reply to a packet fragment (3 of 3")

        r1 = self.node(1).received(src=self.target(1).global_ip(), type=ICMPv6TimeExceeded)
        assertEqual(1, len(r1), "expected to receive an ICMPv6 Time Exceeded message")
	assertLessThanOrEqualTo(1280, len(r1[0].getlayer(IPv6)), "expected the Time Exceeded packet to be smaller than the minimum MTU")
        assertEqual(1, r1[0].getlayer(ICMPv6TimeExceeded).code, "expected the Time Exceeded message to have a Code Field of 1")
        assertEqual(0, r1[0].getlayer(ICMPv6TimeExceeded).unused, "expected the Time Exceeded message to have an unused value of 0")
        

class ReassemblyTimeExceededLinkLocalTimeExceededOnlyFirstFragmentReceivedTestCase(ComplianceTestCase):
    """
    Reassembly Time Exceeded - Time Exceeded (Link-local), Only First Fragment Received
    
    Verify that a node takes the proper actions when the reassembly time has
    been exceeded for a packet.
    
    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.3.1d)
    """
    
    def run(self):
        self.logger.info("Constructing a fragmented IPv6 packet.")
	p = IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoRequest(seq=self.next_seq())/Raw("\0"*80)
        f1, f2, f3 = fragment6(p, 80)

        self.logger.info("Sending fragmented packet.")
        self.node(1).send(f1)
        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).link_local_ip(), dst=self.node(1).link_local_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(0, len(r1), "did not expect a reply to a packet fragment (1 of 3")

        self.ui.wait(55)

        self.logger.info("Sending fragmented packet.")
        self.node(1).send(f2)
        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).link_local_ip(), dst=self.node(1).link_local_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(0, len(r1), "did not expect a reply to a packet fragment (2 of 3")

        self.ui.wait(10)

        self.logger.info("Sending fragmented packet.")
        self.node(1).send(f3)
        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).link_local_ip(), dst=self.target(1).link_local_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(0, len(r1), "did not expect a reply to a packet fragment (3 of node")
        
        r1 = self.node(1).received(src=self.target(1).link_local_ip(), dst=self.node(1).link_local_ip(), type=ICMPv6TimeExceeded)
        assertEqual(1, len(r1), "expected to receive an ICMPv6 Time Exceeded message")
	assertLessThanOrEqualTo(1280, len(r1[0].getlayer(IPv6)), "expected the Time Exceeded packet to be smaller than the minimum MTU")
        assertEqual(1, r1[0].getlayer(ICMPv6TimeExceeded).code, "expected the Time Exceeded message to have a Code Field of 1")
        assertEqual(0, r1[0].getlayer(ICMPv6TimeExceeded).unused, "expected the Time Exceeded message to have an unused value of 0")


class ReassemblyTimeExceededTimeExceededOnlySecondFragmentReceivedTestCase(ComplianceTestCase):
    """
    Reassembly Time Exceeded - Time Exceeded, Only Second Fragment Received
    
    Verify that a node takes the proper actions when the reassembly time has
    been exceeded for a packet.
    
    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.3.1e)
    """
    
    def run(self):
        self.logger.info("Constructing a fragmented IPv6 packet.")
	p = IPv6(src=str(self.node(1).global_ip()), dst=str(self.target(1).global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoRequest(seq=self.next_seq())/Raw("\0"*80)
        f1, f2, f3 = fragment6(p, 80)
        
        self.logger.info("Sending fragmented packet.")
        self.node(1).send(f2)
        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(0, len(r1), "did not expect a reply to a packet fragment (2 of 3")
        
        self.ui.wait(65)

        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(0, len(r1), "did not expect a reply to a packet fragment")

        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), type=ICMPv6TimeExceeded)
        assertEqual(0, len(r1), "did not expect a reply to a packet fragment")
