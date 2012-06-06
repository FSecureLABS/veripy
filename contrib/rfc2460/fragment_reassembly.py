from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase


class FragmentReassemblyAllFragmentsValidTestCase(ComplianceTestCase):
    """
    Fragment Reassembly - All Fragments are Valid
    
    Verify that a node correctly reassembles fragmented packets and
    distinguishes between packet fragments using the Source Address,
    Destination Address, and Fragment ID.
    
    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.3.1a)
    """
    
    def run(self):
        self.logger.info("Constructing a fragmented IPv6 packet.")
        p = IPv6(src=str(self.node(1).global_ip()), dst=str(self.target(1).global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoRequest(seq=self.next_seq())/("\0"*80)
        f1, f2, f3 = fragment6(p, 80)
        
        self.logger.info("Sending fragmented packet.")
        self.node(1).send(f1)
        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(0, len(r1), "did not expect a reply to a packet fragment (1 of 3)")

        self.node(1).send(f2)
        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(0, len(r1), "did not expect a reply to a packet fragment (2 of 3)")

	self.node(1).send(f3)
        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(1, len(r1), "expected to receive a single reply, after sending all packets")

class FragmentReassemblyAllFragmentsValidInReverseOrderTestCase(ComplianceTestCase):
    """
    Fragment Reassembly - All Fragments are Valid, reverse order
    
    Verify that a node correctly reassembles fragmented packets and
    distinguishes between packet fragments using the Source Address,
    Destination Address, and Fragment ID.
    
    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.3.1b)
    """
    
    def run(self):
        self.logger.info("Constructing a fragmented IPv6 packet.")
        p = IPv6(src=str(self.node(1).global_ip()), dst=str(self.target(1).global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoRequest(seq=self.next_seq())/("\0"*80)
        f1, f2, f3 = fragment6(p, 80)
        
        self.logger.info("Sending fragmented packet.")
        self.node(1).send(f3)
        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(0, len(r1), "did not expect a reply to a packet fragment (1 of 3)")

        self.node(1).send(f2)
        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(0, len(r1), "did not expect a reply to a packet fragment (2 of 3)")

        self.node(1).send(f1)
        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(1, len(r1), "expected to receive a single reply, after sending all packets")

class FragmentReassemblyFragmentIDsDifferBetweenFragmentsTestCase(ComplianceTestCase):
    """
    Fragment Reassembly - Fragment IDs Differ Between Fragments
    
    Verify that a node correctly reassembles fragmented packets and
    distinguishes between packet fragments using the Source Address,
    Destination Address, and Fragment ID.
    
    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.3.1c)
    """
    
    def run(self):
        self.logger.info("Constructing a fragmented IPv6 packet.")
        p = IPv6(src=str(self.node(1).global_ip()), dst=str(self.target(1).global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoRequest(seq=self.next_seq())/("\0"*80)
        f1, f2, f3 = fragment6(p, 80)
        
        self.logger.info("Changing the ID of fragment 2.")
        f2.id ^= 0xFFFF
        
        self.logger.info("Sending fragmented packet.")
        self.node(1).send(f1)
        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(0, len(r1), "did not expect a reply to a packet fragment (1 of 3)")

        self.node(1).send(f2)
        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(0, len(r1), "did not expect a reply to a packet fragment (2 of 3)")

        self.node(1).send(f3)
        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(0, len(r1), "did not expect a reply to a packet fragment (3 of 3)")
        
        self.logger.info("Waiting for the default timeout.")
        self.ui.wait(65)

        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), type=ICMPv6TimeExceeded)
        assertEqual(1, len(r1), "expected to receive an ICMPv6 Time Exceeded")

        r1 = self.node(1).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(0, len(r1), "did not expect a reply to invalid fragmented packets")

class FragmentReassemblySourceAddressesDifferBetweenFragmentsTestCase(ComplianceTestCase):
    """
    Fragment Reassembly - Source Addresses Differ Between Fragments
    
    Verify that a node correctly reassembles fragmented packets and
    distinguishes between packet fragments using the Source Address,
    Destination Address, and Fragment ID.
    
    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.3.1d)
    """
    
    def run(self):
        self.logger.info("Constructing a fragmented IPv6 packet.")
        p = IPv6(src=str(self.node(1).global_ip()), dst=str(self.target(1).global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoRequest(seq=self.next_seq())/("\0"*80)
        f1, f2, f3 = fragment6(p, 80)
        
        self.logger.info("Changing the SRC of fragment 2.")
        f2.src = str(self.node(1).link_local_ip())
        
        self.logger.info("Sending fragmented packet.")
        self.node(1).send(f1)
        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(0, len(r1), "did not expect a reply to a packet fragment (1 of 3)")

        self.node(1).send(f2)
        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(0, len(r1), "did not expect a reply to a packet fragment (2 of 3)")

        self.node(1).send(f3)
        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(0, len(r1), "did not expect a reply to a packet fragment (3 of 3)")

        self.logger.info("Waiting for the default timeout.")
        self.ui.wait(65)

        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), type=ICMPv6TimeExceeded)
        assertEqual(1, len(r1), "expected to receive an ICMPv6 Time Exceeded")

        r1 = self.node(1).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(0, len(r1), "did not expect a reply to invalid fragmented packets")

class FragmentReassemblyDestinationAddressesDifferBetweenFragmentsTestCase(ComplianceTestCase):
    """
    Fragment Reassembly - Destination Addresses Differ Between Fragments
    
    Verify that a node correctly reassembles fragmented packets and
    distinguishes between packet fragments using the Source Address,
    Destination Address, and Fragment ID.
    
    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.3.1e)
    """
    
    def run(self):
        self.logger.info("Constructing a fragmented IPv6 packet.")
        p = IPv6(src=str(self.node(1).global_ip()), dst=str(self.target(1).global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoRequest(seq=self.next_seq())/("\0"*80)
        f1, f2, f3 = fragment6(p, 80)
        
        self.logger.info("Changing the DST of the fragments.")
        f1.dst = str(self.target(1).link_local_ip())
        f2.dst = str(self.target(1).global_ip())
        f3.dst = str(self.target(1).link_local_ip())

        self.logger.info("Sending fragmented packet.")
        self.node(1).send(f1)
        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).link_local_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(0, len(r1), "did not expect a reply to a packet fragment (1 of 3)")

        self.node(1).send(f2)
        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(0, len(r1), "did not expect a reply to a packet fragment (2 of 3)")

        self.node(1).send(f3)
        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).link_local_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(0, len(r1), "did not expect a reply to a packet fragment (3 of 3)")

        self.logger.info("Waiting for the default timeout.")
        self.ui.wait(65)

        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).link_local_ip(), type=ICMPv6TimeExceeded)
        assertEqual(1, len(r1), "expected to receive an ICMPv6 Time Exceeded")

        r1 = self.node(1).received(src=self.target(1).link_local_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(0, len(r1), "did not expect a reply to invalid fragmented packets")

class FragmentReassemblyReassembleTo1500TestCase(ComplianceTestCase):
    """
    Fragment Reassembly - Reassemble to 1500
    
    Verify that a node correctly reassembles fragmented packets and
    distinguishes between packet fragments using the Source Address,
    Destination Address, and Fragment ID.
    
    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.3.1f)
    """
    
    def run(self):
        self.logger.info("Sending ICMPv6 echo request.")
        self.node(1).send(IPv6(src=str(self.node(1).global_ip()), dst=str(self.target(1).global_ip()))/ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking for a reply...")
	r1 = self.node(1).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(1, len(r1), "expected to receive an ICMPv6 Time Exceeded")

        self.node(1).clear_received()
        
        self.logger.info("Constructing a fragmented IPv6 packet.")
        p = IPv6(src=str(self.node(1).global_ip()), dst=str(self.target(1).global_ip()))/IPv6ExtHdrFragment()/ICMPv6EchoRequest(seq=self.next_seq())/("\0"*1452)
        f1, f2, f3 = fragment6(p, 536)

        self.logger.info("Sending fragmented packet.")
        self.node(1).send(f1)
        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(0, len(r1), "did not expect a reply to a packet fragment (1 of 3)")

        self.node(1).send(f2)
        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(0, len(r1), "did not expect a reply to a packet fragment (2 of 3)")

        self.node(1).send(f3)
        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(1, len(r1), "expected to receive reply to a packet fragment (3 of 3)")
        