from scapy.all import *
from veripy.assertions import *
from veripy import util
from veripy.models import ComplianceTestCase


class ConfirmPingHelper(ComplianceTestCase):

    def set_up(self):
        self.fail("must override #set_up() to set #length")
    
    def run(self):
        self.logger.info("Sending ICMPv6 Echo Request of %s bytes" % self.length)
        self.node(2).send( \
            util.pad( \
                IPv6(src=str(self.node(2).global_ip()), dst=str(self.target(1).global_ip()))/
                    ICMPv6EchoRequest(seq=self.next_seq()), self.length, True))
        
        self.logger.info("Checking for a reply...")
        r1 = self.node(2).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)

        assertEqual(1, len(r1), "expected to receive an ICMPv6 Echo Reply (seq: %d)" % (self.seq()))
        assertEqual(self.length, len(r1[0]),"expected the ICMPv6 Echo Reply packet to be %d octets long, was %d" % (self.length, len(r1[0])))


class ICMPv6EchoRequest64OctetsTestCase(ConfirmPingHelper):
    """
    Confirm Ping - ICMPv6 Echo Request 64 octets
    
    Verify that a node can reply to variable sized ICMP Echo Requests.
    
    @private:
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (Test v6LC.4.1.1a)
    """

    restart_uut = True
    
    def set_up(self):
        self.length = 64


class ICMPv6EchoRequest1280OctetsTestCase(ConfirmPingHelper):
    """
    Confirm Ping - ICMPv6 Echo Request 1280 octets

    Verify that a node can reply to variable sized ICMP Echo Requests.

    @private:
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (Test v6LC.4.1.1b)
    """

    restart_uut = True

    def set_up(self):
        self.length = 1280


class ICMPv6EchoRequest1500OctetsTestCase(ConfirmPingHelper):
    """
    Confirm Ping - ICMPv6 Echo Request 1500 octets

    Verify that a node can reply to variable sized ICMP Echo Requests.

    @private:
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (Test v6LC.4.1.1c)
    """

    restart_uut = True

    def set_up(self):
        self.length = 1500
        