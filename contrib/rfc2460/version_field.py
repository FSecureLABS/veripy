from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase


class VersionFieldHelper(ComplianceTestCase):

    def set_up(self):
        raise Exception('set_up() must be overridden to define #version')

    def run(self):
        self.logger.info("Sending ICMPv6 echo request, with the IPv6 Version field set to %s." % (self.version))
        self.node(1).send( \
            IPv6(src=str(self.node(1).global_ip()), dst=str(self.target(1).global_ip()), version=self.version)/
                ICMPv6EchoRequest(seq=self.next_seq()))
        
        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        
        assertEqual(0, len(r1), "no response was expected to the IPv6 packet with a Version of %s, got %d (seq: %d)" % (self.version, len(r1), self.seq()))
        
        self.logger.info("Sending ICMPv6 echo request, with correct IPv6 version field.")
        self.node(1).send( \
            IPv6(src=str(self.node(1).global_ip()), dst=str(self.target(1).global_ip()))/
                ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)

        assertEqual(1, len(r1), "expected an ICMPv6 Echo Reply, got %d (seq: %d)" % (len(r1), self.seq()))

class VersionFieldV00TestCase(VersionFieldHelper):
    """
    Version Field (v0)
    
    Verifies that a node properly processes the Version field of received
    packets.
    
    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.1.1)
    """
    
    def set_up(self):
        self.version = 0

class VersionFieldV04TestCase(VersionFieldHelper):
    """
    Version Field (v4)

    Verifies that a node properly processes the Version field of received
    packets.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.1.1)
    """

    def set_up(self):
        self.version = 4

class VersionFieldV05TestCase(VersionFieldHelper):
    """
    Version Field (v5)

    Verifies that a node properly processes the Version field of received
    packets.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.1.1)
    """

    def set_up(self):
        self.version = 5

class VersionFieldV07TestCase(VersionFieldHelper):
    """
    Version Field (v7)

    Verifies that a node properly processes the Version field of received
    packets.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.1.1)
    """

    def set_up(self):
        self.version = 7

class VersionFieldV15TestCase(VersionFieldHelper):
    """
    Version Field (v15)

    Verifies that a node properly processes the Version field of received
    packets.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.1.1)
    """

    def set_up(self):
        self.version = 15
