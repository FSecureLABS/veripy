from scapy.all import *
from veripy.assertions import *
from veripy import util
from veripy.models import ComplianceTestCase

class StoredPMTUTestCase(ComplianceTestCase):
    """
    Stored PMTU
    
    Verify that a node can store Path MTU information for multiple
    destinations.
    
    @private:
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (Test v6LC.4.1.2)
    """

    restart_uut = True

    def run(self):
        # Step 1 ###############################################################
        self.logger.info("Sending ICMPv6 Echo Request from TN1 to NUT...")
        self.node(1).send( \
            util.pad( \
                IPv6(src=str(self.node(1).global_ip()), dst=str(self.target(1).global_ip()))/
                    ICMPv6EchoRequest(seq=self.next_seq()), 1500, True))
        s1 = self.seq()

        # Step 2 ###############################################################
        self.logger.info("Forwarding ICMPv6 Echo Request from TN2 to NUT, via TR1...")
        self.node(2).send( \
            util.pad( \
                IPv6(src=str(self.node(2).global_ip()), dst=str(self.target(1).global_ip()))/
                    ICMPv6EchoRequest(seq=self.next_seq()), 1500, True))
        s2 = self.seq()

        # Step 3 ###############################################################
        self.logger.info("Forwarding ICMPv6 Echo Request from TN3 to NUT, via TR1...")
        self.node(3).send( \
            util.pad( \
                IPv6(src=str(self.node(3).global_ip()), dst=str(self.target(1).global_ip()))/
                    ICMPv6EchoRequest(seq=self.next_seq()), 1500, True))
        s3 = self.seq()

        self.ui.wait(5)
        # Step 4 ###############################################################
        self.logger.info("Checking for a reply to first Echo Request (from TN1)...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), seq=s1, type=ICMPv6EchoReply)
        assertEqual(1, len(r1), "expected to receive an ICMPv6 Echo Reply from TN1 (seq: %d)" % (s1))
        assertNotFragmented(r1[0])

        self.logger.info("Checking for a reply to first Echo Request (from TN2)...")
        r2 = self.node(2).received(src=self.target(1).global_ip(), seq=s2, type=ICMPv6EchoReply)
        assertEqual(1, len(r2), "expected to receive an ICMPv6 Echo Reply from TN2 (seq: %d)" % (s2))
        assertNotFragmented(r2[0])

        self.logger.info("Checking for a reply to first Echo Request (from TN3)...")
        r3 = self.node(3).received(src=self.target(1).global_ip(), seq=s3, type=ICMPv6EchoReply)
        assertEqual(1, len(r3), "expected to receive an ICMPv6 Echo Reply from TN3 (seq: %d)" % (s3))
        assertNotFragmented(r3[0])

        # Step 5 ###############################################################
        self.logger.info("Sending Packet Too Big message to NUT for Echo Reply to TN2...")
        self.node(2).send( \
            IPv6(src=str(self.node(2).global_ip()), dst=str(self.target(1).global_ip()))/
                ICMPv6PacketTooBig(mtu=1400)/
                    Raw(load=r2[0].build()[:(1400-48)]))

        self.node(1).clear_received()
        self.node(2).clear_received()
        self.node(3).clear_received()

        # Step 6 ###############################################################
        self.logger.info("Sending ICMPv6 Echo Request from TN1 to NUT...")
        self.node(1).send( \
            util.pad( \
                IPv6(src=str(self.node(1).global_ip()), dst=str(self.target(1).global_ip()))/
                    ICMPv6EchoRequest(seq=self.next_seq()), 1500, True))
        s1 = self.seq()

        # Step 7 ###############################################################
        self.logger.info("Forwarding ICMPv6 Echo Request from TN2 to NUT, via TR1...")
        self.node(2).send( \
            util.pad( \
                IPv6(src=str(self.node(2).global_ip()), dst=str(self.target(1).global_ip()))/
                    ICMPv6EchoRequest(seq=self.next_seq()), 1500, True))
        s2 = self.seq()

        # Step 8 ###############################################################
        self.logger.info("Forwarding ICMPv6 Echo Request from TN3 to NUT, via TR1...")
        self.node(3).send( \
            util.pad( \
                IPv6(src=str(self.node(3).global_ip()), dst=str(self.target(1).global_ip()))/
                    ICMPv6EchoRequest(seq=self.next_seq()), 1500, True))
        s3 = self.seq()

        self.ui.wait(5)
        # Step 9 ###############################################################
        self.logger.info("Checking for a reply to second Echo Request (from TN1)...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), seq=s1, type=ICMPv6EchoReply)
        assertEqual(1, len(r1), "expected to receive an ICMPv6 Echo Reply from TN1 (seq: %d)" % (s1))
        assertNotFragmented(r1[0])

        self.logger.info("Checking for a fragmented rely to second Echo Request (from TN2)...")
        r2 = self.node(2).received(src=self.target(1).global_ip(), seq=s2, type=ICMPv6EchoReply)
        assertFragmented(r2[0], self.node(2).received(), count=2, size=1400, reassemble_to=1500)

        self.logger.info("Checking for a reply to second Echo Request (from TN3)...")
        r3 = self.node(3).received(src=self.target(1).global_ip(), seq=s3, type=ICMPv6EchoReply)
        assertEqual(1, len(r3), "expected to receive an ICMPv6 Echo Reply from TN3 (seq: %d)" % (s3))
        assertNotFragmented(r3[0])

        self.node(1).clear_received()
        self.node(2).clear_received()
        self.node(3).clear_received()

        # Step 10 ##############################################################
        self.logger.info("Sending Packet Too Big message to NUT for Echo Reply to TN3...")
        self.node(3).send( \
            IPv6(src=str(self.node(3).global_ip()), dst=str(self.target(1).global_ip()))/
                ICMPv6PacketTooBig(mtu=1280)/
                    Raw(load=r3[0].build()[:(1280-48)]))

        # Step 11 ##############################################################
        self.logger.info("Sending ICMPv6 Echo Request from TN1 to NUT...")
        self.node(1).send( \
            util.pad( \
                IPv6(src=str(self.node(1).global_ip()), dst=str(self.target(1).global_ip()))/
                    ICMPv6EchoRequest(seq=self.next_seq()), 1500, True))
        s1 = self.seq()

        # Step 12 ##############################################################
        self.logger.info("Forwarding ICMPv6 Echo Request from TN2 to NUT, via TR1...")
        self.node(2).send( \
            util.pad( \
                IPv6(src=str(self.node(2).global_ip()), dst=str(self.target(1).global_ip()))/
                    ICMPv6EchoRequest(seq=self.next_seq()), 1500, True))
        s2 = self.seq()

        # Step 13 ##############################################################
        self.logger.info("Forwarding ICMPv6 Echo Request from TN3 to NUT, via TR1...")
        self.node(3).send( \
            util.pad( \
                IPv6(src=str(self.node(3).global_ip()), dst=str(self.target(1).global_ip()))/
                    ICMPv6EchoRequest(seq=self.next_seq()), 1500, True))
        s3 = self.seq()

        self.ui.wait(5)
        # Step 14 ##############################################################
        self.logger.info("Checking for a reply to the third Echo Request (from TN1)...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), seq=s1, type=ICMPv6EchoReply)
        assertEqual(1, len(r1), "expected to receive an ICMPv6 Echo Reply from TN1 (seq: %d)" % (s1))
        assertNotFragmented(r1[0])

        self.logger.info("Checking for a fragmented rely to the third Echo Request (from TN2)...")
        r2 = self.node(2).received(src=self.target(1).global_ip(), seq=s2, type=ICMPv6EchoReply)
        assertEqual(1, len(r2), "expected to receive an ICMPv6 Echo Reply from TN2 (seq: %d)" % (s2))
        assertFragmented(r2[0], self.node(2).received(), count=2, size=1400, reassemble_to=1500)
        
        self.logger.info("Checking for a fragmented reply to the third Echo Request (from TN3)...")
        r3 = self.node(3).received(src=self.target(1).global_ip(), seq=s3, type=ICMPv6EchoReply)
        assertEqual(1, len(r3), "expected to receive an ICMPv6 Echo Reply from TN3 (seq: %d)" % (s3))
        assertFragmented(r3[0], self.node(3).received(), count=2, size=1280, reassemble_to=1500)
        