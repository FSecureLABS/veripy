from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase

class ResolutionWaitQueueSingleQueueTestCase(ComplianceTestCase):
    """
    Resolution Wait Queue - Single Queue
     
    Verify that a node properly queues packets while waiting for address
    resolution of the next hop.
    
    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.2.1.2a)
    """

    disabled_nd = True
    restart_uut = True

    def run(self):
        seq = []
        for i in range(0, 3):
            self.logger.info("Sending ICMP Echo Request %d (seq: %d)..." % (i, self.next_seq()))
            seq.append(self.seq())
            
            self.node(1).send(
                IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()))/
                    ICMPv6EchoRequest(seq=self.seq()))

        self.logger.info("Checking for Neighbor Solicitations...")
        r1 = self.node(1).received(src=self.target(1).link_local_ip(), dst=self.node(1).link_local_ip().solicited_node(), type=ICMPv6ND_NS)
        assertGreaterThan(0, len(r1), "expected to receive at least 1 ICMPv6 Neighbor Solicitation")

        for p in r1:
            assertEqual(self.node(1).link_local_ip(), p.getlayer(ICMPv6ND_NS).tgt, "expected the Neighbor Solicitation to be for TN1's link local address")
            
            self.logger.info("Sending Neighbor Advertisement in response to Neighbor Solicitation...")
            self.node(1).send(
                IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()))/
                    ICMPv6ND_NA(R=0, S=1, O=1, tgt=str(self.node(1).link_local_ip()))/
                        ICMPv6NDOptDstLLAddr(lladdr=self.node(1).iface(0).ll_addr))
            
        self.ui.wait(5)
        self.logger.info("Checking for ICMPv6 Echo Replies...")
        r2 = self.node(1).received(src=self.target(1).link_local_ip(), type=ICMPv6EchoReply)

        assertEqual(3, len(r2), "expected to receive 3 ICMPv6 Echo Replies")

        for p in r2:
            assertTrue(p.getlayer(ICMPv6EchoReply).seq in seq, "expected an ICMPv6 echo reply for each request sent")


class ResolutionWaitQueueMultipleQueueTestCase(ComplianceTestCase):
    """
    Resolution Wait Queue - Multiple Queues
     
    Verify that a node properly queues packets while waiting for address
    resolution of the next hop.
    
    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.2.1.2b)
    """

    disable_nd = True
    restart_uut = True
    
    def run(self):
        seq_tn1 = []
        for i in range(0, 3):
            self.logger.info("Sending ICMP Echo Request %d from TN1 (seq: %d)..." % (i, self.next_seq()))
            seq_tn1.append(self.seq())

            self.node(1).send(
                IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()))/
                    ICMPv6EchoRequest(seq=self.seq()))
        
        seq_tr1 = []
        for i in range(0, 4):
            self.logger.info("Sending ICMP Echo Request %d from TR1 (seq: %d)..."%(i, self.next_seq()))
            seq_tr1.append(self.seq())

            self.router(1).send(
                IPv6(src=str(self.router(1).link_local_ip(iface=1)), dst=str(self.target(1).link_local_ip()))/
                    ICMPv6EchoRequest(seq=self.seq()), iface=1)
        
        self.logger.info("Checking for Neighbor Solicitations for TN1...")
        r1 = self.node(1).received(src=self.target(1).link_local_ip(), dst=self.node(1).link_local_ip().solicited_node(), type=ICMPv6ND_NS)
        assertGreaterThan(0, len(r1), "expected to receive an ICMPv6 Neighbor Solicitation for TN1")

        for p in r1:
            assertEqual(self.node(1).link_local_ip(), p.getlayer(ICMPv6ND_NS).tgt, "expected the Neighbor Solicitation to be for TN1's link local address")

            self.logger.info("Sending Neighbor Advertisement in response to Neighbor Solicitation for TN1...")
            self.node(1).send(\
                IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()))/
                    ICMPv6ND_NA(R=0, S=1, O=1, tgt=str(self.node(1).link_local_ip()))/
                        ICMPv6NDOptDstLLAddr(lladdr=self.node(1).iface(0).ll_addr))

        r2 = self.router(1).received(iface=1, src=self.target(1).link_local_ip(), dst=self.router(1).link_local_ip(iface=1).solicited_node(), type=ICMPv6ND_NS)
        assertGreaterThan(0, len(r2), "expected to receive an ICMPv6 Neighbor Solicitation for TR1")

        for p in r2:
            assertEqual(self.router(1).link_local_ip(iface=1), p.getlayer(ICMPv6ND_NS).tgt, "expected the Neighbor Solicitation to be for TR1's link local address")

            self.logger.info("Sending Neighbor Advertisement in response to Neighbor Solicitation for TR1...")
            self.router(1).send(
                IPv6(src=str(self.router(1).link_local_ip(iface=1)), dst=str(self.target(1).link_local_ip()))/
                    ICMPv6ND_NA(R=0, S=1, O=1, tgt=str(self.router(1).link_local_ip(iface=1)))/
                        ICMPv6NDOptDstLLAddr(lladdr=self.router(1).iface(1).ll_addr))
                        
        self.ui.wait(5)
        self.logger.info("Checking for Echo Replies to TN1...")
        r3 = self.node(1).received(src=self.target(1).link_local_ip(), type=ICMPv6EchoReply)

        assertEqual(3, len(r3), "expected to receive 3 ICMPv6 Echo Replies to TN1")

        for p in r3:
            assertTrue(p.getlayer(ICMPv6EchoReply).seq in seq_tn1, "expected an ICMPv6 echo reply for each request sent to TN1")

        self.logger.info("Checking for Echo Replies to TR1...")
        r4 = self.router(1).received(iface=1, src=self.target(1).link_local_ip(), type=ICMPv6EchoReply)

        assertEqual(4, len(r4), "expected to receive 4 ICMPv6 Echo Replies to TR1")

        for p in r4:
            assertTrue(p.getlayer(ICMPv6EchoReply).seq in seq_tr1, "expected an ICMPv6 echo reply for each request sent to TR1")
            