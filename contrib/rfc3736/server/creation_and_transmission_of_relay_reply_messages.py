from contrib.rfc3736 import builder
from contrib.rfc3736.constants import *
from contrib.rfc3736.dhcpv6 import DHCPv6Helper
from scapy.all import *
from veripy.assertions import *


class RelayReplyMessageTransmissionTestCase(DHCPv6Helper):
    """
    Relay Reply Message Transmission
    
    Verify that a DHCPv6 server transmits proper Relay Reply messages.
    
    @private
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 8.1.13)
    """
    
    def run(self):
        #self.ui.ask("Restart DHCPv6 on the NUT. Enter 'y' and press enter when you have done this.")
        self.logger.info("Sending an Information Request message from TN1.")

        q = self.build_dhcpv6_information_request(self.node(2))
        q = self.build_dhcpv6_relay_forward(q, self.node(2), self.router(1))
        self.router(1).send(IPv6(src=str(self.router(1).iface(1).link_local_ip()), dst=AllDHCPv6RelayAgentsAndServers)/UDP(sport=DHCPv6SourcePort, dport=DHCPv6DestPort)/q, iface=1)

        self.logger.info("Checking for a DHCPv6 Relay Reply message.")
        r2 = self.node(1).received(src=str(self.target(1).link_local_ip()), dst=str(self.router(1).iface(1).link_local_ip()), type=DHCP6_RelayReply)
        assertEqual(1, len(r2), "expected to receive a DHCPv6 Relay Reply")
        p = r2[0]

        assertEqual(q.hopcount, p.hopcount, "Reply's hop count does not match Information Request's hop count.")
        assertEqual(q.linkaddr, p.linkaddr, "Reply's link address does not match Information Request's link address.")
        assertEqual(q.peeraddr, p.peeraddr, "Reply's peer address does not match Information Request's peer address.")
        assertHasLayer(DHCP6OptRelayMsg, p)
        assertEqual(len(p[DHCPv6_Reply]), p[DHCP6OptRelayMsg].optlen, "Reply's Relay Message Option has an incorrect option length.")
        assertHasLayer(DHCPv6_Reply, p)
        assertHasLayer(DHCP6OptClientId)
        assertHasLayer(DHCP6OptServerId)
        assertNotEqual(0, p[DHCP6OptServerId].duid, "Reply's Server DUID is not non-zero.")
        assertEqual(q[DHCP6OptClientId].duid, p[DHCP6OptClientId].duid, "Reply's Client DUID does not match Information Request's Client DUID.")
        assertHasLayer(DHCP6OptDNSServers, p)


class MultipleRelayReplyMessageTransmissionTestCase(DHCPv6Helper):
    """
    Multiple Relay Reply Message Transmission
    
    Verify that a DHCPv6 server transmits proper Relay Reply messages
    back to the correct relay that sent the Relay Forward message.
    
    @private
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 8.1.13)
    """
    
    def run(self):
        #self.ui.ask("Restart DHCPv6 on the NUT. Enter 'y' and press enter when you have done this.")
        self.logger.info("Sending an Information Request message from TN1.")

        q1 = self.build_dhcpv6_information_request(self.node(2))
        q1 = self.build_dhcpv6_relay_forward(q1, self.node(2), self.router(1))
        self.router(1).send(IPv6(src=str(self.router(1).iface(1).link_local_ip()), dst=AllDHCPv6RelayAgentsAndServers)/UDP(sport=DHCPv6SourcePort, dport=DHCPv6DestPort)/q1, iface=1)

        self.logger.info("Checking for a DHCPv6 Relay Reply message.")
        r1 = self.router(1).received(iface=1, src=self.target(1).link_local_ip(), dst=self.router(1).iface(1).link_local_ip(), type=DHCP6_RelayReply)
        assertEqual(1, len(r1), "expected to receive a DHCPv6 Relay Reply")
        
        q2 = self.build_dhcpv6_information_request(self.node(2))
        q2 = self.build_dhcpv6_relay_forward(q2, self.node(2), self.router(2))
        self.router(2).send(IPv6(src=str(self.router(2).link_local_ip(iface=1)), dst=AllDHCPv6RelayAgentsAndServers)/UDP(sport=DHCPv6SourcePort, dport=DHCPv6DestPort)/q2, iface=1)

        self.logger.info("Checking for a DHCPv6 Relay Reply message.")
        r2 = self.router(2).received(iface=1, src=self.target(1).link_local_ip(), dst=self.router(2).iface(1).link_local_ip(), type=DHCP6_RelayReply)
        assertEqual(1, len(r2), "expected to receive a DHCPv6 Relay Reply")


class EncapsulatedRelayReplyMessageTransmissionTestCase(DHCPv6Helper):
    """
    Encapsulated Relay Reply Message Transmission
    
    Verify that a DHCPv6 server transmits proper Relay Reply messages which
    encapsulate another Relay Reply.
    
    @private
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 8.1.13)
    """
    
    def run(self):
        #self.ui.ask("Restart DHCPv6 on the NUT. Enter 'y' and press enter when you have done this.")
        self.logger.info("Sending an Information Request message from TN1.")

        o = DHCP6_InfoRequest(trid=0x1234)/ \
                DHCP6OptClientId(duid=builder.duid("fe:80:90:01:02:03"))/ \
                    DHCP6OptElapsedTime(elapsedtime=2000)/ \
                        DHCP6OptOptReq()
        m = DHCP6_RelayForward(linkaddr="9001::1", peeraddr="fe80:9001::1", hopcount=2)/ \
                DHCP6OptIfaceId(ifaceid="eth0")/ \
                    DHCP6OptRelayMsg()/o
        q = DHCP6_RelayForward(linkaddr="::", peeraddr=str(self.node(2).link_local_ip()), hopcount=1)/ \
                DHCP6OptIfaceId(ifaceid="eth0")/ \
                    DHCP6OptRelayMsg()/m
        self.router(1).send(IPv6(src=str(self.router(1).iface(1).link_local_ip()), dst=AllDHCPv6RelayAgentsAndServers)/UDP(sport=DHCPv6SourcePort, dport=DHCPv6DestPort)/q, iface=1)

        self.logger.info("Checking for a DHCPv6 Relay Reply message.")
        r2 = self.node(1).received(src=self.target(1).link_local_ip(), dst=self.router(1).link_local_ip(iface=1), type=DHCP6_RelayReply)
        assertEqual(1, len(r2), "expected to receive a DHCPv6 Relay Reply")
        p = r2[0]

        assertEqual(q.hopcount, p.hopcount, "Reply's hop count does not match Information Request's hop count.")
        assertEqual(q.linkaddr, p.linkaddr, "Reply's link address does not match Information Request's link address.")
        assertEqual(q.peeraddr, p.peeraddr, "Reply's peer address does not match Information Request's peer address.")
        assertHasLayer(DHCP6OptRelayMsg, p)
        assertEqual(len(p[DHCP6OptRelayMsg][1]), p[DHCP6OptRelayMsg].optlen, "Reply's Relay Message Option has an incorrect option length.")
        assertHasLayer(DHCP6_RelayReply, p[DHCP6OptRelayMsg][1])
        assertEqual(q.hopcount, p[DHCP6OptRelayMsg][1].hopcount, "Reply's hop count does not match Information Request's hop count.")
        assertEqual(q.linkaddr, p[DHCP6OptRelayMsg][1].linkaddr, "Reply's link address does not match Information Request's link address.")
        assertEqual(q.peeraddr, p[DHCP6OptRelayMsg][1].peeraddr, "Reply's peer address does not match Information Request's peer address.")
        assertHasLayer(DHCP6OptRelayMsg, p[DHCP6OptRelayMsg][1])
        assertHasLayer(DHCPv6_Reply, p[DHCP6OptRelayMsg][1])
