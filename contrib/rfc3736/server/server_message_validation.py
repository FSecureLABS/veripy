from contrib.rfc3736 import builder
from contrib.rfc3736.constants import *
from contrib.rfc3736.dhcpv6 import DHCPv6Helper
from scapy.all import *
from veripy.assertions import *


class AdvertiseMessageTestCase(DHCPv6Helper):
    """
    Advertise Message
    
    Verify that a DHCPv6 server discards all Advertise, Reply and Relay Reply
    messages.
    
    @private
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 8.1.15)
    """
    
    def run(self):
        #self.ui.ask("Restart DHCPv6 on the NUT. Enter 'y' and press enter when you have done this.")
        self.logger.info("Sending an Information Request message from TN1.")

        q = DHCP6_Advertise(trid=0x1234)/ \
                DHCP6OptServerId(duid=builder.duid(self.target(1).ll_addr()))/ \
                    DHCP6OptClientId(duid=builder.duid(self.node(1).iface(0).ll_addr))
        self.node(1).send(IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()))/UDP(sport=DHCPv6SourcePort, dport=DHCPv6DestPort)/q)

        r = self.node(1).iface(0).received(src=(self.target(1).link_local_ip()))
        assertEqual(0, len(r), "Did not expect to receive any packets.")


class ReplyMessageTestCase(DHCPv6Helper):
    """
    Reply Message
    
    Verify that a DHCPv6 server discards all Advertise, Reply and Relay Reply
    messages.
    
    @private
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 8.1.15)
    """
    
    def run(self):
        #self.ui.ask("Restart DHCPv6 on the NUT. Enter 'y' and press enter when you have done this.")
        self.logger.info("Sending an Information Request message from TN1.")

        q = DHCP6_Reply(trid=0x1234)/ \
                DHCP6OptClientId(duid=builder.duid(self.node(1).iface(0).ll_addr))
        self.node(1).send(IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()))/UDP(sport=DHCPv6SourcePort, dport=DHCPv6DestPort)/q)

        r = self.node(1).iface(0).received(src=(self.target(1).link_local_ip()))
        assertEqual(0, len(r), "Did not expect to receive any packets.")


class RelayReplyMessageTestCase(DHCPv6Helper):
    """
    Relay Reply Message
    
    Verify that a DHCPv6 server discards all Advertise, Reply and Relay Reply
    messages.
    
    @private
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 8.1.15)
    """
    
    def run(self):
        #self.ui.ask("Restart DHCPv6 on the NUT. Enter 'y' and press enter when you have done this.")
        self.logger.info("Sending an Information Request message from TN1.")

        q = self.build_dhcpv6_information_request(self.node(2))
        q = self.build_dhcpv6_relay_reply(q, self.node(2), self.router(1))
        self.router(1).send(IPv6(src=str(self.router(1).iface(1).link_local_ip()), dst=str(self.target(1).link_local_ip()))/UDP(sport=DHCPv6SourcePort, dport=DHCPv6DestPort)/q, iface=1)

        r = self.router(1).iface(0).received(src=(self.target(1).link_local_ip()))
        assertEqual(0, len(r), "Did not expect to receive any packets.")
