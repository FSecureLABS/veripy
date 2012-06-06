from contrib.rfc3736 import builder
from contrib.rfc3736.constants import *
from contrib.rfc3736.dhcpv6 import DHCPv6Helper
from scapy.all import *
from veripy.assertions import *


class ReceptionOfInformationRequestMessageViaUnicastTestCase(DHCPv6Helper):
    """
    Reception Of Information Request Message Via Unicast
    
    Verify that a DHCPv6 server handles the reception of invalid Information
    Request messages.
    
    @private
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 8.1.14)
    """
    
    def run(self):
        #self.ui.ask("Restart DHCPv6 on the NUT. Enter 'y' and press enter when you have done this.")
        self.logger.info("Sending an Information Request message from TN1.")

        q = self.build_dhcpv6_information_request(self.node(2))
        self.node(1).send(IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()))/UDP(sport=DHCPv6SourcePort, dport=DHCPv6DestPort)/q)

        self.logger.info("Checking for a DHCPv6 Relay Reply message.")
        r2 = self.node(1).received(src=str(self.target(1).link_local_ip()), dst=str(self.node(1).link_local_ip()), type=DHCP6_RelayReply)
        assertEqual(0, len(r2), "did not expect to receive a DHCPv6 Relay Reply")


class ContainsServerIdentifierOptionTestCase(DHCPv6Helper):
    """
    Contains Server Identifier Option
    
    Verify that a DHCPv6 server handles the reception of invalid Information
    Request messages.
    
    @private
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 8.1.14)
    """
    
    def run(self):
        #self.ui.ask("Restart DHCPv6 on the NUT. Enter 'y' and press enter when you have done this.")
        self.logger.info("Sending an Information Request message from TN1.")

        p = DHCP6_InfoRequest(trid=0x1324)/ \
                DHCP6OptClientId(duid=builder.duid(self.node(1).iface(0).ll_addr))/ \
                    DHCP6OptServerId(duid=builder.duid(self.target(1).link_local_ip()))/ \
                        DHCP6OptElapsedTime(elapsedtime=2000)/ \
                            DHCP6OptOptReq()

        q = self.build_dhcpv6_information_request(self.node(1))
        self.node(1).send(IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()))/UDP(sport=DHCPv6SourcePort, dport=DHCPv6DestPort)/q)

        self.logger.info("Checking for a DHCPv6 Relay Reply message.")
        r2 = self.node(1).received(src=str(self.target(1).link_local_ip()), dst=str(self.node(1).link_local_ip()), type=DHCP6_RelayReply)
        assertEqual(0, len(r2), "did not expect to receive a DHCPv6 Relay Reply")


class ContainsIANAOptionTestCase(DHCPv6Helper):
    """
    Contains IA NA Option
    
    Verify that a DHCPv6 server handles the reception of invalid Information
    Request messages.
    
    @private
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 8.1.14)
    """
    
    def run(self):
        #self.ui.ask("Restart DHCPv6 on the NUT. Enter 'y' and press enter when you have done this.")
        self.logger.info("Sending an Information Request message from TN1.")

        p = DHCP6_InfoRequest(trid=0x1324)/ \
                DHCP6OptClientId(duid=builder.duid(self.node(1).iface(0).ll_addr))/ \
                    DHCP6OptIA_NA(iaid=0x1234, T1=300, T2=300)/ \
                        DHCP6OptElapsedTime(elapsedtime=2000)/ \
                            DHCP6OptOptReq()

        q = self.build_dhcpv6_information_request(self.node(1))
        self.node(1).send(IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()))/UDP(sport=DHCPv6SourcePort, dport=DHCPv6DestPort)/q)

        self.logger.info("Checking for a DHCPv6 Relay Reply message.")
        r2 = self.node(1).received(src=str(self.target(1).link_local_ip()), dst=str(self.node(1).link_local_ip()), type=DHCP6_RelayReply)
        assertEqual(0, len(r2), "did not expect to receive a DHCPv6 Relay Reply")
