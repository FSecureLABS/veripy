from contrib.rfc3736.builder import *
from contrib.rfc3736.constants import *
from contrib.rfc3736.dhcpv6 import DHCPv6Helper
from scapy.all import *
from veripy.assertions import *


class MessageValidationHelper(DHCPv6Helper):

    def run(self):
        q = self.restart_and_wait_for_information_request(self.node(1), self.target(1))

        self.logger.info("Building a DHCPv6 Reply message...")
        p = IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()))/\
                UDP(sport=q.dport, dport=q.sport)/\
                    self.build_dhcpv6_reply(q, self.node(1), self.target(1), ias=False, dns_servers=[str(self.node(3).global_ip())], pref=False, server_id=False)
                    
        self.logger.info("Sending the DHCPv6 Reply message...")
        self.node(1).send(p)

        self.node(1).clear_received()
        self.logger.info("Sending unexpected message...")
        self.node(1).send(self.packet(p[0]))

        r1 = self.node(1).iface(0).received(src=(self.target(1).link_local_ip()))
        assertEqual(0, len(r1), "did not expect to receive any packets")


class SolicitMessageTestCase(MessageValidationHelper):
    """
    Solicit Message
    
    Verify that a client device properly discards all Solicit, Request, Confirm, Renew, 
    Rebind, Decline, Release, Information Request, Relay Forward and Relay Reply messages.
    
    @private
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 7.1.8)
    """

    def packet(self, q):
        return IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()))/\
                    UDP(sport=q[UDP].dport, dport=q[UDP].sport)/\
                        self.build_dhcpv6_solicit(self.target(1))


class RequestMessageTestCase(MessageValidationHelper):
    """
    Request Message
    
    Verify that a client device properly discards all Solicit, Request, Confirm, Renew, 
    Rebind, Decline, Release, Information Request, Relay Forward and Relay Reply messages.
    
    @private
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 7.1.8)
    """
    
    def packet(self, q):
        return IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()))/\
                    UDP(sport=q[UDP].dport, dport=q[UDP].sport)/\
                        self.build_dhcpv6_reply(q, self.node(1), self.target(1), ias=False, dns_servers=[str(self.node(3).global_ip())], pref=False, server_id=False)


class ConfirmMessageTestCase(MessageValidationHelper):
    """
    Confirm Message
    
    Verify that a client device properly discards all Solicit, Request, Confirm, Renew, 
    Rebind, Decline, Release, Information Request, Relay Forward and Relay Reply messages.
    
    @private
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 7.1.8)
    """

    def packet(self, q):
        return IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()))/\
                    UDP(sport=q[UDP].dport, dport=q[UDP].sport)/\
                        self.build_dhcpv6_reply(q, self.node(1), self.target(1), ias=False, dns_servers=[str(self.node(3).global_ip())], pref=False, server_id=False)


class RenewMessageTestCase(MessageValidationHelper):
    """
    Renew Message
    
    Verify that a client device properly discards all Solicit, Request, Confirm, Renew, 
    Rebind, Decline, Release, Information Request, Relay Forward and Relay Reply messages.
    
    @private
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 7.1.8)
    """

    def packet(self, q):
        return IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()))/\
                    UDP(sport=q[UDP].dport, dport=q[UDP].sport)/\
                        self.build_dhcpv6_reply(q, self.node(1), self.target(1), ias=False, dns_servers=[str(self.node(3).global_ip())], pref=False, server_id=False)


class RebindMessageTestCase(MessageValidationHelper):
    """
    Rebind Message
    
    Verify that a client device properly discards all Solicit, Request, Confirm, Renew, 
    Rebind, Decline, Release, Information Request, Relay Forward and Relay Reply messages.
    
    @private
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 7.1.8)
    """

    def packet(self, q):
        return IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()))/\
                    UDP(sport=q[UDP].dport, dport=q[UDP].sport)/\
                        self.build_dhcpv6_reply(q, self.node(1), self.target(1), ias=False, dns_servers=[str(self.node(3).global_ip())], pref=False, server_id=False)


class DeclineMessageTestCase(MessageValidationHelper):
    """
    Decline Message
    
    Verify that a client device properly discards all Solicit, Request, Confirm, Renew, 
    Rebind, Decline, Release, Information Request, Relay Forward and Relay Reply messages.
    
    @private
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 7.1.8)
    """

    def packet(self, q):
        return IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()))/\
                    UDP(sport=q[UDP].dport, dport=q[UDP].sport)/\
                        self.build_dhcpv6_reply(q, self.node(1), self.target(1), ias=False, dns_servers=[str(self.node(3).global_ip())], pref=False, server_id=False)


class ReleaseMessageTestCase(MessageValidationHelper):
    """
    Release Message
    
    Verify that a client device properly discards all Solicit, Request, Confirm, Renew, 
    Rebind, Decline, Release, Information Request, Relay Forward and Relay Reply messages.
    
    @private
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 7.1.8)
    """

    def packet(self, q):
        return IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()))/\
                    UDP(sport=q[UDP].dport, dport=q[UDP].sport)/\
                        self.build_dhcpv6_reply(q, self.node(1), self.target(1), ias=False, dns_servers=[str(self.node(3).global_ip())], pref=False, server_id=False)


class InformationRequestMessageTestCase(MessageValidationHelper):
    """
    Information Request Message
    
    Verify that a client device properly discards all Solicit, Request, Confirm, Renew, 
    Rebind, Decline, Release, Information Request, Relay Forward and Relay Reply messages.
    
    @private
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 7.1.8)
    """

    def packet(self, q):
        return IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()))/\
                    UDP(sport=q[UDP].dport, dport=q[UDP].sport)/\
                        self.build_dhcpv6_reply(q, self.node(1), self.target(1), ias=False, dns_servers=[str(self.node(3).global_ip())], pref=False, server_id=False)


class RelayForwardMessageTestCase(MessageValidationHelper):
    """
    Relay Forward Message
    
    Verify that a client device properly discards all Solicit, Request, Confirm, Renew, 
    Rebind, Decline, Release, Information Request, Relay Forward and Relay Reply messages.
    
    @private
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 7.1.8)
    """

    def packet(self, q):
        return IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()))/\
                    UDP(sport=q[UDP].dport, dport=q[UDP].sport)/\
                        self.build_dhcpv6_reply(q, self.node(1), self.target(1), ias=False, dns_servers=[str(self.node(3).global_ip())], pref=False, server_id=False)


class RelayReplyMessageTestCase(MessageValidationHelper):
    """
    Relay Reply Message
    
    Verify that a client device properly discards all Solicit, Request, Confirm, Renew, 
    Rebind, Decline, Release, Information Request, Relay Forward and Relay Reply messages.
    
    @private
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 7.1.8)
    """

    def packet(self, q):
        return IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()))/\
                    UDP(sport=q[UDP].dport, dport=q[UDP].sport)/\
                        self.build_dhcpv6_reply(q, self.node(1), self.target(1), ias=False, dns_servers=[str(self.node(3).global_ip())], pref=False, server_id=False)

