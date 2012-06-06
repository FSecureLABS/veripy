from contrib.rfc3315 import builder
from contrib.rfc3315 import dhcpv6
from contrib.rfc3315.constants import *
from scapy.all import *
from veripy.assertions import *


class DHCPv6PDHelper(dhcpv6.DHCPv6Helper):

    def build_dhcpv6_pd_advertise(self, s, server, client, ias=True, T1=300, T2=300):
        p = DHCP6_Advertise(trid=s.trid)/ \
                DHCP6OptClientId(duid=s[DHCP6OptClientId].duid)/ \
                    DHCP6OptServerId(duid=builder.duid(server.iface(0).ll_addr))
        if ias:
            for ia in builder.pd_ias(s[DHCP6OptIA_PD], server.iface(0), T1, T2):
                p = p/ia
            
        return p

    def build_dhcpv6_pd_rebind(self, p, server, client):
        p = DHCP6_Rebind(trid=p.trid+1)/ \
                DHCP6OptClientId(duid=p[DHCP6OptClientId].duid)/ \
                    DHCP6OptServerId(duid=p[DHCP6OptServerId].duid)/ \
                        DHCP6OptIA_PD(iaid=p[DHCP6OptIA_PD].iaid, T1=p[DHCP6OptIA_PD].T1, T2=p[DHCP6OptIA_PD].T2)/\
                            p[DHCP6OptIAPrefix]
        return p

    def build_dhcpv6_pd_reply(self, s, server, client, T1=300, T2=300):
        p = DHCP6_Reply(trid=s.trid)/ \
                DHCP6OptClientId(duid=s[DHCP6OptClientId].duid)/ \
                    DHCP6OptServerId(duid=builder.duid(server.iface(0).ll_addr))
        for ia in builder.pd_ias(s[DHCP6OptIA_PD], server.iface(0), T1, T2):
            p = p/ia

        return p
    
    def build_dhcpv6_pd_request(self, a, server, client):
        p = DHCP6_Request(trid=a.trid)/ \
                DHCP6OptClientId(duid=a[DHCP6OptClientId].duid)/ \
                    DHCP6OptServerId(duid=a[DHCP6OptServerId].duid)/ \
                        DHCP6OptIA_PD(iaid=a[DHCP6OptIA_PD].iaid, T1=a[DHCP6OptIA_PD].T1, T2=a[DHCP6OptIA_PD].T2)/\
                            a[DHCP6OptIAPrefix]
        return p

    def build_dhcpv6_pd_release(self, p, server, client):
        p = DHCP6_Release(trid=p.trid+1)/ \
                DHCP6OptClientId(duid=p[DHCP6OptClientId].duid)/ \
                    DHCP6OptServerId(duid=p[DHCP6OptServerId].duid)/ \
                        DHCP6OptIA_PD(iaid=p[DHCP6OptIA_PD].iaid, T1=p[DHCP6OptIA_PD].T1, T2=p[DHCP6OptIA_PD].T2)/\
                            p[DHCP6OptIAPrefix]
        return p

    def build_dhcpv6_pd_renew(self, p, server, client):
        p = DHCP6_Renew(trid=p.trid+1)/ \
                DHCP6OptClientId(duid=p[DHCP6OptClientId].duid)/ \
                    DHCP6OptServerId(duid=p[DHCP6OptServerId].duid)/ \
                        DHCP6OptIA_PD(iaid=p[DHCP6OptIA_PD].iaid, T1=p[DHCP6OptIA_PD].T1, T2=p[DHCP6OptIA_PD].T2)/\
                            p[DHCP6OptIAPrefix]
        return p

    def build_dhcpv6_pd_solicit(self, client, iaid=0x4321, trid=0x1234, T1=300, T2=300):
        p = DHCP6_Solicit(trid=trid)/ \
                DHCP6OptClientId(duid=builder.duid(client.iface(0).ll_addr))/ \
                    DHCP6OptOptReq()/ \
                        DHCP6OptIA_PD(iaid=iaid, T1=T1, T2=T2)
        return p

    def do_dhcpv6_pd_handshake_as_client(self, server, client):
        self.logger.info("Sending a DHCPv6 Solicit message, with a IA for Prefix Delegation...")
        client.send(
            IPv6(src=str(client.link_local_ip()), dst=str(AllDHCPv6RelayAgentsAndServers))/
                UDP(sport=DHCPv6SourcePort, dport=DHCPv6DestPort)/
                    self.build_dhcpv6_pd_solicit(client))

        self.logger.info("Checking for a DHCPv6 Advertise message...")
        r1 = client.received(src=server.link_local_ip(), type=DHCP6_Advertise)
        assertEqual(1, len(r1), "expected to receive a DHCPv6 Advertise message")

        assertHasLayer(DHCP6OptIA_PD, r1[0], "expected the DHCPv6 Advertise to contain an IA for Prefix Delegation")
        assertHasLayer(DHCP6OptIAPrefix, r1[0], "expected the DHCPv6 Advertise to contain an IA Prefix")

        self.logger.info("Sending a DHCPv6 Request message, with the offered IA for Prefix Delegation...")
        client.send(
            IPv6(src=str(client.link_local_ip()), dst=str(AllDHCPv6RelayAgentsAndServers))/
                UDP(sport=DHCPv6SourcePort, dport=DHCPv6DestPort)/
                    self.build_dhcpv6_pd_request(r1[0], server, client))

        self.logger.info("Checking for a DHCPv6 Reply message...")
        r2 = client.received(src=server.link_local_ip(), type=DHCP6_Reply)
        assertEqual(1, len(r2), "expected to receive a DHCPv6 Reply message")

        assertHasLayer(DHCP6OptIA_PD, r2[0], "expected the DHCPv6 Reply to contain an IA for Prefix Delegation")
        assertHasLayer(DHCP6OptIAPrefix, r2[0], "expected the DHCPv6 Reply to contain an IA Prefix")

        return ("%s/%s" % (r2[0][DHCP6OptIAPrefix].prefix, r2[0][DHCP6OptIAPrefix].plen), r2[0])
        