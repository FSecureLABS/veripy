from constants import *
from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase


class RouterAdvertisementValidityHelper(ComplianceTestCase):

    disabled_ra = True
    restart_uut = True

    def set_up(self):
        raise Exception("override #set_up to define #p")

    def run(self):
        self.logger.info("Sending an invalid Router Advertisement for TR1...")
        self.router(1).send(self.p, iface=1)

        self.ui.wait(3)

        self.logger.info("Sending an ICMPv6 Echo Request from TR1...")
        self.router(1).send(
            IPv6(src=str(self.router(1).link_local_ip(iface=1)), dst=str(self.target(1).link_local_ip()))/
                ICMPv6EchoRequest(seq=self.next_seq()), iface=1)

        self.ui.wait(2)

        self.logger.info("Checking for Neighbor Solicitations for TR1...")
        r1 = self.router(1).received(iface=1, src=self.target(1).link_local_ip(), dst=self.router(1).link_local_ip(iface=1).solicited_node(), type=ICMPv6ND_NS)
        assertGreaterThanOrEqualTo(1, len(r1), "expecting one-or-more multicast Neighbor Solicitations for TR1")


class GlobalSourceAddressTestCase(RouterAdvertisementValidityHelper):
    """
    Router Advertisement Processing, Validity -

    Verify that a host properly discards an invalid Router Advertisement.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (Test v6LC.2.2.12)
    """

    def set_up(self):
        self.p = IPv6(src=str(self.router(1).global_ip(iface=1)), dst="ff02::1", hlim=255)/\
                    ICMPv6ND_RA(routerlifetime=20, reachabletime=600, retranstimer=1)/\
                        ICMPv6NDOptSrcLLAddr(lladdr=self.router(1).iface(1).ll_addr)


class BadHopLimitTestCase(RouterAdvertisementValidityHelper):
    """
    Router Advertisement Processing, Validity - 

    Verify that a host properly discards an invalid Router Advertisement.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (Test v6LC.2.2.12)
    """

    def set_up(self):
        self.p = IPv6(src=str(self.router(1).link_local_ip(iface=1)), dst="ff02::1", hlim=2)/\
                    ICMPv6ND_RA(routerlifetime=20, reachabletime=600, retranstimer=1)/\
                        ICMPv6NDOptSrcLLAddr(lladdr=self.router(1).iface(1).ll_addr)


class BadICMPChecksumTestCase(RouterAdvertisementValidityHelper):
    """
    Router Advertisement Processing, Validity - 

    Verify that a host properly discards an invalid Router Advertisement.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (Test v6LC.2.2.12)
    """

    def set_up(self):
        self.p = IPv6(src=str(self.router(1).link_local_ip(iface=1)), dst="ff02::1", hlim=255)/\
                    ICMPv6ND_RA(cksum=0, routerlifetime=20, reachabletime=600, retranstimer=1)/\
                        ICMPv6NDOptSrcLLAddr(lladdr=self.router(1).iface(1).ll_addr)


class BadICMPCodeTestCase(RouterAdvertisementValidityHelper):
    """
    Router Advertisement Processing, Validity - 

    Verify that a host properly discards an invalid Router Advertisement.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (Test v6LC.2.2.12)
    """

    def set_up(self):
        self.p = IPv6(src=str(self.router(1).link_local_ip(iface=1)), dst="ff02::1", hlim=255)/\
                    ICMPv6ND_RA(code=1, routerlifetime=20, reachabletime=600, retranstimer=1)/\
                        ICMPv6NDOptSrcLLAddr(lladdr=self.router(1).iface(1).ll_addr)


class BadICMPLengthTestCase(RouterAdvertisementValidityHelper):
    """
    Router Advertisement Processing, Validity - 

    Verify that a host properly discards an invalid Router Advertisement.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (Test v6LC.2.2.12)
    """

    def set_up(self):
        self.p = IPv6(src=str(self.router(1).link_local_ip(iface=1)), dst="ff02::1", hlim=255, plen=14)/\
                    ICMPv6ND_RA(routerlifetime=20, reachabletime=600, retranstimer=1)/\
                        ICMPv6NDOptSrcLLAddr(lladdr=self.router(1).iface(1).ll_addr)


class BadOptionLengthTestCase(RouterAdvertisementValidityHelper):
    """
    Router Advertisement Processing, Validity -

    Verify that a host properly discards an invalid Router Advertisement.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (Test v6LC.2.2.12)
    """

    def set_up(self):
        self.p = IPv6(src=str(self.router(1).link_local_ip(iface=1)), dst="ff02::1", hlim=255)/\
                    ICMPv6ND_RA(routerlifetime=20, reachabletime=600, retranstimer=1)/\
                        ICMPv6NDOptSrcLLAddr(len=0, lladdr=self.router(1).iface(1).ll_addr)
    