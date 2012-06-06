from contrib.rfc3315.builder import *
from contrib.rfc3315.constants import *
from contrib.rfc3315.dhcpv6 import DHCPv6Helper
from scapy.all import *
from veripy.assertions import *

class AdvertiseMessagesWithNoAddrsAvailTestCase(DHCPv6Helper):
    """
    Tranmission of Advertise messages with NoAddrsAvail

    Verify a client and server device properly generates Advertise messages
    with a status code of 2 (NoAddrsAvail).

    @private
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 1.7)
    """

    def run(self):
        self.ui.tell("Please configure the DHCP server to have 5 IPs available for allocation.")
        assertTrue(self.ui.ask("Press y when ready."))

        try:
            for i in range(0, 10):
                ip, p = self.do_dhcpv6_handshake_as_client(self.target(1), self.node(1), iaid=0x4321 + i, trid=0x1234 + i)
                self.logger.info("Got IP: %s" % (ip))
                self.node(1).clear_received()

            fail("Could not exhaust the address pool.")
        except AssertionFailedError, e:
            if not e.message == "expected the DHCPv6 Advertise to contain an IA": raise(e)

        self.logger.info("Checking for the final Advertise message...")
        r1 = self.node(1).received(src=self.target(1).link_local_ip(), type=DHCP6_Advertise)
        assertGreaterThanOrEqualTo(1, len(r1), "expected to find one-or-more Advertise messages")
        a = r1[-1]

        assertHasLayer(DHCP6OptStatusCode, a, "expected the DHCPv6 Advertise to contain an Status Code")
        assertEqual(0x002, a[DHCP6OptStatusCode].statuscode, "expected the DHCPv6 Status Code to be NoAddrsAvail (0x0002)")

    def tear_down(self):
        self.ui.tell("Please reset the DHCP server's IP address pool.")
        assertTrue(self.ui.ask("Press y when ready."))
        