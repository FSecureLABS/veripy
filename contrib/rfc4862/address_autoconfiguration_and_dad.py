from scapy.all import *
from veripy.assertions import *
from slaac_test_helper import SlaacTestHelper
from veripy.models import IPv6Address

class AddressAutoConfigurationAndDadTestCase(SlaacTestHelper):
    """
    Address Autoconfiguration and Duplicate Address Detection

    @private
    Source:           IPv6 Ready Phase-1/Phase-2 Test Specification Core
                      Test v6LC.3.1.1
                      RFC4862 5.3, 5.4
    """
    def run(self):
        if self.ui.ask("Is duplicate address detection configured on the device?"):
            self.ui.ask("Please press Y and then restart the interface being tested or restart the UUT. After pressing Y you will have 5 minutes to restart the interface or UUT.")

        # Result 2
        ns_packets = self.wait_for_neighbor_solicitation()
        assertGreaterThan(0, len(ns_packets), "expected ICMPv6 Neighbor Solicitation to be sent.")

        self.logger.info("Waiting for UUT to assign the IP to it's interface.")
        self.ui.wait(3)

        uut_tentative_ip = IPv6Address.identify(ns_packets[0][ICMPv6ND_NS].tgt)

        # Check it has assigned that ip by pinging it
        self.ping_uut(uut_tentative_ip)
        r1 = self.node(1).received(src=self.target(1).link_local_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(1, len(r1), "expected an ICMPv6 Echo Reply")

        # Step 3 Send NS
        self.node(1).clear_received()
        self.send_neighbor_solicitation_from_node_1(dst=uut_tentative_ip.solicited_node(), target=uut_tentative_ip)

        # Result 4 Receive NA in reply
        na = self.node(1).received(src=uut_tentative_ip, dst="ff02::1", type=ICMPv6ND_NA)
        assertEqual(1, len(na), "expected a ICMPv6 Neighbor Advertisement to be sent.")
