from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase
from veripy.models import IPv6Address

class SlaacTestHelper(ComplianceTestCase):
    
    disabled_ra = True

    def wait_for_neighbor_solicitation(self, dst=None):
        if dst == None:
            dst = self.target(1).link_local_ip().solicited_node()

        self.logger.info("Waiting for neighbor solicitation")

        # Use the real interace to sniff so we can get the packet quicker
        return self.node(1).iface(0).real().sniff(lfilter=lambda p: p.haslayer(ICMPv6ND_NS), count=1, timeout = 300)

    def send_neighbor_solicitation_from_node_1(self, dst, target, src="::"):
        self.logger.info("Sending Neighbor solicitation from tn1 src=%s dst=%s target=%s", src, dst, target)
        self.node(1).send(IPv6(src=str(src), dst=str(dst))/ICMPv6ND_NS(tgt = str(target)))

    def send_neighbor_advertisement_from_node_1(self, dst, target, src="::"):
        self.logger.info("Sending Neighbor advertisement from tn1 src=%s dst=%s target=%s", src, dst, target)
        self.node(1).send(IPv6(src=str(src), dst=str(dst)/ICMPv6ND_NA(tgt=str(target))))

    def send_neighbor_solicitation_from_router_1(self, dst, target, src="::"):
        self.logger.info("Sending Neighbor solicitation from tr1 src=%s dst=%s target=%s", src, dst, target)
        self.router(1).send(IPv6(src = src, dst = dst)/ICMPv6ND_NS(tgt = target), iface=1)

    def send_neighbor_advertisement_from_router_1(self, dst, target, src="::"):
        self.logger.info("Sending Neighbor advertisement from tr1 src=%s dst=%s target=%s", src, dst, target)
        self.router(1).send(IPv6(src=str(src), dst=str(dst)/ICMPv6ND_NA(tgt=str(target))), iface=1)
        
    def ping_uut(self, uut_ip):
        self.logger.info("Ping UUT on %s", uut_ip)
        self.node(1).send(IPv6(src = str(self.node(1).link_local_ip()), dst = str(uut_ip))/ICMPv6EchoRequest(seq=self.next_seq()))




class UutReceivesPacketDuringDadAndContinuesTestHelper(SlaacTestHelper):
    """
     Generic Run Method for parts A-H.
     Send different invalid NA.
    """
    def run(self):
        if self.ui.ask("Is duplicate address detection configured on the device?"):
# Initialize the Interface
            self.ui.ask("Please press Y and then restart the interface being tested or UUT. After pressing Y you will have 5 minutes to restart the interface or UUT.")

# Wait for NS to get sent out then send invalid
            ns_packets = self.wait_for_neighbor_solicitation()
            assertGreaterThan(0, len(ns_packets), "expected ICMPv6 Neighbor Solicitation to be sent.")

            uut_tentative = IPv6Address.identify(ns_packets[0][ICMPv6ND_NS].tgt)
            self.logger.info("Got UUT tenative link-local: %s", uut_tentative)
            sol_node_multicast = uut_tentative.solicited_node()

            self.node(1).clear_received()

            # Sending Test Case Specific Packet
            self.logger.info("Sending Test Case Packet:")
            self.node(1).send(self.test_case_packet(sol_node_multicast=sol_node_multicast, uut_tentative=uut_tentative))

# Allow for DAD and SLAAC
            self.logger.info("Waiting for UUT to assign the IP to it's interface.")
            self.ui.wait(3)

# Observable result
            # ping device on dst ip sen as target in DAD NS to check it has now assigned that ip
            self.logger.info("Ping UUT on tentative IP")
            self.ping_uut(str(uut_tentative))

            r1 = self.node(1).received(src=self.target(1).link_local_ip(), dst=self.node(1).link_local_ip(), seq=self.seq(), type=ICMPv6EchoReply)
            assertEqual(1, len(r1), "expected an ICMPv6 Echo Reply")

# Send NS
            self.node(1).clear_received()
            self.send_neighbor_solicitation_from_node_1(dst=sol_node_multicast, target=uut_tentative)


# Observable Result
# Get NA in return
            na = self.node(1).received(src=uut_tentative, dst="ff02::1", type=ICMPv6ND_NA)
            assertEqual(1, len(na), "expected a ICMPv6 Neighbor Advertisement to be sent.")

# Send NS
            self.node(1).clear_received()
            self.send_neighbor_solicitation_from_node_1(src=str(self.node(1).link_local_ip()), dst=uut_tentative, target=uut_tentative)

# Observation Result
# Get NA in return
            na = self.node(1).received(src=uut_tentative, dst=self.node(1).link_local_ip(), type=ICMPv6ND_NA)
            assertEqual(1, len(na), "expected a ICMPv6 Neighbor Advertisement to be sent.")


class HostUutReceivesPacketDuringDadAndStopsTestHelper(SlaacTestHelper):
    """
     Generic Run Method for parts A-H.
     Send different invalid NS.
    """
    def run(self):
        if self.ui.ask("Is duplicate address detection configured on the device?"):
# Initialize the Interface
            self.ui.ask("Please press Y and then restart the interface being tested or UUT. After pressing Y you will have 5 minutes to restart the interface or UUT.")

# Wait for NS to get sent out then send invalid
            ns_packets = self.wait_for_neighbor_solicitation()
            assertGreaterThan(0, len(ns_packets), "expected ICMPv6 Neighbor Solicitation to be sent.")

            uut_tentative = IPv6Address.identify(ns_packets[0][ICMPv6ND_NS].tgt)
            self.logger.info("Got UUT tenative link-local: %s", uut_tentative)
            sol_node_multicast = uut_tentative.solicited_node()

            self.node(1).clear_received()

            # Sending Test Case Specific Packet
            self.logger.info("Sending Test Case Packet:")
            self.node(1).send(self.test_case_packet(sol_node_multicast=sol_node_multicast, uut_tentative=uut_tentative))

# Allow for DAD and SLAAC
            self.logger.info("Waiting for UUT to assign the IP to it's interface.")
            self.ui.wait(3)

# Observable Results
# Not assign address and not transmit any RS
            # ping device on dst ip sent as target in DAD NS to check it has not assigned that ip
            self.ping_uut(str(uut_tentative))
            r1 = self.node(1).received(src=self.target(1).link_local_ip(), dst=self.node(1).link_local_ip(), seq=self.seq(), type=ICMPv6EchoReply)
            assertEqual(0, len(r1), "not expected an ICMPv6 Echo Reply")

            self.logger.info("Check no router solicitations have been sent out by the UUT.")

            # check no router solicitations were sent out
            self.ui.wait(1)
            rs = self.node(1).received(src=uut_tentative, dst="ff02::2", type=ICMPv6ND_RS)
            assertEqual(0, len(rs), "not expecting router solicitation")

# Send NS
            self.node(1).clear_received()
            self.send_neighbor_solicitation_from_node_1(dst=sol_node_multicast, target=uut_tentative)


# Observable Result
# Don't get NA in return
            na = self.node(1).received(src=uut_tentative, dst="ff02::1", type=ICMPv6ND_NA)
            assertEqual(0, len(na), "expected a ICMPv6 Neighbor Advertisement to be sent.")

# Send NS
            self.node(1).clear_received()
            self.send_neighbor_solicitation_from_node_1(src=str(self.node(1).link_local_ip()), dst=uut_tentative, target=uut_tentative)

# Observation Result
# Don't get NA in return
            na = self.node(1).received(src=uut_tentative, dst=self.node(1).link_local_ip(), type=ICMPv6ND_NA)
            assertEqual(0, len(na), "expected a ICMPv6 Neighbor Advertisement to be sent.")

# Send RA with prefix
            self.logger.info("Sending Router Advertisement with prefix %s", self.router(1).iface(0).global_ip().network())
            ll_info = ICMPv6NDOptSrcLLAddr(lladdr=self.router(1).iface(0).ll_addr)
            link_mtu_info = ICMPv6NDOptMTU(mtu=self.router(1).iface(0).ll_protocol.mtu)
            prefix_info = ICMPv6NDOptPrefixInfo(validlifetime=20, preferredlifetime=20, prefixlen=self.router(1).iface(0).global_ip().prefix_size, prefix=self.router(1).iface(0).global_ip().network())
            self.router(1).send(IPv6(src=str(self.router(1).iface(0).link_local_ip()), dst="ff02::1")/ICMPv6ND_RA()/ll_info/link_mtu_info/prefix_info, iface=1)

# Send NS for global address
            self.node(1).clear_received()
            self.send_neighbor_solicitation_from_node_1(src="::", dst=uut_tentative, target=self.target(1).global_ip())

# Observation Result
# Don't get NA in return
            na = self.node(1).received(src=uut_tentative, dst=self.node(1).link_local_ip(), type=ICMPv6ND_NA)
            assertEqual(0, len(na), "expected a ICMPv6 Neighbor Advertisement for global address to be sent.")

class RouterUutReceivesPacketDuringDadAndStopsTestHelper(SlaacTestHelper):
    """
     Generic Run Method for parts A-H.
     Send different invalid NS.
    """
    def run(self):
        if self.ui.ask("Is duplicate address detection configured on the device?"):
# Initialize the Interface
            self.ui.ask("Please press Y and then restart the interface being tested or UUT. After pressing Y you will have 5 minutes to restart the interface or UUT.")

# Wait for NS to get sent out then send invalid
            ns_packets = self.wait_for_neighbor_solicitation()
            assertGreaterThan(0, len(ns_packets), "expected ICMPv6 Neighbor Solicitation to be sent.")

            uut_tentative = IPv6Address.identify(ns_packets[0][ICMPv6ND_NS].tgt)
            self.logger.info("Got UUT tenative link-local: %s", uut_tentative)
            sol_node_multicast = uut_tentative.solicited_node()

            self.node(1).clear_received()

            # Sending Test Case Specific Packet
            self.logger.info("Sending Test Case Packet: ")
            self.node(1).send(self.test_case_packet(sol_node_multicast=sol_node_multicast, uut_tentative=uut_tentative))

# Allow for DAD and SLAAC
            self.logger.info("Waiting for UUT to assign the IP to it's interface.")
            self.ui.wait(3)

# Observable Results
# Not assign address and not transmit any RS
            # ping device on dst ip sent as target in DAD NS to check it has not assigned that ip
            self.ping_uut(str(uut_tentative))
            r1 = self.node(1).received(src=self.target(1).link_local_ip(), dst=self.node(1).link_local_ip(), seq=self.seq(), type=ICMPv6EchoReply)
            assertEqual(0, len(r1), "not expected an ICMPv6 Echo Reply")            

# Send NS
            self.node(1).clear_received()
            self.send_neighbor_solicitation_from_node_1(dst=sol_node_multicast, target=uut_tentative)


# Observable Result
# Don't get NA in return
            na = self.node(1).received(src=uut_tentative, dst="ff02::1", type=ICMPv6ND_NA)
            assertEqual(0, len(na), "expected a ICMPv6 Neighbor Advertisement to be sent.")

# Send NS
            self.node(1).clear_received()
            self.send_neighbor_solicitation_from_node_1(src=str(self.node(1).link_local_ip()), dst=uut_tentative, target=uut_tentative)

# Observation Result
# Don't get NA in return
            na = self.node(1).received(src=uut_tentative, dst=self.node(1).link_local_ip(), type=ICMPv6ND_NA)
            assertEqual(0, len(na), "expected a ICMPv6 Neighbor Advertisement to be sent.")

            self.node(1).clear_received()
            self.logger.info("Send echo request to tn4 through the RUT")
            self.node(1).send(IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.node(4).global_ip))/ICMPv6EchoRequest(seq=self.next_seq()))

            echo_req = self.node(4).received(src=self.target(1).link_local_ip(), seq=self.seq(), type=ICMPv6EchoRequest)
            assertEqual(0, len(echo_req), "not expected an ICMPv6 Echo Request to be forwarded to TN4")
