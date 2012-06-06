from veripy.models import ComplianceTestSuite
from veripy.models.decorators import must, should

import checking_for_increase_in_pmtu
import confirm_ping
import increase_estimate
# import multicast_destination_one_router
# import multicast_destination_two_routers
import non_zero_icmpv6_code
import receiving_mtu_below_ipv6_minimum
import reduce_pmtu_off_link
import reduce_pmtu_on_link
import router_advertisement_with_mtu_option
import stored_pmtu

class PathMTUDiscoveryEndNode(ComplianceTestSuite):
    """
    Path MTU Discovery for IP version 6 - End Node

    The following tests cover the Path MTU Discovery for IP version 6.

    The Path MTU Discovery protocol is a technique to dynamically discover the
    PMTU of a path. The basic idea is that a source node initially assumes that
    the PMTU of a path is the (known) MTU is the first hop in the path. If any
    of the packets sent on the path are too large to be forwarded by some node
    along the path, that node will discard them and return ICMPv6 Packet Too
    Big messages. Upon receipt of such a message, the source node reduces its
    assumed PMTU for the path based on the MTU of the constricting hop as
    reported in the Packet Too Big message. The Path MTU Discovery process ends
    when the nodes's estimate of the PMTU is less than or equal to the actual
    PMTU.

    These tests are designed to verify the readiness of an IPv6 implementation
    vis-a-vis the Path MTU Discovery IPv6 specification.

    @private
    Author:         MWR
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (Section 4)
    """

    TestCase_001 = confirm_ping.ICMPv6EchoRequest64OctetsTestCase
    TestCase_002 = confirm_ping.ICMPv6EchoRequest1280OctetsTestCase
    TestCase_003 = confirm_ping.ICMPv6EchoRequest1500OctetsTestCase
    TestCase_004 = stored_pmtu.StoredPMTUTestCase
    TestCase_005 = non_zero_icmpv6_code.NonZeroICMPv6CodeTestCase
    TestCase_006 = reduce_pmtu_on_link.ReducePMTUOnLinkLinkLocalTestCase
    TestCase_007 = reduce_pmtu_on_link.ReducePMTUOnLinkGlobalTestCase
    TestCase_008 = reduce_pmtu_off_link.ReducePMTUOffLinkTestCase
    TestCase_009 = receiving_mtu_below_ipv6_minimum.MTUEqualTo56TestCase
    TestCase_010 = receiving_mtu_below_ipv6_minimum.MTUEqualTo1279TestCase
    TestCase_011 = increase_estimate.MTUIncreaseTestCase
    TestCase_012 = increase_estimate.MTUEqualTo0x1ffffffTestCase
    TestCase_013 = router_advertisement_with_mtu_option.RouterAdvertisementWithMTUOptionTestCase # hosts only
    TestCase_014 = checking_for_increase_in_pmtu.CheckingForIncreaseInPMTUTestCase
    # TestCase_015 = multicast_destination_one_router.MulticastDestinationOneRouterTestCase
    # TestCase_016 = multicast_destination_two_routers.MulticastDestinationTwoRoutersTestCase

class PathMTUDiscoveryIntermediateNode(ComplianceTestSuite):
    """
    Path MTU Discovery for IP version 6 - Intermediate Node

    The following tests cover the Path MTU Discovery for IP version 6.

    The Path MTU Discovery protocol is a technique to dynamically discover the
    PMTU of a path. The basic idea is that a source node initially assumes that
    the PMTU of a path is the (known) MTU is the first hop in the path. If any
    of the packets sent on the path are too large to be forwarded by some node
    along the path, that node will discard them and return ICMPv6 Packet Too
    Big messages. Upon receipt of such a message, the source node reduces its
    assumed PMTU for the path based on the MTU of the constricting hop as
    reported in the Packet Too Big message. The Path MTU Discovery process ends
    when the nodes's estimate of the PMTU is less than or equal to the actual
    PMTU.

    These tests are designed to verify the readiness of an IPv6 implementation
    vis-a-vis the Path MTU Discovery IPv6 specification.

    @private
    Author:         MWR
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (Section 4)
    """

    TestCase_001 = confirm_ping.ICMPv6EchoRequest64OctetsTestCase
    TestCase_002 = confirm_ping.ICMPv6EchoRequest1280OctetsTestCase
    TestCase_003 = confirm_ping.ICMPv6EchoRequest1500OctetsTestCase
    TestCase_004 = stored_pmtu.StoredPMTUTestCase
    TestCase_005 = non_zero_icmpv6_code.NonZeroICMPv6CodeTestCase
    TestCase_006 = reduce_pmtu_on_link.ReducePMTUOnLinkLinkLocalTestCase
    TestCase_007 = reduce_pmtu_on_link.ReducePMTUOnLinkGlobalTestCase
    TestCase_008 = reduce_pmtu_off_link.ReducePMTUOffLinkTestCase
    TestCase_009 = receiving_mtu_below_ipv6_minimum.MTUEqualTo56TestCase
    TestCase_010 = receiving_mtu_below_ipv6_minimum.MTUEqualTo1279TestCase
    TestCase_011 = increase_estimate.MTUIncreaseTestCase
    TestCase_012 = increase_estimate.MTUEqualTo0x1ffffffTestCase
    # TestCase_013 for hosts only (router_advertisement_with_mtu_option.RouterAdvertisementWithMTUOptionTestCase)
    TestCase_014 = checking_for_increase_in_pmtu.CheckingForIncreaseInPMTUTestCase
    # TestCase_015 = multicast_destination_one_router.MulticastDestinationOneRouterTestCase
    # TestCase_016 = multicast_destination_two_routers.MulticastDestinationTwoRoutersTestCase

ComplianceTestSuite.register('pmtu-discovery-end-node', PathMTUDiscoveryEndNode)
ComplianceTestSuite.register('pmtu-discovery-intermediate-node', PathMTUDiscoveryIntermediateNode)
