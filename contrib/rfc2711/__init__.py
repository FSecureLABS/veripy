from veripy.models import ComplianceTestSuite
from veripy.models.decorators import must, should

import multicast_listener_discovery
import unrecognized_value

class RouterAlertOption(ComplianceTestSuite):
    """
    Router Alert Option

    The following tests cover the Router Alert Option header.

    New protocols, such as RSVP, use control datagrams which, while addressed
    to a particular destination, contain information that needs to be examined,
    and in some case updated, by routers along the path between the source and
    destination. It is desirable to forward regular datagrams as rapidly as
    possible, while ensuring that the router processes these special control
    datagrams appropriately.

    The Router Alert option is defined within the IPv6 Hop-by-Hop header, and
    informs the router that the contents of this datagram are of interest to
    the router and to handle any control data accordingly.

    These tests are designed to verify the readiness of an IPv6 implementation
    vis-a-vis the Router Alert Option specification.

    @private
    Author:         MWR
    Source:         RFC 2711
    """

    TestCase_001 = multicast_listener_discovery.MulticastListenerDiscoveryTestCase
    TestCase_002 = unrecognized_value.UnrecognizedValueTestCase

ComplianceTestSuite.register('ipv6-router-alert-option', RouterAlertOption)
