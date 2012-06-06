from veripy.models import ComplianceTestSuite
from veripy.models.decorators import must, should

import encapsulation
import neighbor_discovery
import static_tunnel_fragmentation

class BasicIPv6TransitionMechanisms(ComplianceTestSuite):
    """
    Basic IPv6 Transition Mechanisms for IPv6 Hosts and Routers

    The key to a successful IPv6 transition is compatibility with the large
    installed base of IPv4 hosts and routers. Maintaining compatibility with
    IPv4 while deploying IPv6 will streamline the task of transitioning the
    Internet to IPv6.

    These tests cover establishing point-to-point tunnels by encapsulating IPv6
    packets within IPv4 headers to carry them over IPv4 routing infrastructures.
    
    @private
    Author:         MWR
    Source:         RFC4213
    """
    
    TestCase_001 = encapsulation.IPv4HeaderAddedTestCase
    TestCase_002 = encapsulation.CorrectVersionFieldTestCase
    TestCase_003 = encapsulation.CorrectLengthFieldTestCase
    TestCase_004 = encapsulation.CorrectProtocolFieldTestCase
    TestCase_005 = encapsulation.CorrectIPv4SourceAddressTestCase
    TestCase_006 = encapsulation.CorrectIPv4DestinationAddressTestCase
    TestCase_007 = encapsulation.CorrectIPv6SourceAddressTestCase
    TestCase_008 = encapsulation.CorrectIPv6DestinationAddressTestCase
    TestCase_009 = neighbor_discovery.RespondsToNUDProbeTestCase
    TestCase_010 = static_tunnel_fragmentation.ReassemblesTo1500TestCase
    TestCase_011 = static_tunnel_fragmentation.DontFragmentBitNotSetTestCase

ComplianceTestSuite.register('basic-ipv6-transition-mechanisms', BasicIPv6TransitionMechanisms)
