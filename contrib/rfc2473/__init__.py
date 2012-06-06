from veripy.models import ComplianceTestSuite
from veripy.models.decorators import must, should

import tn_4in6
import tn_6in6

import tunnel_encapsulation_limit_option


class GenericPacketTunnelingInIPv6On6In6(ComplianceTestSuite):
    """
    Generic Packet Tunneling In IPv6 On 6in6

    The following tests cover Generic Packet Tunneling for IP version 6.

    Generic Packet Tunneling in IPV6 is a generic mechanism by which a
    packet is encapsulated and carried as payload within an IPv6 packet.
    The resulting packet is called an IPv6 tunnel packet. The forwarding
    path between the source and destination of the tunnel packet is
    called an IPv6 tunnel. The technique is called IPv6 tunneling.

    A typical scenario for IPv6 tunneling is the case in which an
    intermediate node exerts explicit routing control by specifying
    particular forwarding paths for selected packets.  This control is
    achieved by prepending IPv6 headers to each of the selected original
    packets. These prepended headers identify the forwarding paths.

    These tests are designed to verify the readiness of an IPv6 implementation
    vis-a-vis the Generic Packet Tunneling IPv6 specification, with a 6in6 
    tunnel implementation.

    @private
    Author:         MWR
    Source:         RFC2473
    """

    TestCase_001 = tn_6in6.encapsulation.HopLimitDecrementedTestCase
    TestCase_002 = tn_6in6.encapsulation.EntryPointAddressTestCase
    TestCase_003 = tn_6in6.encapsulation.EndPointAddressTestCase
    TestCase_004 = tn_6in6.packet_processing.EncapsulatingHopLimitDecrementedTestCase
    TestCase_005 = tn_6in6.decapsulation.AllEncapsulatedOptionsRemovedTestCase
    TestCase_006 = tn_6in6.decapsulation.NextHeaderIsIPv6WithEncapsulatedIPv6HeaderTestCase
    TestCase_007 = tn_6in6.decapsulation.NextHeaderIsIPv6WithEncapsulatedIPv4HeaderTestCase
    TestCase_008 = tn_6in6.decapsulation.NextHeaderIsIPv4WithEncapsulatedIPv6HeaderTestCase
    TestCase_009 = tn_6in6.nested_encapsulation.HopLimitDecrementedTestCase
    TestCase_010 = tn_6in6.nested_encapsulation.EntryPointAddressTestCase
    TestCase_011 = tn_6in6.nested_encapsulation.EndPointAddressTestCase
    TestCase_012 = tn_6in6.nested_packet_processing.EncapsulatingHopLimitDecrementedWithIPv6EncapsulatedTestCase
    TestCase_013 = tn_6in6.nested_packet_processing.EncapsulatingHopLimitDecrementedWithIPv4EncapsulatedTestCase
    TestCase_014 = tn_6in6.nested_decapsulation.AllEncapsulatedOptionsRemovedTestCase
    TestCase_015 = tn_6in6.nested_decapsulation.NextHeaderIsIPv6WithEncapsulatedIPv6HeaderTestCase
    TestCase_016 = tn_6in6.nested_decapsulation.NextHeaderIsIPv4WithEncapsulatedIPv6HeaderTestCase
    TestCase_017 = tunnel_encapsulation_limit_option.TunnelEncapsulationLimitOptionOf0TestCase
    TestCase_018 = tunnel_encapsulation_limit_option.TunnelEncapsulationLimitOptionOf4TestCase
    TestCase_019 = tunnel_encapsulation_limit_option.TunnelEncapsulationLimitOptionOf255TestCase
    TestCase_020 = tunnel_encapsulation_limit_option.NotEncapsulatedHeaderTestCase
    TestCase_021 = tn_6in6.packet_processing.HopLimitExceededWithinTunnelTestCase
    TestCase_022 = tn_6in6.packet_processing.UnreachableNodeWithinTunnelTestCase
    TestCase_023 = tn_6in6.packet_processing.PacketTooBigWithinTunnelTestCase
    TestCase_024 = tn_6in6.post_processing.HopLimitExceededAfterTunnelTestCase
    TestCase_025 = tn_6in6.post_processing.UnreachableNodeAfterTunnelTestCase
    

class GenericPacketTunnelingInIPv6On4In6(ComplianceTestSuite):
    """
    Generic Packet Tunneling In IPv6 On 4in6

    The following tests cover Generic Packet Tunneling for IP version 6.

    Generic Packet Tunneling in IPV6 is a generic mechanism by which a
    packet is encapsulated and carried as payload within an IPv6 packet.
    The resulting packet is called an IPv6 tunnel packet. The forwarding
    path between the source and destination of the tunnel packet is
    called an IPv6 tunnel. The technique is called IPv6 tunneling.

    A typical scenario for IPv6 tunneling is the case in which an
    intermediate node exerts explicit routing control by specifying
    particular forwarding paths for selected packets.  This control is
    achieved by prepending IPv6 headers to each of the selected original
    packets. These prepended headers identify the forwarding paths.

    These tests are designed to verify the readiness of an IPv6 implementation
    vis-a-vis the Generic Packet Tunneling IPv6 specification, with a 4in6 
    tunnel implementation.

    @private
    Author:         MWR
    Source:         RFC2473
    """
    
    TestCase_001 = tn_4in6.encapsulation.TTLDecrementedTestCase
    TestCase_002 = tn_4in6.encapsulation.EntryPointAddressTestCase
    TestCase_003 = tn_4in6.encapsulation.EndPointAddressTestCase
    TestCase_004 = tn_4in6.packet_processing.EncapsulatingHopLimitDecrementedWithIPv4EncapsulatedTestCase
    TestCase_005 = tn_4in6.decapsulation.AllEncapsulatedOptionsRemovedIPv4TestCase
    TestCase_006 = tn_4in6.packet_processing.HopLimitExceededWithinTunnelTestCase
    TestCase_007 = tn_4in6.packet_processing.UnreachableNodeWithinTunnelIPv4TestCase
    TestCase_008 = tn_4in6.packet_processing.PacketTooBigWithinTunnelIPv4TestCase
    TestCase_009 = tn_4in6.post_processing.TTLExceededAfterTunnelTestCase
    TestCase_010 = tn_4in6.post_processing.UnreachableNodeAfterTunnelTestCase

ComplianceTestSuite.register('generic-packet-tunneling-in-ipv6-on-6in6', GenericPacketTunnelingInIPv6On6In6)
ComplianceTestSuite.register('generic-packet-tunneling-in-ipv6-on-4in6', GenericPacketTunnelingInIPv6On4In6)
