from veripy.models import ComplianceTestSuite
from veripy.models.decorators import must, should

import destination_unreachable_message_generation
import erroneous_header_field
import error_condition_with_icmpv6_error_messages
import error_condition_with_multicast_destination
import error_condition_with_non_unique_source
import error_condition_with_non_unique_source_anycast
import error_condition_with_non_unique_source_multicast
import hop_limit_exceeded
import packet_too_big_message_generation
import replying_to_echo_requests
import transmitting_echo_requests
import unknown_informational_message_type
import unrecognized_next_header

class ICMPv6EndNodeSpecification(ComplianceTestSuite):
    """
    ICMPv6 - End Node

    The following tests cover the Internet Control Message Protocol for
    IP version 6.

    @private
    Author:         MWR
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (Section 5)
    """

    TestCase_001 = transmitting_echo_requests.TransmittingEchoRequestsTestCase
    TestCase_002 = replying_to_echo_requests.RequestSentToLinkLocalAddressTestCase
    TestCase_003 = replying_to_echo_requests.RequestSentToGlobalAddressTestCase
    TestCase_004 = replying_to_echo_requests.RequestSentToAllNodesMulticastAddressTestCase
    # TestCase_005 for routers only (replying_to_echo_requests.RequestSentToAllRoutersMulticastAddressTestCase)
    TestCase_006 = replying_to_echo_requests.RequestSentToUnspecifiedAddressTestCase
    TestCase_007 = replying_to_echo_requests.RequestSentToLoopbackAddressTestCase
    TestCase_008 = replying_to_echo_requests.RequestSentToSiteLocalAddressEndNodeTestCase
    # TestCase_009 for routers only (destination_unreachable_message_generation.RouteUnreachableTestCase)
    # TestCase_010 for routers only (destination_unreachable_message_generation.AddressUnreachableTestCase)
    TestCase_011 = destination_unreachable_message_generation.PortUnreachableLinkLocalTestCase
    TestCase_012 = destination_unreachable_message_generation.PortUnreachableGlobalTestCase
    # TestCase_013 for routers only (destination_unreachable_message_generation.BeyondScopeOfSourceAddressTestCase)
    # TestCase_014 for routers only (packet_too_big_message_generation.UnicastDestinationTestCase)
    # TestCase_015 for routers only (packet_too_big_message_generation.MulticastDestinationTestCase)
    # TestCase_016 for routers only (hop_limit_exceeded.ReceiveHopLimit0TestCase)
    # TestCase_017 for routers only (hop_limit_exceeded.DecrementHopLimitTo0TestCase)
    TestCase_018 = erroneous_header_field.ErroneousHeaderFieldTestCase
    TestCase_019 = unrecognized_next_header.UnrecognizedNextHeaderTestCase
    TestCase_020 = unknown_informational_message_type.UnknownInformationalMessageTypeTestCase
    TestCase_021 = error_condition_with_icmpv6_error_messages.FlawedDstUnreachableCode0WithDestinationUnreachableTestCase
    TestCase_022 = error_condition_with_icmpv6_error_messages.FlawedDstUnreachableCode3WithHopLimit0TestCase
    TestCase_023 = error_condition_with_icmpv6_error_messages.FlawedTimeExceededCode0WithNoRouteToDestinationTestCase
    TestCase_024 = error_condition_with_icmpv6_error_messages.FlawedTimeExceededCode1WithNoRouteToDestinationTestCase
    TestCase_025 = error_condition_with_icmpv6_error_messages.FlawedDstPacketTooBigWithAddressUnreachableTestCase
    TestCase_026 = error_condition_with_icmpv6_error_messages.FlawedParamProblemWithHopLimit0TestCase
    TestCase_027 = error_condition_with_multicast_destination.UDPPortUnreachableTestCase
    TestCase_028 = error_condition_with_multicast_destination.EchoRequestReassemblyTimeoutTestCase
    TestCase_029 = error_condition_with_non_unique_source.NonUniqueSourceUDPPortUnreachableTestCase
    # TestCase_030 for routers only (error_condition_with_non_unique_source.NonUniqueSourceEchoRequestTooBigTest)
    TestCase_031 = error_condition_with_non_unique_source.NonUniqueSourceReassemblyTimeoutTestCase
    TestCase_032 = error_condition_with_non_unique_source.NonUniqueSourceInvalidDestinationOptionsTestCase
    TestCase_033 = error_condition_with_non_unique_source_multicast.NonUniqueSourceMulticastUDPPortUnreachableTestCase
    # TestCase_034 for routers only (error_condition_with_non_unique_source_multicast.NonUniqueSourceMulticastEchoRequestTooBigTestCase)
    TestCase_035 = error_condition_with_non_unique_source_multicast.NonUniqueSourceMulticastReassemblyTimeoutTestCase
    TestCase_036 = error_condition_with_non_unique_source_multicast.NonUniqueSourceMulticastInvalidDestinationOptionsTestCase
    TestCase_036 = error_condition_with_non_unique_source_anycast.UDPPortUnreachableTestCase
    TestCase_037 = error_condition_with_non_unique_source_anycast.EchoRequestTooBigTestCase
    TestCase_038 = error_condition_with_non_unique_source_anycast.EchoRequestReassemblyTimeoutTestCase
    TestCase_039 = error_condition_with_non_unique_source_anycast.EchoRequestWithUnknownOptionInDestinationOptionsTestCase


class ICMPv6IntermediateNodeSpecification(ComplianceTestSuite):
    """
    ICMPv6 - Intermediate Node

    The following tests cover the Internet Control Message Protocol for
    IP version 6.

    @private
    Author:         MWR
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (Section 5)
    """

    TestCase_001 = transmitting_echo_requests.TransmittingEchoRequestsTestCase
    TestCase_002 = replying_to_echo_requests.RequestSentToLinkLocalAddressTestCase
    TestCase_003 = replying_to_echo_requests.RequestSentToGlobalAddressTestCase
    TestCase_004 = replying_to_echo_requests.RequestSentToAllNodesMulticastAddressTestCase
    TestCase_005 = replying_to_echo_requests.RequestSentToAllRoutersMulticastAddressTestCase
    TestCase_006 = replying_to_echo_requests.RequestSentToUnspecifiedAddressTestCase
    TestCase_007 = replying_to_echo_requests.RequestSentToLoopbackAddressTestCase
    TestCase_008 = replying_to_echo_requests.RequestSentToSiteLocalAddressIntermediateNodeTestCase
    TestCase_009 = destination_unreachable_message_generation.RouteUnreachableTestCase
    TestCase_010 = destination_unreachable_message_generation.AddressUnreachableTestCase
    TestCase_011 = destination_unreachable_message_generation.PortUnreachableLinkLocalTestCase
    TestCase_012 = destination_unreachable_message_generation.PortUnreachableGlobalTestCase
    TestCase_013 = destination_unreachable_message_generation.BeyondScopeOfSourceAddressTestCase
    TestCase_014 = packet_too_big_message_generation.UnicastDestinationTestCase
    TestCase_015 = packet_too_big_message_generation.MulticastDestinationTestCase
    TestCase_016 = hop_limit_exceeded.ReceiveHopLimit0TestCase
    TestCase_017 = hop_limit_exceeded.DecrementHopLimitTo0TestCase
    TestCase_018 = erroneous_header_field.ErroneousHeaderFieldTestCase
    TestCase_019 = unrecognized_next_header.UnrecognizedNextHeaderTestCase
    TestCase_020 = unknown_informational_message_type.UnknownInformationalMessageTypeTestCase
    TestCase_021 = error_condition_with_icmpv6_error_messages.FlawedDstUnreachableCode0WithDestinationUnreachableTestCase
    TestCase_022 = error_condition_with_icmpv6_error_messages.FlawedDstUnreachableCode3WithHopLimit0TestCase
    TestCase_023 = error_condition_with_icmpv6_error_messages.FlawedTimeExceededCode0WithNoRouteToDestinationTestCase
    TestCase_024 = error_condition_with_icmpv6_error_messages.FlawedTimeExceededCode1WithNoRouteToDestinationTestCase
    TestCase_025 = error_condition_with_icmpv6_error_messages.FlawedDstPacketTooBigWithAddressUnreachableTestCase
    TestCase_026 = error_condition_with_icmpv6_error_messages.FlawedParamProblemWithHopLimit0TestCase
    TestCase_027 = error_condition_with_multicast_destination.UDPPortUnreachableTestCase
    TestCase_028 = error_condition_with_multicast_destination.EchoRequestReassemblyTimeoutTestCase
    TestCase_029 = error_condition_with_non_unique_source.NonUniqueSourceUDPPortUnreachableTestCase
    TestCase_030 = error_condition_with_non_unique_source.NonUniqueSourceEchoRequestTooBigTestCase
    TestCase_031 = error_condition_with_non_unique_source.NonUniqueSourceReassemblyTimeoutTestCase
    TestCase_032 = error_condition_with_non_unique_source.NonUniqueSourceInvalidDestinationOptionsTestCase
    TestCase_033 = error_condition_with_non_unique_source_multicast.NonUniqueSourceMulticastUDPPortUnreachableTestCase
    TestCase_034 = error_condition_with_non_unique_source_multicast.NonUniqueSourceMulticastEchoRequestTooBigTestCase
    TestCase_035 = error_condition_with_non_unique_source_multicast.NonUniqueSourceMulticastReassemblyTimeoutTestCase
    TestCase_036 = error_condition_with_non_unique_source_multicast.NonUniqueSourceMulticastInvalidDestinationOptionsTestCase
    TestCase_036 = error_condition_with_non_unique_source_anycast.UDPPortUnreachableTestCase
    TestCase_037 = error_condition_with_non_unique_source_anycast.EchoRequestTooBigTestCase
    TestCase_038 = error_condition_with_non_unique_source_anycast.EchoRequestReassemblyTimeoutTestCase
    TestCase_039 = error_condition_with_non_unique_source_anycast.EchoRequestWithUnknownOptionInDestinationOptionsTestCase


ComplianceTestSuite.register('icmpv6-end-node', ICMPv6EndNodeSpecification)
ComplianceTestSuite.register('icmpv6-intermediate-node', ICMPv6IntermediateNodeSpecification)
