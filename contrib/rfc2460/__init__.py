from veripy.models import ComplianceTestSuite
from veripy.models.decorators import must, should

import extension_header_processing_order
import flow_label_non_zero
import fragment_header_mbit_set_payload_length_invalid
import fragment_reassembly
import hop_limit_decremented
import hop_limit_zero
import ip_forwarding_source_and_destination_address
import next_header_zero
import no_next_header
import no_next_header_after_extension_header
import option_processing_order
import options_processing_destination_options_header
import options_processing_hbhoh_intermediate_node
import options_processing_hop_by_hop_options_header
import payload_length
import reassembly_time_exceeded
import stub_fragment_header
import traffic_class_non_zero
import unrecognised_next_header
import unrecognised_next_header_in_extension_header
import unrecognised_routing_type
import version_field

class IPv6BasicEndNodeSpecification(ComplianceTestSuite):
    """
    IPv6 Basic Specification - End Node

    These tests cover the base specification for Internet Protocol version 6,
    RFC 2460. The base specification specifies the basic IPv6 header and the
    initially defined IPv6 extension headers and options. It also discusses
    packet size issues, the semantics of flow labels and traffic classes, and
    the effects of IPv6 on upper-layer protocols.

    These tests are designed to verify the readiness of an IPv6
    implementation vis-a-vis the IPv6 Base specification.

    @private
    Author:         MWR
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (Section 1)
    """

    # Group 1: IPv6 Header
    TestCase_101 = version_field.VersionFieldV00TestCase
    TestCase_102 = version_field.VersionFieldV04TestCase
    TestCase_103 = version_field.VersionFieldV05TestCase
    TestCase_104 = version_field.VersionFieldV07TestCase
    TestCase_105 = version_field.VersionFieldV15TestCase
    TestCase_106 = traffic_class_non_zero.TrafficClassNonZeroEndNodeTestCase
    # TestCase_107 for routers only (traffic_class_non_zero.TrafficClassNonZeroIntermediateNodeTestCase)
    TestCase_108 = flow_label_non_zero.FlowLabelNonZeroTestCase
    # TestCase_109 for routers only (flow_label_non_zero.FlowLabelNonZeroIntermediateNodeTestCase)
    TestCase_110 = payload_length.PayloadLengthOddTestCase
    # TestCase_111 for routers only (payload_length.RUTForwardsPayloadLengthOddTestCase)
    TestCase_112 = payload_length.PayloadLengthEvenTestCase
    TestCase_113 = no_next_header.NoNextHeaderTestCase
    # TestCase_014 for routers only no_next_header (no_next_header.RUTForwardsNoNextHeader)
    TestCase_115 = unrecognised_next_header.UnrecognisedNextHeaderInIPv6HeaderTestCase
    TestCase_116 = unrecognised_next_header.UnexpectedNextHeaderInIPv6HeaderTestCase
    TestCase_117 = hop_limit_zero.HopLimitZeroTestCase
    # TestCase_118 for routers only (hop_limit_decremented.HopLimitDecrementTestCase)
    # TestCase_119 for routers only (ip_forwarding_source_and_destination_address.RequestSentToGlobalUnicastTestCase)
    # TestCase_120 for routers only (ip_forwarding_source_and_destination_address.RequestSentToGlobalUnicastPrefixEndsInZeroValueFieldsTestCase)
    # TestCase_121 for routers only (ip_forwarding_source_and_destination_address.RequestSentFromUnspecifiedAddressTestCase)
    # TestCase_122 for routers only (ip_forwarding_source_and_destination_address.RequestSentToLoopbackAddressTestCase)
    # TestCase_123 for routers only (ip_forwarding_source_and_destination_address.RequestSentFromLinkLocalAddressTestCase)
    # TestCase_124 for routers only (ip_forwarding_source_and_destination_address.RequestSentToLinkLocalAddressTestCase)
    # TestCase_125 for routers only (ip_forwarding_source_and_destination_address.RequestSentToSiteLocalAddressTestCase)
    # TestCase_126 for routers only (ip_forwarding_source_and_destination_address.RequestSentToGlobalScopeMulticastAddressTestCase)
    # TestCase_127 for routers only (ip_forwarding_source_and_destination_address.RequestSentToLinkLocalScopeMulticastAddressTestCase)
    # TestCase_128 for routers only (ip_forwarding_source_and_destination_address.RequestSentToMulticastAddressReservedValue0TestCase)
    # TestCase_129 for routers only (ip_forwarding_source_and_destination_address.RequestSentToMulticastAddressReservedValueFTestCase)

    # Group 2: Extension Headers and Options
    TestCase_201 = next_header_zero.NextHeaderZeroTestCase
    TestCase_202 = no_next_header_after_extension_header.NoNextHeaderAfterExtensionHeaderEndNodeTestCase
    # TestCase_203 for routers only (no_next_header_after_extension_header.NoNextHeaderAfterExtensionHeaderIntermediateNodeTestCase)
    TestCase_204 = unrecognised_next_header_in_extension_header.UnrecognisedNextHeaderInExtensionHeaderTestCase
    TestCase_205 = unrecognised_next_header_in_extension_header.UnexpectedNextHeaderInExtensionHeaderTestCase
    TestCase_206 = extension_header_processing_order.DstOptnsHdrPrecedesFragHdrAndErrorFromDstOptnsHdrTestCase
    TestCase_207 = extension_header_processing_order.DstOptnsHdrPrecedesFragHdrAndErrorFromFragHdrTestCase
    TestCase_208 = extension_header_processing_order.FragHdrPrecedesDstOptnsHdrAndErrorFromFragHdrTestCase
    TestCase_209 = extension_header_processing_order.FragHdrPrecedesDstOptnsHdrAndErrorFromDstOptnsHdrTestCase
    TestCase_210 = option_processing_order.FirstOptionHasMostSignificantBits00NextHasMostSignificantBits01TestCase
    TestCase_211 = option_processing_order.FirstOptionHasMostSignificantBits00NextHasMostSignificantBits10TestCase
    TestCase_212 = option_processing_order.FirstOptionHasMostSignificantBits00NextHasMostSignificantBits11TestCase
    TestCase_213 = options_processing_hop_by_hop_options_header.OptionsProcessingHopByHopOptionsHeaderPad1TestCase
    TestCase_214 = options_processing_hop_by_hop_options_header.OptionsProcessingHopByHopOptionsHeaderPadNTestCase
    TestCase_215 = options_processing_hop_by_hop_options_header.OptionsProcessingHopByHopOptionsHeaderMostSignificantBits00TestCase
    TestCase_216 = options_processing_hop_by_hop_options_header.OptionsProcessingHopByHopOptionsHeaderMostSignificantBits01TestCase
    TestCase_217 = options_processing_hop_by_hop_options_header.OptionsProcessingHopByHopOptionsHeaderMostSignificantBits10UnicastDestinationTestCase
    TestCase_218 = options_processing_hop_by_hop_options_header.OptionsProcessingHopByHopOptionsHeaderMostSignificantBits11UnicastDestinationTestCase
    TestCase_219 = options_processing_hop_by_hop_options_header.OptionsProcessingHopByHopOptionsHeaderMostSignificantBits10MulticastDestinationTestCase
    TestCase_220 = options_processing_hop_by_hop_options_header.OptionsProcessingHopByHopOptionsHeaderMostSignificantBits11MulticastDestinationTestCase
    # TestCase_221 for routers only (options_processing_hbhoh_intermediate_node.HopByHopOptionsHeaderPad1TestCase)
    # TestCase_222 for routers only (options_processing_hbhoh_intermediate_node.HopByHopOptionsHeaderPadNTestCase)
    # TestCase_223 for routers only (options_processing_hbhoh_intermediate_node.HopByHopOptionsHeaderMostSignificantBits00TestCase)
    # TestCase_224 for routers only (options_processing_hbhoh_intermediate_node.HopByHopOptionsHeaderMostSignificantBits01TestCase)
    # TestCase_225 for routers only (options_processing_hbhoh_intermediate_node.HopByHopOptionsHeaderMostSignificantBits10UnicastDestinationTestCase)
    # TestCase_226 for routers only (options_processing_hbhoh_intermediate_node.HopByHopOptionsHeaderMostSignificantBits11UnicastDestinationTestCase)
    # TestCase_227 for routers only (options_processing_hbhoh_intermediate_node.HopByHopOptionsHeaderMostSignificantBits10MulticastDestinationTestCase)
    # TestCase_228 for routers only (options_processing_hbhoh_intermediate_node.HopByHopOptionsHeaderMostSignificantBits11MulticastDestinationTestCase)
    TestCase_229 = options_processing_destination_options_header.OptionsProcessingDestinationOptionsHeaderPad1TestCase
    TestCase_230 = options_processing_destination_options_header.OptionsProcessingDestinationOptionsHeaderPadNTestCase
    TestCase_231 = options_processing_destination_options_header.OptionsProcessingDestinationOptionsHeaderMostSignificantBits00TestCase
    TestCase_232 = options_processing_destination_options_header.OptionsProcessingDestinationOptionsHeaderMostSignificantBits01TestCase
    TestCase_233 = options_processing_destination_options_header.OptionsProcessingDestinationOptionsHeaderMostSignificantBits10UnicastDestinationTestCase
    TestCase_234 = options_processing_destination_options_header.OptionsProcessingDestinationOptionsHeaderMostSignificantBits11UnicastDestinationTestCase
    TestCase_235 = options_processing_destination_options_header.OptionsProcessingDestinationOptionsHeaderMostSignificantBits10MulticastDestinationTestCase
    TestCase_236 = options_processing_destination_options_header.OptionsProcessingDestinationOptionsHeaderMostSignificantBits11MulticastDestinationTestCase
    TestCase_237 = unrecognised_routing_type.UnrecognisedRoutingTypeType33TestCase
    TestCase_238 = unrecognised_routing_type.UnrecognisedRoutingTypeType0TestCase
    # TestCase_239 for routers only (unrecognised_routing_type_intermediate_node.UnrecognisedRoutingTypeType33TestCase)
    # TestCase_240 for routers only (unrecognised_routing_type_intermediate_node.UnrecognisedRoutingTypeType0TestCase)

    # Group 3: Fragmentation
    TestCase_301 = fragment_reassembly.FragmentReassemblyAllFragmentsValidTestCase
    TestCase_302 = fragment_reassembly.FragmentReassemblyAllFragmentsValidInReverseOrderTestCase
    TestCase_303 = fragment_reassembly.FragmentReassemblyFragmentIDsDifferBetweenFragmentsTestCase
    TestCase_304 = fragment_reassembly.FragmentReassemblySourceAddressesDifferBetweenFragmentsTestCase
    TestCase_305 = fragment_reassembly.FragmentReassemblyDestinationAddressesDifferBetweenFragmentsTestCase
    TestCase_306 = fragment_reassembly.FragmentReassemblyReassembleTo1500TestCase
    TestCase_307 = reassembly_time_exceeded.ReassemblyTimeExceededTimeElapsedBetweenFragmentsLessThanSixtySecondsTestCase
    TestCase_308 = reassembly_time_exceeded.ReassemblyTimeExceededTimeElapsedBeforeLastFragmentsArriveTestCase
    TestCase_309 = reassembly_time_exceeded.ReassemblyTimeExceededGlobalTimeExceededOnlyFirstFragmentReceivedTestCase
    TestCase_310 = reassembly_time_exceeded.ReassemblyTimeExceededLinkLocalTimeExceededOnlyFirstFragmentReceivedTestCase
    TestCase_311 = reassembly_time_exceeded.ReassemblyTimeExceededTimeExceededOnlySecondFragmentReceivedTestCase
    TestCase_312 = fragment_header_mbit_set_payload_length_invalid.FragmentHeaderMBitSetPayloadLengthInvalidTestCase
    TestCase_313 = stub_fragment_header.StubFragmentHeaderTestCase


class IPv6BasicIntermediateNodeSpecification(ComplianceTestSuite):
    """
    IPv6 Basic Specification - Intermediate Node

    These tests cover the base specification for Internet Protocol version 6,
    RFC 2460. The base specification specifies the basic IPv6 header and the
    initially defined IPv6 extension headers and options. It also discusses
    packet size issues, the semantics of flow labels and traffic classes, and
    the effects of IPv6 on upper-layer protocols.

    These tests are designed to verify the readiness of an IPv6
    implementation vis-a-vis the IPv6 Base specification.

    @private
    Author:         MWR
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (Section 1)
    """

    # Group 1: IPv6 Header
    TestCase_101 = version_field.VersionFieldV00TestCase
    TestCase_102 = version_field.VersionFieldV04TestCase
    TestCase_103 = version_field.VersionFieldV05TestCase
    TestCase_104 = version_field.VersionFieldV07TestCase
    TestCase_105 = version_field.VersionFieldV15TestCase
    # TestCase_106 for end nodes only (traffic_class_non_zero.TrafficClassNonZeroEndNodeTestCase)
    TestCase_107 = traffic_class_non_zero.TrafficClassNonZeroIntermediateNodeTestCase
    TestCase_108 = flow_label_non_zero.FlowLabelNonZeroTestCase
    TestCase_109 = flow_label_non_zero.FlowLabelNonZeroIntermediateNodeTestCase
    TestCase_110 = payload_length.PayloadLengthOddTestCase
    TestCase_111 = payload_length.RUTForwardsPayloadLengthOddTestCase
    TestCase_112 = payload_length.PayloadLengthEvenTestCase
    TestCase_113 = no_next_header.NoNextHeaderTestCase
    TestCase_114 = no_next_header.RUTForwardsNoNextHeader
    TestCase_115 = unrecognised_next_header.UnrecognisedNextHeaderInIPv6HeaderTestCase
    TestCase_116 = unrecognised_next_header.UnexpectedNextHeaderInIPv6HeaderTestCase
    # TestCase_117 for end nodes only (hop_limit_zero.HopLimitZeroTestCase)
    TestCase_118 = hop_limit_decremented.HopLimitDecrementTestCase
    TestCase_119 = ip_forwarding_source_and_destination_address.RequestSentToGlobalUnicastTestCase
    TestCase_120 = ip_forwarding_source_and_destination_address.RequestSentToGlobalUnicastPrefixEndsInZeroValueFieldsTestCase
    TestCase_121 = ip_forwarding_source_and_destination_address.RequestSentFromUnspecifiedAddressTestCase
    TestCase_122 = ip_forwarding_source_and_destination_address.RequestSentToLoopbackAddressTestCase
    TestCase_123 = ip_forwarding_source_and_destination_address.RequestSentFromLinkLocalAddressTestCase
    TestCase_124 = ip_forwarding_source_and_destination_address.RequestSentToLinkLocalAddressTestCase
    TestCase_125 = ip_forwarding_source_and_destination_address.RequestSentToSiteLocalAddressTestCase
    TestCase_126 = ip_forwarding_source_and_destination_address.RequestSentToGlobalScopeMulticastAddressTestCase
    TestCase_127 = ip_forwarding_source_and_destination_address.RequestSentToLinkLocalScopeMulticastAddressTestCase
    TestCase_128 = ip_forwarding_source_and_destination_address.RequestSentToMulticastAddressReservedValue0TestCase
    TestCase_129 = ip_forwarding_source_and_destination_address.RequestSentToMulticastAddressReservedValueFTestCase

    # Group 2: Extension Headers and Options
    TestCase_201 = next_header_zero.NextHeaderZeroTestCase
    TestCase_202 = no_next_header_after_extension_header.NoNextHeaderAfterExtensionHeaderEndNodeTestCase
    TestCase_203 = no_next_header_after_extension_header.NoNextHeaderAfterExtensionHeaderIntermediateNodeTestCase
    TestCase_204 = unrecognised_next_header_in_extension_header.UnrecognisedNextHeaderInExtensionHeaderTestCase
    TestCase_205 = unrecognised_next_header_in_extension_header.UnexpectedNextHeaderInExtensionHeaderTestCase
    TestCase_206 = extension_header_processing_order.DstOptnsHdrPrecedesFragHdrAndErrorFromDstOptnsHdrTestCase
    TestCase_207 = extension_header_processing_order.DstOptnsHdrPrecedesFragHdrAndErrorFromFragHdrTestCase
    TestCase_208 = extension_header_processing_order.FragHdrPrecedesDstOptnsHdrAndErrorFromFragHdrTestCase
    TestCase_209 = extension_header_processing_order.FragHdrPrecedesDstOptnsHdrAndErrorFromDstOptnsHdrTestCase
    TestCase_210 = option_processing_order.FirstOptionHasMostSignificantBits00NextHasMostSignificantBits01TestCase
    TestCase_211 = option_processing_order.FirstOptionHasMostSignificantBits00NextHasMostSignificantBits10TestCase
    TestCase_212 = option_processing_order.FirstOptionHasMostSignificantBits00NextHasMostSignificantBits11TestCase
    # TestCase_213 for end nodes only (options_processing_hop_by_hop_options_header.OptionsProcessingHopByHopOptionsHeaderPad1TestCase)
    # TestCase_214 for end nodes only (options_processing_hop_by_hop_options_header.OptionsProcessingHopByHopOptionsHeaderPadNTestCase)
    # TestCase_215 for end nodes only (options_processing_hop_by_hop_options_header.OptionsProcessingHopByHopOptionsHeaderMostSignificantBits00TestCase)
    # TestCase_216 for end nodes only (options_processing_hop_by_hop_options_header.OptionsProcessingHopByHopOptionsHeaderMostSignificantBits01TestCase)
    # TestCase_217 for end nodes only (options_processing_hop_by_hop_options_header.OptionsProcessingHopByHopOptionsHeaderMostSignificantBits10UnicastDestinationTestCase)
    # TestCase_218 for end nodes only (options_processing_hop_by_hop_options_header.OptionsProcessingHopByHopOptionsHeaderMostSignificantBits11UnicastDestinationTestCase)
    # TestCase_219 for end nodes only (options_processing_hop_by_hop_options_header.OptionsProcessingHopByHopOptionsHeaderMostSignificantBits10MulticastDestinationTestCase)
    # TestCase_220 for end nodes only (options_processing_hop_by_hop_options_header.OptionsProcessingHopByHopOptionsHeaderMostSignificantBits11MulticastDestinationTestCase)
    TestCase_221 = options_processing_hbhoh_intermediate_node.HopByHopOptionsHeaderPad1TestCase
    TestCase_222 = options_processing_hbhoh_intermediate_node.HopByHopOptionsHeaderPadNTestCase
    TestCase_223 = options_processing_hbhoh_intermediate_node.HopByHopOptionsHeaderMostSignificantBits00TestCase
    TestCase_224 = options_processing_hbhoh_intermediate_node.HopByHopOptionsHeaderMostSignificantBits01TestCase
    TestCase_225 = options_processing_hbhoh_intermediate_node.HopByHopOptionsHeaderMostSignificantBits10UnicastDestinationTestCase
    TestCase_226 = options_processing_hbhoh_intermediate_node.HopByHopOptionsHeaderMostSignificantBits11UnicastDestinationTestCase
    TestCase_227 = options_processing_hbhoh_intermediate_node.HopByHopOptionsHeaderMostSignificantBits10MulticastDestinationTestCase
    TestCase_228 = options_processing_hbhoh_intermediate_node.HopByHopOptionsHeaderMostSignificantBits11MulticastDestinationTestCase
    TestCase_229 = options_processing_destination_options_header.OptionsProcessingDestinationOptionsHeaderPad1TestCase
    TestCase_230 = options_processing_destination_options_header.OptionsProcessingDestinationOptionsHeaderPadNTestCase
    TestCase_231 = options_processing_destination_options_header.OptionsProcessingDestinationOptionsHeaderMostSignificantBits00TestCase
    TestCase_232 = options_processing_destination_options_header.OptionsProcessingDestinationOptionsHeaderMostSignificantBits01TestCase
    TestCase_233 = options_processing_destination_options_header.OptionsProcessingDestinationOptionsHeaderMostSignificantBits10UnicastDestinationTestCase
    TestCase_234 = options_processing_destination_options_header.OptionsProcessingDestinationOptionsHeaderMostSignificantBits11UnicastDestinationTestCase
    TestCase_235 = options_processing_destination_options_header.OptionsProcessingDestinationOptionsHeaderMostSignificantBits10MulticastDestinationTestCase
    TestCase_236 = options_processing_destination_options_header.OptionsProcessingDestinationOptionsHeaderMostSignificantBits11MulticastDestinationTestCase
    # TestCase_237 for end nodes only (unrecognised_routing_type.UnrecognisedRoutingTypeType33TestCase)
    # TestCase_238 for end nodes only (unrecognised_routing_type.UnrecognisedRoutingTypeType0TestCase)
    TestCase_239 = unrecognised_routing_type.UnrecognisedRoutingTypeType33IntermediateNodeTestCase
    TestCase_240 = unrecognised_routing_type.UnrecognisedRoutingTypeType0IntermediateNodeTestCase

    # Group 3: Fragmentation
    TestCase_301 = fragment_reassembly.FragmentReassemblyAllFragmentsValidTestCase
    TestCase_302 = fragment_reassembly.FragmentReassemblyAllFragmentsValidInReverseOrderTestCase
    TestCase_303 = fragment_reassembly.FragmentReassemblyFragmentIDsDifferBetweenFragmentsTestCase
    TestCase_304 = fragment_reassembly.FragmentReassemblySourceAddressesDifferBetweenFragmentsTestCase
    TestCase_305 = fragment_reassembly.FragmentReassemblyDestinationAddressesDifferBetweenFragmentsTestCase
    TestCase_306 = fragment_reassembly.FragmentReassemblyReassembleTo1500TestCase
    TestCase_307 = reassembly_time_exceeded.ReassemblyTimeExceededTimeElapsedBetweenFragmentsLessThanSixtySecondsTestCase
    TestCase_308 = reassembly_time_exceeded.ReassemblyTimeExceededTimeElapsedBeforeLastFragmentsArriveTestCase
    TestCase_309 = reassembly_time_exceeded.ReassemblyTimeExceededGlobalTimeExceededOnlyFirstFragmentReceivedTestCase
    TestCase_310 = reassembly_time_exceeded.ReassemblyTimeExceededLinkLocalTimeExceededOnlyFirstFragmentReceivedTestCase
    TestCase_311 = reassembly_time_exceeded.ReassemblyTimeExceededTimeExceededOnlySecondFragmentReceivedTestCase
    TestCase_312 = fragment_header_mbit_set_payload_length_invalid.FragmentHeaderMBitSetPayloadLengthInvalidTestCase
    TestCase_313 = stub_fragment_header.StubFragmentHeaderTestCase

ComplianceTestSuite.register('ipv6-basic-end-node-specification', IPv6BasicEndNodeSpecification)
ComplianceTestSuite.register('ipv6-basic-intermediate-node-specification', IPv6BasicIntermediateNodeSpecification)
