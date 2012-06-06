from veripy.models import ComplianceTestSuite
from veripy.models.decorators import must, should

import default_router_switch
import host_ignores_router_solicitations
import invalid_neighbor_advertisement_handling
import invalid_neighbor_solicitation_handling
import invalid_option
import invalid_redirect_does_not_update_neighbor_cache
import neighbor_advertisement_processing_rbit_change
import neighbor_solicitation_is_router_flag
import neighbor_solicitation_origination_address_resolution
import neighbor_solicitation_origination_reachability_confirmation
import neighbor_solicitation_processing_anycast
import next_hop_determination
import on_link_determination
import prefix_information_option_processing
import redirected_on_link_invalid
import redirected_on_link_suspicious
import redirected_on_link_valid
import redirected_to_alternate_router_invalid
import redirected_to_alternate_router_suspicious
import redirected_to_alternate_router_valid
import redirected_twice
import resolution_wait_queue
import router_advertisement_processing_cur_hop_limit
import router_advertisement_processing_isrouter_flag
import router_advertisement_processing_on_link_determination
import router_advertisement_processing_validity
import router_solicitations
import solicited_router_advertisement
import router_ignores_invalid_router_solicitations
import router_sends_valid_router_advertisement


class NeighborDiscoverySpecification(ComplianceTestSuite):
    """
    Neighbor Discovery - End Node

    The tests in this group verify conformance of the Address Resolution and
    Neighbor Unreachability Detection function with the Neighbor Discovery
    Specification.
    """

    TestCase_001 = on_link_determination.OnLinkDeterminationLinkLocalTestCase
    TestCase_002 = on_link_determination.OnLinkDeterminationGlobalTestCase
    TestCase_003 = on_link_determination.OnLinkDeterminationGlobalAddressTestCase
    TestCase_004 = resolution_wait_queue.ResolutionWaitQueueSingleQueueTestCase
    TestCase_005 = resolution_wait_queue.ResolutionWaitQueueMultipleQueueTestCase
    TestCase_006 = prefix_information_option_processing.PrefixInformationOptionProcessingTestCase
    TestCase_007 = neighbor_solicitation_origination_address_resolution.LinkLocalRetransmitInterval1TestCase
    TestCase_008 = neighbor_solicitation_origination_address_resolution.LinkLocalRetransmitInterval5TestCase
    TestCase_009 = neighbor_solicitation_origination_address_resolution.GlobalRetransmitInterval1TestCase
    TestCase_010 = neighbor_solicitation_origination_address_resolution.GlobalRetransmitInterval5TestCase
    TestCase_011 = neighbor_solicitation_origination_reachability_confirmation.LinkLocalToLinkLocalTestCase
    TestCase_012 = neighbor_solicitation_origination_reachability_confirmation.GlobalToGlobalTestCase
    TestCase_013 = neighbor_solicitation_origination_reachability_confirmation.LinkLocalToGlobalTestCase
    TestCase_014 = neighbor_solicitation_origination_reachability_confirmation.GlobalToLinkLocalTestCase
    TestCase_015 = invalid_neighbor_solicitation_handling.InvalidTargetAddressTestCase
    TestCase_016 = invalid_neighbor_solicitation_handling.InvalidDestinationAddressTestCase
    TestCase_017 = invalid_neighbor_solicitation_handling.InvalidSourceLinkLayerAddressOptionTestCase
    TestCase_018 = invalid_neighbor_solicitation_handling.InvalidHopLimitTestCase
    TestCase_019 = invalid_neighbor_solicitation_handling.InvalidChecksumTestCase
    TestCase_020 = invalid_neighbor_solicitation_handling.InvalidICMPCodeTestCase
    TestCase_021 = invalid_neighbor_solicitation_handling.InvalidICMPLengthTestCase
    TestCase_022 = invalid_neighbor_solicitation_handling.OptionOfLengthZeroTestCase
    #TestCase_023-025 neighbor_solicitation_processing_no_nce
    #TestCase_026-028 neighbor_solicitation_processing_nce_state_incomplete
    #TestCase_029-031 neighbor_solicitation_processing_nce_state_reachable
    #TestCase_032-035 neighbor_solicitation_processing_nce_state_stale
    #TestCase_036-039 neighbor_solicitation_processing_nce_state_probe
    TestCase_040 = neighbor_solicitation_is_router_flag.UnicastNeighborSolicitationWithoutSLLATestCase
    TestCase_041 = neighbor_solicitation_is_router_flag.UnicastNeighborSolicitationWithSLLATestCase
    TestCase_042 = neighbor_solicitation_is_router_flag.MulticastNeighborSolicitationWithDifferentSLLATestCase
    #TestCase_043 for routers only (neighbor_solicitation_processing_anycase)
    TestCase_044 = invalid_neighbor_advertisement_handling.SolicitedFlagIsSetTestCase
    TestCase_045 = invalid_neighbor_advertisement_handling.HopLimitIs254TestCase
    TestCase_046 = invalid_neighbor_advertisement_handling.InvalidChecksumTestCase
    TestCase_047 = invalid_neighbor_advertisement_handling.InvalidICMPCodeTestCase
    TestCase_048 = invalid_neighbor_advertisement_handling.InvalidICMPLengthTestCase
    TestCase_049 = invalid_neighbor_advertisement_handling.TargetIsMulticastTestCase
    TestCase_050 = invalid_neighbor_advertisement_handling.OptionLengthIsZeroTestCase
    #TestCase_051-058 neighbor_advertisement_processing_no_nce
    #TestCase_059-063 neighbor_advertisement_processing_nce_state_incomplete
    #TestCase_064-082 neighbor_advertisement_processing_nce_state_reachable
    #TestCase_083-102 neighbor_advertisement_processing_nce_state_stale
    #TestCase_103-121 neighbor_advertisement_processing_nce_state_probe
    TestCase_122 = neighbor_advertisement_processing_rbit_change.FlagsSet0x011TestCase
    TestCase_123 = neighbor_advertisement_processing_rbit_change.FlagsSet0x000TestCase
    TestCase_124 = neighbor_advertisement_processing_rbit_change.FlagsSet0x001TestCase
    TestCase_125 = neighbor_advertisement_processing_rbit_change.FlagsSet0x010TestCase
    TestCase_126 = neighbor_advertisement_processing_rbit_change.FlagsSet0x011TLLTestCase
    TestCase_127 = neighbor_advertisement_processing_rbit_change.FlagsSet0x000TLLTestCase
    TestCase_128 = neighbor_advertisement_processing_rbit_change.FlagsSet0x001TLLTestCase
    TestCase_129 = neighbor_advertisement_processing_rbit_change.FlagsSet0x010TLLTestCase

    TestCase_201 = router_solicitations.RouterSolicitationsTestCase
    TestCase_202 = solicited_router_advertisement.ValidAdvertisementNoSLLTestCase
    TestCase_203 = solicited_router_advertisement.ValidAdvertisementSLLTestCase
    TestCase_204 = solicited_router_advertisement.InvalidAdvertisementGlobalSourceAddressTestCase
    TestCase_205 = solicited_router_advertisement.InvalidAdvertisementBadHopLimitTestCase
    TestCase_206 = solicited_router_advertisement.InvalidAdvertisementBadICMPChecksumTestCase
    TestCase_207 = solicited_router_advertisement.InvalidAdvertisementBadICMPCodeTestCase
    TestCase_208 = host_ignores_router_solicitations.AllRouterMulticastDestinationTestCase
    TestCase_209 = host_ignores_router_solicitations.AllNodesMulticastDestinationTestCase
    TestCase_210 = host_ignores_router_solicitations.LinkLoalUnicastDestinationTestCase
    #TestCase_211-237 for routers only
    TestCase_229 = default_router_switch.RouterInUseFailsTestCase
    TestCase_230 = router_advertisement_processing_validity.GlobalSourceAddressTestCase
    TestCase_231 = router_advertisement_processing_validity.BadHopLimitTestCase
    TestCase_232 = router_advertisement_processing_validity.BadICMPChecksumTestCase
    TestCase_233 = router_advertisement_processing_validity.BadICMPCodeTestCase
    TestCase_234 = router_advertisement_processing_validity.BadICMPLengthTestCase
    TestCase_235 = router_advertisement_processing_validity.BadOptionLengthTestCase
    TestCase_236 = router_advertisement_processing_cur_hop_limit.UnspecifiedTestCase
    TestCase_237 = router_advertisement_processing_cur_hop_limit.NonZeroTestCase
    #TestCase_238-242 router_advertisement_processing_router_lifetime
    #TestCase_243-253 router_advertisement_processing_neighbor_cache
    TestCase_254 = router_advertisement_processing_isrouter_flag.RAWithoutSLLTestCase
    TestCase_255 = router_advertisement_processing_isrouter_flag.RAWithSameSLLAsCachedTestCase
    TestCase_256 = router_advertisement_processing_isrouter_flag.RAWithDifferentSLLAsCachedTestCase
    TestCase_257 = next_hop_determination.NextHopDeterminationTestCase
    TestCase_258 = router_advertisement_processing_on_link_determination.OnLinkDeterminationTestCase


class NeighborDiscoveryIntermediateNodeSpecification(ComplianceTestSuite):
    """
    Neighbor Discovery - Intermediate Node

    The tests in this group verify conformance of the Address Resolution and
    Neighbor Unreachability Detection function with the Neighbor Discovery
    Specification.
    """

    TestCase_001 = on_link_determination.OnLinkDeterminationLinkLocalTestCase
    TestCase_002 = on_link_determination.OnLinkDeterminationGlobalTestCase
    TestCase_003 = on_link_determination.OnLinkDeterminationGlobalAddressTestCase
    TestCase_004 = resolution_wait_queue.ResolutionWaitQueueSingleQueueTestCase
    TestCase_005 = resolution_wait_queue.ResolutionWaitQueueMultipleQueueTestCase
    #TestCase_006     for hosts only (prefix_information_option_processing)
    TestCase_007 = neighbor_solicitation_origination_address_resolution.LinkLocalRetransmitInterval1TestCase
    TestCase_008 = neighbor_solicitation_origination_address_resolution.LinkLocalRetransmitInterval5TestCase
    TestCase_009 = neighbor_solicitation_origination_address_resolution.GlobalRetransmitInterval1TestCase
    TestCase_010 = neighbor_solicitation_origination_address_resolution.GlobalRetransmitInterval5TestCase
    TestCase_011 = neighbor_solicitation_origination_reachability_confirmation.LinkLocalToLinkLocalTestCase
    TestCase_012 = neighbor_solicitation_origination_reachability_confirmation.GlobalToGlobalTestCase
    TestCase_013 = neighbor_solicitation_origination_reachability_confirmation.LinkLocalToGlobalTestCase
    TestCase_014 = neighbor_solicitation_origination_reachability_confirmation.GlobalToLinkLocalTestCase
    TestCase_015 = invalid_neighbor_solicitation_handling.InvalidTargetAddressTestCase
    TestCase_016 = invalid_neighbor_solicitation_handling.InvalidDestinationAddressTestCase
    TestCase_017 = invalid_neighbor_solicitation_handling.InvalidSourceLinkLayerAddressOptionTestCase
    TestCase_018 = invalid_neighbor_solicitation_handling.InvalidHopLimitTestCase
    TestCase_019 = invalid_neighbor_solicitation_handling.InvalidChecksumTestCase
    TestCase_020 = invalid_neighbor_solicitation_handling.InvalidICMPCodeTestCase
    TestCase_021 = invalid_neighbor_solicitation_handling.InvalidICMPLengthTestCase
    TestCase_022 = invalid_neighbor_solicitation_handling.OptionOfLengthZeroTestCase
    #TestCase_023-025 neighbor_solicitation_processing_no_nce
    #TestCase_026-028 neighbor_solicitation_processing_nce_state_incomplete
    #TestCase_029-031 neighbor_solicitation_processing_nce_state_reachable
    #TestCase_032-035 neighbor_solicitation_processing_nce_state_stale
    #TestCase_036-039 neighbor_solicitation_processing_nce_state_probe
    #TestCase_040-042 for hosts only (neighbor_solicitation_is_router_flag)
    TestCase_043 = neighbor_solicitation_processing_anycast.AnycastTestCase
    TestCase_044 = invalid_neighbor_advertisement_handling.SolicitedFlagIsSetTestCase
    TestCase_045 = invalid_neighbor_advertisement_handling.HopLimitIs254TestCase
    TestCase_046 = invalid_neighbor_advertisement_handling.InvalidChecksumTestCase
    TestCase_047 = invalid_neighbor_advertisement_handling.InvalidICMPCodeTestCase
    TestCase_048 = invalid_neighbor_advertisement_handling.InvalidICMPLengthTestCase
    TestCase_049 = invalid_neighbor_advertisement_handling.TargetIsMulticastTestCase
    TestCase_050 = invalid_neighbor_advertisement_handling.OptionLengthIsZeroTestCase
    #TestCase_051-058 neighbor_advertisement_processing_no_nce
    #TestCase_059-063 neighbor_advertisement_processing_nce_state_incomplete
    #TestCase_064-082 neighbor_advertisement_processing_nce_state_reachable
    #TestCase_083-102 neighbor_advertisement_processing_nce_state_stale
    #TestCase_103-121 neighbor_advertisement_processing_nce_state_probe
    #TestCase_122-129 for hosts only (neighbor_advertisement_processing_rbit_change)

    #TestCase_201     for routers only (router_solicitations)
    #TestCase_202-207 for routers only (solicited_router_advertisement)
    #TestCase_208-210 for routers only (host_ignores_router_solicitations)
    TestCase_211 = router_ignores_invalid_router_solicitations.HopLimitIsNot255TestCase
    TestCase_212 = router_ignores_invalid_router_solicitations.InvalidICMPChecksumTestCase
    TestCase_213 = router_ignores_invalid_router_solicitations.InvalidICMPCodeTestCase
    TestCase_214 = router_ignores_invalid_router_solicitations.InvalidICMPLengthTestCase
    #TestCase_215 is invalid
    TestCase_216 = router_ignores_invalid_router_solicitations.UnspecifiedIPSourceAddressWithSLLTestCase
    TestCase_217 = router_sends_valid_router_advertisement.RouterAdvertisementTestCase
    #TestCase_218 = router_does_not_send_router_advertisements_on_non_advertising_interface.NoAdvertisingInterfacesTestCase
    #TestCase_219 = router_does_not_send_router_advertisements_on_non_advertising_interface.AdvertisingInterfaceTestCase
    #TestCase_220 = sending_unsolicited_router_advertisements.RAIntervalTestCase
    #TestCase_221 = sending_unsolicited_router_advertisements.InitialRAIntervalTestCase
    #TestCase_222 = sending_unsolicited_router_advertisements.MinValuesTestCase
    #TestCase_223 = sending_unsolicited_router_advertisements.MaxValuesTestCase
    #TestCase_224 = sending_unsolicited_router_advertisements.GlobalUnicastAddressPrefixTestCase
    #TestCase_225 = sending_unsolicited_router_advertisements.SiteLocalPrefixTestCase
    #TestCase_226 = ceasing_to_be_an_advertising_interface.RouterAdvertisementTestCase
    #TestCase_227 = processing_router_solicitations.MaxRADelayTimeTestCase
    #TestCase_228 = processing_router_solicitations.MinDelayBetweenRAsTestCase
    #TestCase229-237 router solicitation processing nce
    #TestCase_229     for hosts only (default_router_switch)
    #TestCase_230-235 for hosts only (router_advertisement_processing_validity)
    TestCase_236 = router_advertisement_processing_cur_hop_limit.UnspecifiedTestCase
    TestCase_237 = router_advertisement_processing_cur_hop_limit.NonZeroTestCase
    #TestCase_238-242 router_advertisement_processing_router_lifetime
    #TestCase_243-253 router_advertisement_processing_neighbor_cache
    #TestCase_254-256 for hosts only (router_advertisement_processing_isrouter_flag)
    #TestCase_257     for hosts only (next_hop_determination)
    #TestCase_258     for hosts only (router_advertisement_processing_on_link_determination)


class NeighborDiscoveryRedirectFunctionSpecification(ComplianceTestSuite):
    """
    Neighbor Discovery - Redirect Function - End Node

    The tests in this group verify conformance of the Address Resolution and
    Neighbor Unreachability Detection function with the Neighbor Discovery
    Specification.

    Tests in this group verify that a node properly processes valid, suspicious,
    and invalid Redirect messages. These tests also verify a node uses the
    appropriate first hop when redirected twice, receiving invalid options,
    having no entry in its Destination Cache, or when the new first hop is not
    reachable. These tests also verify interactions between Target Link-layer
    Address options with the Neighbor Cache.
    """

    TestCase_301 = redirected_on_link_valid.NoTLLANoRedirectTestCase
    TestCase_302 = redirected_on_link_valid.NoTLLARedirectTestCase
    TestCase_303 = redirected_on_link_valid.TLLANoRedirectTestCase
    TestCase_304 = redirected_on_link_valid.TLLARedirectTestCase
    TestCase_305 = redirected_on_link_suspicious.OptionUnrecognizedTestCase
    TestCase_306 = redirected_on_link_suspicious.ReservedFieldIsNonZeroTestCase
    #TestCase_307 is invalid
    TestCase_308 = redirected_on_link_invalid.RedirectSourceAddressIsGlobalTestCase
    TestCase_309 = redirected_on_link_invalid.RedirectSourceIsNotFirstHopRouterTestCase
    TestCase_310 = redirected_on_link_invalid.HopLimitIsNot255TestCase
    TestCase_311 = redirected_on_link_invalid.ICMPCodeIsNot0TestCase
    TestCase_312 = redirected_on_link_invalid.ICMPChecksumInvalid
    TestCase_313 = redirected_on_link_invalid.ICMPDestinationIsMulticastTestCase
    TestCase_314 = redirected_on_link_invalid.TargetAddressIsMulticastTestCase
    TestCase_315 = redirected_on_link_invalid.ICMPLengthIsLessThan40OctetsTestCase
    TestCase_316 = redirected_on_link_invalid.OptionHasZeroLengthTestCase
    TestCase_317 = redirected_to_alternate_router_valid.NoTLLANoRedirectTestCase
    TestCase_318 = redirected_to_alternate_router_valid.NoTLLARedirectTestCase
    TestCase_319 = redirected_to_alternate_router_valid.TLLANoRedirectTestCase
    TestCase_320 = redirected_to_alternate_router_valid.TLLARedirectTestCase
    TestCase_321 = redirected_to_alternate_router_suspicious.OptionUnrecognizedTestCase
    TestCase_322 = redirected_to_alternate_router_suspicious.ReservedFieldIsNonZeroTestCase
    TestCase_323 = redirected_to_alternate_router_invalid.RedirectSourceAddressIsGlobalTestCase
    TestCase_324 = redirected_to_alternate_router_invalid.RedirectSourceIsNotFirstHopRouterTestCase
    TestCase_325 = redirected_to_alternate_router_invalid.HopLimitIsNot255TestCase
    TestCase_326 = redirected_to_alternate_router_invalid.ICMPCodeIsNot0TestCase
    TestCase_327 = redirected_to_alternate_router_invalid.ICMPChecksumInvalid
    TestCase_328 = redirected_to_alternate_router_invalid.ICMPDestinationIsMulticastTestCase
    TestCase_329 = redirected_to_alternate_router_invalid.TargetAddressIsMulticastTestCase
    TestCase_330 = redirected_to_alternate_router_invalid.ICMPLengthIsLessThan40OctetsTestCase
    TestCase_331 = redirected_to_alternate_router_invalid.OptionHasZeroLengthTestCase
    TestCase_332 = redirected_twice.RedirectedTwiceTestCase
    TestCase_333 = invalid_option.PathMTUOptionTestCase
    TestCase_334 = invalid_option.PrefixInformationOptionTestCase
    TestCase_335 = invalid_option.SourceLinkLayerAddressOption
    #TestCase_336      no_destination_cache_entry
    #TestCase_337-340 neighbor_cache_updated_no_nce
    #TestCase_341-344 neighbor_cache_updated_state_incomplete
    #TestCase_345-350 neighbor_cache_updated_state_reachable
    #TestCase_351-355 neighbor_cache_updated_state_stale
    #TestCase_356-360 neighbor_cache_updated_state_probe
    TestCase_361 = invalid_redirect_does_not_update_neighbor_cache.RedirectSourceAddressIsGlobalTestCase
    TestCase_362 = invalid_redirect_does_not_update_neighbor_cache.RedirectSourceIsNotFirstHopRouterTestCase
    TestCase_363 = invalid_redirect_does_not_update_neighbor_cache.HopLimitIsNot255TestCase
    TestCase_364 = invalid_redirect_does_not_update_neighbor_cache.ICMPCodeIsNot0TestCase
    TestCase_365 = invalid_redirect_does_not_update_neighbor_cache.ICMPChecksumInvalid
    TestCase_366 = invalid_redirect_does_not_update_neighbor_cache.ICMPDestinationIsMulticastTestCase
    TestCase_367 = invalid_redirect_does_not_update_neighbor_cache.TargetAddressIsMulticastTestCase
    TestCase_368 = invalid_redirect_does_not_update_neighbor_cache.ICMPLengthIsLessThan40OctetsTestCase
    TestCase_369 = invalid_redirect_does_not_update_neighbor_cache.OptionHasZeroLengthTestCase
    #TestCase_370-374 for routers only
    #TestCase_374     for routers only


class NeighborDiscoveryRedirectFunctionIntermediateNodeSpecification(ComplianceTestSuite):
    """
    Neighbor Discovery - Redirect Function - Intermediate Node

    The tests in this group verify conformance of the Address Resolution and
    Neighbor Unreachability Detection function with the Neighbor Discovery
    Specification.

    Tests in this group verify that a node properly processes valid, suspicious,
    and invalid Redirect messages. These tests also verify a node uses the
    appropriate first hop when redirected twice, receiving invalid options,
    having no entry in its Destination Cache, or when the new first hop is not
    reachable. These tests also verify interactions between Target Link-layer
    Address options with the Neighbor Cache.
    """
    pass

    #TestCase_301-304 for hosts only (redirected_on_link_valid)
    #TestCase_305-307 for hosts only (redirected_on_link_suspicious)
    #TestCase_308-316 for hosts only (redirected_on_link_invalid)
    #TestCase_317-320 for hosts only (redirected_to_alternate_router_valid)
    #TestCase_321-322 for hosts only (redirected_to_alternate_router_suspicious)
    #TestCase_323-331 for hosts only (redirected_to_alternate_router_invalid)
    #TestCase_332     for hosts only (redirected_twice)
    #TestCase_333     for hosts only (invalid_option)
    #TestCase_336     no_destination_cache_entry
    #TestCase_337-340 neighbor_cache_updated_no_nce
    #TestCase_341-344 neighbor_cache_updated_state_incomplete
    #TestCase_345-350 neighbor_cache_updated_state_reachable
    #TestCase_351-355 neighbor_cache_updated_state_stale
    #TestCase_356-360 neighbor_cache_updated_state_probe
    #TestCase_361-369 for hosts only (invalid_redirect_does_not_update_neighbor_cache)
#    TestCase_370 = redirect_transmit.SendRedirectTestCase
#    TestCase_371 = redirect_transmit.SendRedirectToAlternateRouterTestCase
#    TestCase_372 = redirect_transmit.SourceNotNeighborTestCase
#    TestCase_373 = redirect_transmit.DestinationMulticastTestCase
#    TestCase_374 = redirect_receive.RedirectTestCase


ComplianceTestSuite.register('neighbor-discovery-end-node', NeighborDiscoverySpecification)
ComplianceTestSuite.register('neighbor-discovery-intermediate-node', NeighborDiscoveryIntermediateNodeSpecification)
ComplianceTestSuite.register('neighbor-discovery-end-node-redirect', NeighborDiscoveryRedirectFunctionSpecification)
ComplianceTestSuite.register('neighbor-discovery-intermediate-node-intermediate', NeighborDiscoveryRedirectFunctionIntermediateNodeSpecification)
