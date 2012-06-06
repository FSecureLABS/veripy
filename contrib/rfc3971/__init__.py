from veripy.models import ComplianceTestSuite

import receiving_send
import sending_cga_option_send
import sending_nonce_option_send
import sending_timestamp_option_send
import sending_rsa_option_send

class SecureNeighborDiscoveryEndNode(ComplianceTestSuite):
    """
    SEcure Neighbor Discovery

    IPv6 nodes use the Neighbor Discovery Protocol (NDP) to discover other
    nodes on the link, to determine their link-layer addresses to find routers,
    and to maintain reachability information about the paths to active
    neighbors. If not secured, NDP is vulnerable to various attacks.

    These tests cover SEcure Neighbor Discovery, a security mechanisms for
    NDP which does not use IPsec.

    @private
    Source:         RFC3971
    Author:         MWR
    """

    TestCase_001 = sending_cga_option_send.UUTSendsNSFromLinkLocalWithCGAOptionTestCase
    TestCase_002 = sending_cga_option_send.UUTSendsNSFromUnspecifiedWithCGAOptionTestCase
    TestCase_003 = sending_cga_option_send.UUTSendsNAFromLinkLocalWithCGAOptionTestCase
    TestCase_004 = sending_cga_option_send.UUTSendsRSFromLinkLocalWithCGAOptionTestCase
    TestCase_005 = sending_nonce_option_send.UUTSendsNSFromLinkLocalWithNonceTestCase
    TestCase_006 = sending_nonce_option_send.UUTSendsNSFromUnspecifiedWithNonceTestCase
    TestCase_007 = sending_nonce_option_send.UUTSendsNAFromLinkLocalWithNonceOptionTestCase
    TestCase_008 = sending_nonce_option_send.UUTSendsRSFromLinkLocalWithNonceOptionTestCase
    TestCase_009 = sending_rsa_option_send.UUTSendsNSFromLinkLocalWithRSAOptionTestCase
    TestCase_010 = sending_rsa_option_send.UUTSendsNSFromUnspecifiedWithRSAOptionTestCase
    TestCase_011 = sending_rsa_option_send.UUTSendsNAFromLinkLocalWithRSAOptionTestCase
    TestCase_012 = sending_rsa_option_send.UUTSendsRSFromLinkLocalWithRSAOptionTestCase
    TestCase_013 = sending_timestamp_option_send.UUTSendsNSFromLinkLocalWithTimeStampTestCase
    TestCase_014 = sending_timestamp_option_send.UUTSendsNSFromUnspecifiedWithTimeStampTestCase
    TestCase_015 = sending_timestamp_option_send.UUTSendsNAFromLinkLocalWithTimeStampOptionTestCase
    TestCase_016 = sending_timestamp_option_send.UUTSendsRSFromLinkLocalWithTimeStampTestCase
    TestCase_017 = receiving_send.UUTProcessValidSendTestCase
    TestCase_018 = receiving_send.UUTProcessValidSendReservedFieldSetTestCase
    TestCase_019 = receiving_send.UUTReceivesNoCGAOptionTestCase
    TestCase_020 = receiving_send.UUTReceivesDifferentKeyTestCase
    TestCase_021 = receiving_send.UUTReceivesNoRSAOptionTestCase
    TestCase_022 = receiving_send.UUTReceivesNoNonceOptionTestCase
    TestCase_023 = receiving_send.UUTReceivesNoTimeStampOptionTestCase
    TestCase_024 = receiving_send.UUTReceivesRSAOptionNotLastTestCase


class SecureNeighborDiscoveryIntermediateNode(ComplianceTestSuite):
    """
    SEcure Neighbor Discovery

    IPv6 nodes use the Neighbor Discovery Protocol (NDP) to discover other
    nodes on the link, to determine their link-layer addresses to find routers,
    and to maintain reachability information about the paths to active
    neighbors. If not secured, NDP is vulnerable to various attacks.

    These tests cover SEcure Neighbor Discovery, a security mechanisms for
    NDP which does not use IPsec.

    @private
    Source:         RFC3971
    Author:         MWR
    """
    
    TestCase_001 = sending_cga_option_send.UUTSendsNSFromLinkLocalWithCGAOptionTestCase
    TestCase_002 = sending_cga_option_send.UUTSendsNSFromUnspecifiedWithCGAOptionTestCase
    TestCase_003 = sending_cga_option_send.UUTSendsNAFromLinkLocalWithCGAOptionTestCase
    TestCase_004 = sending_nonce_option_send.UUTSendsNSFromLinkLocalWithNonceTestCase
    TestCase_005 = sending_nonce_option_send.UUTSendsNSFromUnspecifiedWithNonceTestCase
    TestCase_006 = sending_nonce_option_send.UUTSendsNAFromLinkLocalWithNonceOptionTestCase
    TestCase_007 = sending_nonce_option_send.UUTSendsRAFromLinkLocalWithNonceOptionTestCase
    TestCase_008 = sending_rsa_option_send.UUTSendsNSFromLinkLocalWithRSAOptionTestCase
    TestCase_009 = sending_rsa_option_send.UUTSendsNSFromUnspecifiedWithRSAOptionTestCase
    TestCase_010 = sending_rsa_option_send.UUTSendsNAFromLinkLocalWithRSAOptionTestCase
    TestCase_011 = sending_rsa_option_send.UUTSendsRAFromLinkLocalWithRSAOptionTestCase
    TestCase_012 = sending_timestamp_option_send.UUTSendsNSFromLinkLocalWithTimeStampTestCase
    TestCase_013 = sending_timestamp_option_send.UUTSendsNSFromUnspecifiedWithTimeStampTestCase
    TestCase_014 = sending_timestamp_option_send.UUTSendsNAFromLinkLocalWithTimeStampOptionTestCase
    TestCase_015 = sending_timestamp_option_send.UUTSendsRAFromLinkLocalWithTimeStampOptionTestCase
    TestCase_016 = receiving_send.UUTProcessValidSendTestCase
    TestCase_017 = receiving_send.UUTProcessValidSendReservedFieldSetTestCase
    TestCase_018 = receiving_send.UUTReceivesNoCGAOptionTestCase
    TestCase_019 = receiving_send.UUTReceivesDifferentKeyTestCase
    TestCase_020 = receiving_send.UUTReceivesNoRSAOptionTestCase
    TestCase_021 = receiving_send.UUTReceivesNoNonceOptionTestCase
    TestCase_022 = receiving_send.UUTReceivesNoTimeStampOptionTestCase
    TestCase_023 = receiving_send.UUTReceivesRSAOptionNotLastTestCase


ComplianceTestSuite.register('secure-neighbor-discovery-end-node', SecureNeighborDiscoveryEndNode)
ComplianceTestSuite.register('secure-neighbor-discovery-intermediate-node', SecureNeighborDiscoveryIntermediateNode)
