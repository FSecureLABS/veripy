from veripy.models import ComplianceTestSuite
from veripy.models.decorators import must, should

import source_address_selection

class DefaultAddressSelectionEndNode(ComplianceTestSuite):
    """
    Default Address Selection - End Node

    The following tests cover Default Address Selection for Internet Protocol
    version 6 (IPv6) for both source and destination addresses, as described
    in RC3484.
    
    The algorithms described must be implemented by all IPv6 nodes, but do
    not override choices made by applications or upper-layer protocols.

    @private
    Author:         MWR
    Source:         RFC3484
    """

    TestCase_001 = source_address_selection.ChooseSameAddressTestCase
    TestCase_002 = source_address_selection.ChooseAppropriateScopeTestCase
    TestCase_003 = source_address_selection.PreferHomeAddressTestCase
    # TestCase_004 for routers only (source_address_selection.PreferOutgoingInterfaceTestCase)
    # TestCase_005 = source_address_selection.PreferMatchingLabelTestCase
    # TestCase_006 = source_address_selection.PreferPublicAddressTestCase
    # TestCase_007 = source_address_selection.UseLongestMatchingPrefixTestCase
    TestCase_008 = source_address_selection.SourceAddressMustBeIPv4MappedOnSIITNodeTestCase
    TestCase_009 = source_address_selection.SourceAddressMustNotBeIPv4MappedOnSIITNodeTestCase

class DefaultAddressSelectionIntermediateNode(ComplianceTestSuite):
    """
    Default Address Selection - End Node

    The following tests cover Default Address Selection for Internet Protocol
    version 6 (IPv6) for both source and destination addresses, as described
    in RC3484.

    The algorithms described must be implemented by all IPv6 nodes, but do
    not override choices made by applications or upper-layer protocols.

    @private
    Author:         MWR
    Source:         RFC3484
    """

    TestCase_001 = source_address_selection.ChooseSameAddressTestCase
    TestCase_002 = source_address_selection.ChooseAppropriateScopeTestCase
    TestCase_003 = source_address_selection.PreferHomeAddressTestCase
    TestCase_004 = source_address_selection.PreferOutgoingInterfaceTestCase
    # TestCase_005 = source_address_selection.PreferMatchingLabelTestCase
    # TestCase_006 = source_address_selection.PreferPublicAddressTestCase
    # TestCase_007 = source_address_selection.UseLongestMatchingPrefixTestCase
    TestCase_008 = source_address_selection.SourceAddressMustBeIPv4MappedOnSIITNodeTestCase
    TestCase_009 = source_address_selection.SourceAddressMustNotBeIPv4MappedOnSIITNodeTestCase

ComplianceTestSuite.register('default-address-selection-end-node', DefaultAddressSelectionEndNode)
ComplianceTestSuite.register('default-address-selection-intermediate-node', DefaultAddressSelectionIntermediateNode)
