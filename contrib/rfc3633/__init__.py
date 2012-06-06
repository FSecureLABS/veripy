from veripy.models import ComplianceTestSuite
from veripy.models.decorators import must, should

import dr
import rr

class DHCPv6PrefixDelegationDR(ComplianceTestSuite):
    """
    IPv6 Prefix Options for Dynamic Host Configuration Protocol - Delegating
    Router

    Tests in this group cover basic interoperability of the IPv6 Prefix Options
    for Dynamic Host Configuration Protocol for IPv6 (DHCPv6-PD), Request for
    Comments 3633.

    These tests are designed to verify the readiness of DHCPv6 Requesting
    Router (Client) and Delegating Router (Server) interoperability vis-a-vis
    the specifications of the DHCPv6-PD protocol.
    """

    TestCase_001 = dr.basic_message_exchange.BasicMessageExchangeTestCase
    TestCase_002 = dr.renew_message.RenewMessageTestCase
    TestCase_003 = dr.rebind_message.RebindMessageTestCase
    TestCase_004 = dr.release_message.ReleaseMessageTestCase
    TestCase_005 = dr.advertise_message_status.NoPrefixAvailTestCase


class DHCPv6PrefixDelegationRR(ComplianceTestSuite):
    """
    IPv6 Prefix Options for Dynamic Host Configuration Protocol - Requesting
    Router

    Tests in this group cover basic interoperability of the IPv6 Prefix Options
    for Dynamic Host Configuration Protocol for IPv6 (DHCPv6-PD), Request for
    Comments 3633.

    These tests are designed to verify the readiness of DHCPv6 Requesting
    Router (Client) and Delegating Router (Server) interoperability vis-a-vis
    the specifications of the DHCPv6-PD protocol.
    """

    TestCase_001 = rr.basic_message_exchange.BasicMessageExchangeTestCase
    TestCase_002 = rr.renew_message.RenewMessageTestCase
    TestCase_003 = rr.rebind_message.RebindMessageTestCase
    TestCase_004 = rr.release_message.ReleaseMessageTestCase
    TestCase_005 = rr.advertise_message_status.NoPrefixAvailTestCase


ComplianceTestSuite.register('dhcpv6-pd-dr', DHCPv6PrefixDelegationDR)
ComplianceTestSuite.register('dhcpv6-pd-rr', DHCPv6PrefixDelegationRR)
