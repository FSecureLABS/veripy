from veripy.models import ComplianceTestSuite
from veripy.models.decorators import must, should

import client
#import relay_agent
import server

class DHCPv6ClientSpecification(ComplianceTestSuite):
    """
    Dynamic Host Configuration Protocol for IPv6 (DHCPv6 Client)

    These tests are designed to verify the readiness of DHCPv6 client
    interoperability vis-a-vis the base specifications of the Dynamic Host
    Configuration Protocol for IPv6.

    @private
    Author:         MWR
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Group 1)
    """
    
    TestCase_001 = client.dhcpv6_initialization.DHCPv6InitializationTestCase
    TestCase_002 = client.transmission_of_confirm_messages.TransmissionOfConfirmMessagesTestCase
    TestCase_003 = client.transmission_of_renew_messages.TransmissionOfRenewMessagesTestCase
    TestCase_004 = client.transmission_of_rebind_messages.TransmissionOfRebindMessagesTestCase
    TestCase_005 = client.transmission_of_release_messages.TransmissionOfReleaseMessagesTestCase
    TestCase_006 = client.transmission_of_decline_messages.TransmissionOfDeclineMessagesTestCase
    TestCase_007 = client.transmission_of_no_addrs_available.TransmissionOfAdvertisementWithNoAddrsAvailableTestCase
    TestCase_008 = client.transmission_of_not_on_link.TransmissionOfNotOnLinkTestCase


class DHCPv6ServerSpecification(ComplianceTestSuite):
    """
    Dynamic Host Configuration Protocol for IPv6 (DHCPv6 Server)

    These tests are designed to verify the readiness of DHCPv6 server
    interoperability vis-a-vis the base specifications of the Dynamic Host
    Configuration Protocol for IPv6.

    @private
    Author:         MWR
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Group 1)
    """

    TestCase_001 = server.dhcpv6_initialization.DHCPv6InitializationTestCase
    TestCase_002 = server.receipt_of_confirm_messages.ReceiptOfConfirmMessagesTestCase
    TestCase_003 = server.receipt_of_renew_messages.ReceiptOfRenewMessagesTestCase
    TestCase_004 = server.receipt_of_rebind_messages.ReceiptOfRebindMessagesTestCase
    TestCase_005 = server.receipt_of_release_messages.ReceiptOfReleaseMessagesTestCase
    TestCase_006 = server.receipt_of_decline_messages.ReceiptOfDeclineMessagesTestCase
    TestCase_007 = server.advertise_message_with_no_addrs_avail.AdvertiseMessagesWithNoAddrsAvailTestCase
    TestCase_008 = server.reply_message_with_not_on_link.ReplyMessagesWithNotOnLinkTestCase


ComplianceTestSuite.register('dhcpv6-client', DHCPv6ClientSpecification)
#ComplianceTestSuite.register('dhcpv6-relay-agent', DHCPv6RelayAgentSpecification)
ComplianceTestSuite.register('dhcpv6-server', DHCPv6ServerSpecification)
