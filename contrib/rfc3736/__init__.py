from veripy.models import ComplianceTestSuite
from veripy.models.decorators import must, should

import client
#import relay_agent
import server

class StatelessDHCPv6ServiceClientSpecification(ComplianceTestSuite):
    """
    Stateless Dynamic Host Configuration Protocol Service for IPv6 (DHCPv6 Client)

    These tests are designed to verify the readiness of a DHCPv6 client implementation 
    vis-a-vis the Stateless Dynamic Host Configuration Protocol for IPv6 specification.

    @private
    Author:         MWR
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 7)
    """

    TestCase001 = client.basic_message_exchanges.BasicMessageExchangeTestCase
    TestCase002 = client.implementation_of_dhcp_constants.MulticastAddressesTestCase
    TestCase003 = client.implementation_of_dhcp_constants.ValidUDPPortTestCase
    TestCase004 = client.implementation_of_dhcp_constants.InvalidUDPPortTestCase
    TestCase005 = client.client_message_format.ClientMessageFormatTestCase
    TestCase006 = client.option_request_option_format.DNSRecursiveNameServerOptionTestCase
    TestCase007 = client.option_request_option_format.DomainSearchListOptionTestCase
    TestCase008 = client.transmission_of_information_request_messages.ReliabilityOfDHCPv6RetransmissionTestCase
    TestCase011 = client.reception_of_reply_messages_for_dns_configuration_options.DNSRecursiveNameServerOptionTestCase
    TestCase012 = client.reception_of_reply_messages_for_dns_configuration_options.DomainSearchListOptionTestCase
    TestCase013 = client.reception_of_invalid_reply_message.NoServerIdentifierOptionTestCase
    TestCase014 = client.reception_of_invalid_reply_message.TransactionIDMismatchTestCase
    #TestCase015 = client.client_message_validation.SolicitMessageTestCase
    #TestCase016 = client.client_message_validation.RequestMessageTestCase
    #TestCase017 = client.client_message_validation.ConfirmMessageTestCase
    #TestCase018 = client.client_message_validation.RenewMessageTestCase
    #TestCase019 = client.client_message_validation.RebindMessageTestCase
    #TestCase020 = client.client_message_validation.DeclineMessageTestCase
    #TestCase021 = client.client_message_validation.ReleaseMessageTestCase
    #TestCase022 = client.client_message_validation.InformationRequestMessageTestCase
    #TestCase023 = client.client_message_validation.RelayForwardMessageTestCase
    #TestCase024 = client.client_message_validation.RelayReplyMessageTestCase
    TestCase025 = client.client_dhcp_unique_identifier.DUIDFormatTestCase


class StatelessDHCPv6ServiceServerSpecification(ComplianceTestSuite):
    """
    Stateless Dynamic Host Configuration Protocol Service for IPv6 (DHCPv6 Server)

    These tests are designed to verify the readiness of a DHCPv6 server implementation 
    vis-a-vis the Stateless Dynamic Host Configuration Protocol for IPv6 specification.

    @private
    Author:         MWR
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 8)
    """

    TestCase001 = server.basic_message_exchanges.BasicMessageExchangeTestCase
    TestCase002 = server.transaction_id_consistency.TransactionIDConsistencyTestCase
    TestCase003 = server.implementation_of_dhcp_constants.ValidUDPPortTestCase
    TestCase004 = server.implementation_of_dhcp_constants.InvalidUDPPortTestCase
    TestCase005 = server.server_message_format.ClientServerMessageFormatTestCase
    TestCase006 = server.server_message_format.RelayAgentServerMessageFormatTestCase
    TestCase007 = server.server_identifier_option_format.ServerIdentifierOptionFormatTestCase
    TestCase008 = server.dhcp_unique_identifier_contents.DHCPUniqueIdentifierContentsTestCase
    TestCase009 = server.dns_recursive_name_server_option_format.DNSRecursiveNameServerOptionFormatTestCase
    TestCase010 = server.domain_search_list_option_format.DomainSearchListOptionFormatTestCase
    TestCase011 = server.interface_id_option_format.InterfaceIDOptionFormatTestCase
    TestCase012 = server.relay_message_option_format.RelayMessageOptionFormatTestCase
    TestCase013 = should(server.configuration_of_dns_options.ReturningDNSRecursiveNameServerOptionTestCase)
    TestCase014 = server.configuration_of_dns_options.ReturningDNSServerandDomainSearchListOptionsTestCase
    TestCase015 = should(server.creation_and_transmission_of_reply_messages.ReplyMessageTransmissionTestCase)
    TestCase016 = server.creation_and_transmission_of_reply_messages.ReplyMessageTransmissionWithDNSRNSOptionTestCase
    TestCase017 = server.creation_and_transmission_of_reply_messages.ReplyMessageTransmissionWithDomainSearchListOptionTestCase
    TestCase018 = server.creation_and_transmission_of_reply_messages.RelayReplyMessageWithoutInterfaceIDTestCase
    TestCase019 = server.creation_and_transmission_of_reply_messages.RelayReplyMessageWithInterfaceIDTestCase
    TestCase020 = server.creation_and_transmission_of_relay_reply_messages.RelayReplyMessageTransmissionTestCase
    TestCase021 = server.creation_and_transmission_of_relay_reply_messages.MultipleRelayReplyMessageTransmissionTestCase
    TestCase022 = server.creation_and_transmission_of_relay_reply_messages.EncapsulatedRelayReplyMessageTransmissionTestCase
    TestCase023 = server.reception_of_invalid_information_request_message.ReceptionOfInformationRequestMessageViaUnicastTestCase
    TestCase024 = server.reception_of_invalid_information_request_message.ContainsServerIdentifierOptionTestCase
    TestCase025 = server.reception_of_invalid_information_request_message.ContainsIANAOptionTestCase
    TestCase026 = server.server_message_validation.AdvertiseMessageTestCase
    TestCase027 = server.server_message_validation.ReplyMessageTestCase
    TestCase028 = server.server_message_validation.RelayReplyMessageTestCase

ComplianceTestSuite.register('stateless-dhcpv6-client', StatelessDHCPv6ServiceClientSpecification)
#ComplianceTestSuite.register('dhcpv6-relay-agent', StatelessDHCPv6ServiceRelayAgentSpecification)
ComplianceTestSuite.register('stateless-dhcpv6-server', StatelessDHCPv6ServiceServerSpecification)
