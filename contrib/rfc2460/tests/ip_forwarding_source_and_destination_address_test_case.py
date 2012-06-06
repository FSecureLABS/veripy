from contrib.rfc2460 import ip_forwarding_source_and_destination_address as suite
from scapy.all import *
from veripy.models import IPAddressCollection
from veripy.testability import ComplianceTestTestCase


class RequestSentToGlobalUnicastTestCase(ComplianceTestTestCase):

    def test_payload_is_delivered(self):
        self.ify.replies_with(IPv6(src=str(self.tn4.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoRequest(), to=self.ifx)

        o = self.get_outcome(suite.RequestSentToGlobalUnicastTestCase)

        self.assertCheckPasses(o)

    def test_payload_is_not_delivered(self):
        o = self.get_outcome(suite.RequestSentToGlobalUnicastTestCase)

        self.assertCheckFails(o)


class RequestSentToGlobalUnicastPrefixEndsInZeroValueFieldsTestCase(ComplianceTestTestCase):

    def test_payload_is_delivered(self):
        self.fail("TODO")

    def test_payload_is_not_delivered(self):
        self.fail("TODO")


class RequestSentFromUnspecifiedAddressTestCase(ComplianceTestTestCase):

    def test_payload_is_delivered(self):
        self.ify.replies_with(IPv6(src='::', dst=str(self.tn1.global_ip()))/ICMPv6EchoRequest(), to=self.ifx)

        o = self.get_outcome(suite.RequestSentFromUnspecifiedAddressTestCase)

        self.assertCheckFails(o)

    def test_payload_is_not_delivered(self):
        o = self.get_outcome(suite.RequestSentFromUnspecifiedAddressTestCase)

        self.assertCheckPasses(o)


class RequestSentToLoopbackAddressTestCase(ComplianceTestTestCase):

    def test_payload_is_delivered(self):
        self.ify.replies_with(IPv6(src=str(self.tn4.global_ip()), dst='::1')/ICMPv6EchoRequest(), to=self.ifx)

        o = self.get_outcome(suite.RequestSentToLoopbackAddressTestCase)

        self.assertCheckFails(o)
    
    def test_payload_is_not_delivered(self):
        o = self.get_outcome(suite.RequestSentToLoopbackAddressTestCase)

        self.assertCheckPasses(o)


class RequestSentFromLinkLocalAddressTestCase(ComplianceTestTestCase):

    def test_payload_is_delivered(self):
        self.ify.replies_with(IPv6(src=str(self.tn4.link_local_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoRequest(), to=self.ifx)

        o = self.get_outcome(suite.RequestSentFromLinkLocalAddressTestCase)

        self.assertCheckFails(o)

    def test_payload_is_not_delivered(self):
        o = self.get_outcome(suite.RequestSentFromLinkLocalAddressTestCase)

        self.assertCheckPasses(o)


class RequestSentToLinkLocalAddressTestCase(ComplianceTestTestCase):

    def test_payload_is_delivered(self):
        self.ify.replies_with(IPv6(src=str(self.tn4.global_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoRequest(), to=self.ifx)
        
        o = self.get_outcome(suite.RequestSentToLinkLocalAddressTestCase)

        self.assertCheckFails(o)

    def test_payload_is_not_delivered(self):
        o = self.get_outcome(suite.RequestSentToLinkLocalAddressTestCase)

        self.assertCheckPasses(o)


class RequestSentFromGlobalAddressToSiteLocalAddressTestCase(ComplianceTestTestCase):

    def test_payload_is_delivered(self):
        self.ify.replies_with(IPv6(src=str(self.tn4.global_ip()), dst=str(self.tn1.ip(scope=IPAddressCollection.SITELOCAL)))/ICMPv6EchoRequest(), to=self.ifx)

        o = self.get_outcome(suite.RequestSentToSiteLocalAddressTestCase)

        self.assertCheckPasses(o)

    def test_payload_is_not_delivered(self):
        o = self.get_outcome(suite.RequestSentToSiteLocalAddressTestCase)

        self.assertCheckFails(o)


class RequestSentToGlobalScopeMulticastAddressTestCase(ComplianceTestTestCase):

    def test_payload_is_delivered(self):
        self.ify.replies_with(IPv6(src=str(self.tn4.global_ip()), dst='ff1e::1:2')/ICMPv6EchoRequest(), to=self.ifx)
        self.ui.inputs.append('y')

        o = self.get_outcome(suite.RequestSentToGlobalScopeMulticastAddressTestCase)

        self.assertCheckPasses(o)

    def test_payload_is_not_delivered(self):
        self.ui.inputs.append('y')

        o = self.get_outcome(suite.RequestSentToGlobalScopeMulticastAddressTestCase)

        self.assertCheckFails(o)

    def test_not_supported_but_payload_is_delivered(self):
        self.ify.replies_with(IPv6(src=str(self.tn4.global_ip()), dst='ff1e::1:2')/ICMPv6EchoRequest(), to=self.ifx)
        self.ui.inputs.append('n')

        o = self.get_outcome(suite.RequestSentToGlobalScopeMulticastAddressTestCase)

        self.assertCheckPasses(o)

    def test_not_supported_and_payload_is_not_delivered(self):
        self.ui.inputs.append('n')

        o = self.get_outcome(suite.RequestSentToGlobalScopeMulticastAddressTestCase)

        self.assertCheckPasses(o)


class RequestSentToLinkLocalScopeMulticastAddressTestCase(ComplianceTestTestCase):

    def test_payload_is_delivered(self):
        self.ify.replies_with(IPv6(src=str(self.tn4.global_ip()), dst='ff12::1:2')/ICMPv6EchoRequest(), to=self.ifx)
        self.ui.inputs.append('y')

        o = self.get_outcome(suite.RequestSentToLinkLocalScopeMulticastAddressTestCase)

        self.assertCheckFails(o)

    def test_payload_is_not_delivered(self):
        self.ui.inputs.append('y')

        o = self.get_outcome(suite.RequestSentToLinkLocalScopeMulticastAddressTestCase)

        self.assertCheckPasses(o)

    def test_not_supported_but_payload_is_delivered(self):
        self.ify.replies_with(IPv6(src=str(self.tn4.global_ip()), dst='ff12::1:2')/ICMPv6EchoRequest(), to=self.ifx)
        self.ui.inputs.append('n')

        o = self.get_outcome(suite.RequestSentToLinkLocalScopeMulticastAddressTestCase)

        self.assertCheckPasses(o)

    def test_not_supported_and_payload_is_not_delivered(self):
        self.ui.inputs.append('n')

        o = self.get_outcome(suite.RequestSentToLinkLocalScopeMulticastAddressTestCase)

        self.assertCheckPasses(o)


class RequestSentToMulticastAddressReservedValue0TestCase(ComplianceTestTestCase):

    def test_payload_is_delivered(self):
        self.ify.replies_with(IPv6(src=str(self.tn4.global_ip()), dst='ff10::1:2')/ICMPv6EchoRequest(), to=self.ifx)
        self.ui.inputs.append('y')

        o = self.get_outcome(suite.RequestSentToMulticastAddressReservedValue0TestCase)

        self.assertCheckFails(o)

    def test_payload_is_not_delivered(self):
        self.ui.inputs.append('y')

        o = self.get_outcome(suite.RequestSentToMulticastAddressReservedValue0TestCase)

        self.assertCheckPasses(o)

    def test_not_supported_but_payload_is_delivered(self):
        self.ify.replies_with(IPv6(src=str(self.tn4.global_ip()), dst='ff10::1:2')/ICMPv6EchoRequest(), to=self.ifx)
        self.ui.inputs.append('n')

        o = self.get_outcome(suite.RequestSentToMulticastAddressReservedValue0TestCase)

        self.assertCheckPasses(o)

    def test_not_supported_and_payload_is_not_delivered(self):
        self.ui.inputs.append('n')

        o = self.get_outcome(suite.RequestSentToMulticastAddressReservedValue0TestCase)

        self.assertCheckPasses(o)


class RequestSentToMulticastAddressReservedValueFTestCase(ComplianceTestTestCase):

    def test_payload_is_delivered(self):
        self.ify.replies_with(IPv6(src=str(self.tn4.global_ip()), dst='ff1f::1:2')/ICMPv6EchoRequest(), to=self.ifx)
        self.ui.inputs.append('y')

        o = self.get_outcome(suite.RequestSentToMulticastAddressReservedValueFTestCase)

        self.assertCheckFails(o)

    def test_payload_is_not_delivered(self):
        self.ui.inputs.append('y')

        o = self.get_outcome(suite.RequestSentToMulticastAddressReservedValueFTestCase)

        self.assertCheckPasses(o)

    def test_not_supported_but_payload_is_delivered(self):
        self.ify.replies_with(IPv6(src=str(self.tn4.global_ip()), dst='ff1f::1:2')/ICMPv6EchoRequest(), to=self.ifx)
        self.ui.inputs.append('n')

        o = self.get_outcome(suite.RequestSentToMulticastAddressReservedValueFTestCase)

        self.assertCheckPasses(o)

    def test_not_supported_and_payload_is_not_delivered(self):
        self.ui.inputs.append('n')

        o = self.get_outcome(suite.RequestSentToMulticastAddressReservedValueFTestCase)

        self.assertCheckPasses(o)
