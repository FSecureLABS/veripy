from contrib.rfc3484 import source_address_selection as suite
from scapy.all import *
from veripy import util
from veripy.testability import ComplianceTestTestCase


class ChooseSameAddressTestCase(ComplianceTestTestCase):

    def setUp(self):
        super(ChooseSameAddressTestCase, self).setUp()
        
        self.ifx.ips.append("2003:800:88:200::50")

    def test_same_address_chosen_both_times(self):
        self.ifx.sends(IPv6(src=str(self.ifx.global_ip(offset=0)), dst=str(self.ifx.global_ip(offset=0)))/ICMPv6EchoRequest(), 0)
        self.ifx.sends(IPv6(src=str(self.ifx.global_ip(offset=1)), dst=str(self.ifx.global_ip(offset=1)))/ICMPv6EchoRequest(), 0)
        self.ui.inputs.append('y')
        self.ui.inputs.append('y')

        o = self.get_outcome(suite.ChooseSameAddressTestCase)

        self.assertCheckPasses(o)
    
    def test_same_address_not_chosen_first_time(self):
        self.ifx.sends(IPv6(src=str(self.ifx.global_ip(offset=1)), dst=str(self.ifx.global_ip(offset=0)))/ICMPv6EchoRequest(), 0)
        self.ui.inputs.append('y')

        o = self.get_outcome(suite.ChooseSameAddressTestCase)

        self.assertCheckFails(o)

    def test_same_address_not_chosen_second_time(self):
        self.ifx.sends(IPv6(src=str(self.ifx.global_ip(offset=0)), dst=str(self.ifx.global_ip(offset=0)))/ICMPv6EchoRequest(), 0)
        self.ifx.sends(IPv6(src=str(self.ifx.global_ip(offset=0)), dst=str(self.ifx.global_ip(offset=1)))/ICMPv6EchoRequest(), 0)
        self.ui.inputs.append('y')
        self.ui.inputs.append('y')

        o = self.get_outcome(suite.ChooseSameAddressTestCase)

        self.assertCheckFails(o)


class ChooseAppropriateScopeTestCase(ComplianceTestTestCase):

    def test_appropriate_scope_chosen_both_times(self):
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoRequest(), 0)
        self.ifx.sends(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoRequest(), 0)
        self.ui.inputs.append('y')
        self.ui.inputs.append('y')

        o = self.get_outcome(suite.ChooseAppropriateScopeTestCase)

        self.assertCheckPasses(o)

    def test_first_packet_sent_from_inappropriate_scope(self):
        self.ifx.sends(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoRequest(), 0)
        self.ifx.sends(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoRequest(), 0)
        self.ui.inputs.append('y')
        self.ui.inputs.append('y')

        o = self.get_outcome(suite.ChooseAppropriateScopeTestCase)

        self.assertCheckFails(o)

    def test_second_packet_sent_from_inappropriate_scope(self):
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoRequest(), 0)
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoRequest(), 0)
        self.ui.inputs.append('y')
        self.ui.inputs.append('y')

        o = self.get_outcome(suite.ChooseAppropriateScopeTestCase)

        self.assertCheckFails(o)


class PreferHomeAddressTestCase(ComplianceTestTestCase):

    def test_home_address_is_preferred(self):
        self.fail("TODO")

    def test_home_address_is_not_preferred(self):
        self.fail("TODO")


class PreferOutgoingInterfaceTestCase(ComplianceTestTestCase):

    def test_outgoing_interface_preferred(self):
        self.ifx.sends(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoRequest(), 0)
        self.ify.sends(IPv6(src=str(self.ify.global_ip()), dst=str(self.tn4.global_ip()))/ICMPv6EchoRequest(), 0)
        self.ui.inputs.append('y')
        self.ui.inputs.append('y')
        
        o = self.get_outcome(suite.PreferOutgoingInterfaceTestCase)

        self.assertCheckPasses(o)
    
    def test_outgoing_interface_not_preferred_first_time(self):
        self.ifx.sends(IPv6(src=str(self.ify.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoRequest(), 0)
        self.ify.sends(IPv6(src=str(self.ify.global_ip()), dst=str(self.tn4.global_ip()))/ICMPv6EchoRequest(), 0)
        self.ui.inputs.append('y')
        self.ui.inputs.append('y')

        o = self.get_outcome(suite.PreferOutgoingInterfaceTestCase)

        self.assertCheckFails(o)

    def test_outgoing_interface_not_preferred_second_time(self):
        self.ifx.sends(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoRequest(), 0)
        self.ify.sends(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn4.global_ip()))/ICMPv6EchoRequest(), 0)
        self.ui.inputs.append('y')
        self.ui.inputs.append('y')
        
        o = self.get_outcome(suite.PreferOutgoingInterfaceTestCase)

        self.assertCheckFails(o)


class PreferMatchingLabelTestCase(ComplianceTestTestCase):

    def test_matching_label_preferred(self):
        self.fail("TODO")
#		self.ui_1 = UUTInterface.get('Ethernet', ['2002::1', '2003::1', '01:02:de:ad:be:ef'])
#		self.ni_1.configure(IPCollection(['2001::1']))
#		self.ni_1.uut_iface = self.ui_1
#		p = IPv6(src='2002::1', dst='2001::1')/ICMPv6EchoRequest()
#		self.ni_1._Base__sniffer = MockSniffer([p])
#		self.ni_1.receives.append(p)
#
#		t = self.prep(source_address_selection.PreferMatchingLabelTestCase())
#		t.ui.inputs.extend(['n', '2002::1', '2003::1', 'y'])
#		o = t.run_case()
#
#		self.assertEqual(True, o.result, 'Expected test to pass, instead got: ' + repr(o.message))

    def test_matching_label_not_preferred(self):
        self.fail("TODO")
#		self.ui_1 = UUTInterface.get('Ethernet', ['2002::1', '2003::1', '01:02:de:ad:be:ef'])
#		self.ni_1.configure(IPCollection(['2001::1']))
#		self.ni_1.uut_iface = self.ui_1
#		p = IPv6(src='2003::1', dst='2001::1')/ICMPv6EchoRequest()
#		self.ni_1._Base__sniffer = MockSniffer([p])
#		self.ni_1.receives.append(p)
#
#		t = self.prep(source_address_selection.PreferMatchingLabelTestCase())
#		t.ui.inputs.extend(['n', '2002::1', '2003::1', 'y'])
#		o = t.run_case()
#
#		self.assertEqual(False, o.result, 'Expected test to fail, instead got: ' + repr(o.message))


class PreferPublicAddressTestCase(ComplianceTestTestCase):

    def test_public_address_preferred(self):
        self.fail("TODO")
#		self.ui_1 = UUTInterface.get('Ethernet', ['2001::1', '2001::d5e3:7953:13eb:22e8', '01:02:de:ad:be:ef'])
#		self.ni_1.configure(IPCollection(['2001::d5e3:0:0:1']))
#		self.ni_1.uut_iface = self.ui_1
#		p = IPv6(src='2001::1', dst='2001::d5e3:0:0:1')/ICMPv6EchoRequest()
#		self.ni_1._Base__sniffer = MockSniffer([p])
#		self.ni_1.receives.append(p)
#
#		t = self.prep(source_address_selection.PreferPublicAddressTestCase())
#		t.ui.inputs.extend(['n', 'y', '2001::1', '2001::d5e3:7953:13eb:22e8', 'y'])
#		o = t.run_case()
#
#		self.assertEqual(True, o.result, 'Expected test to pass, instead got: ' + repr(o.message))

    def test_public_address_not_preferred(self):
        self.fail("TODO")
#		self.ui_1 = UUTInterface.get('Ethernet', ['2001::1', '2001::d5e3:7953:13eb:22e8', '01:02:de:ad:be:ef'])
#		self.ni_1.configure(IPCollection(['2001::d5e3:0:0:1']))
#		self.ni_1.uut_iface = self.ui_1
#		p = IPv6(src='2001::d5e3:7953:13eb:22e8', dst='2001::d5e3:0:0:1')/ICMPv6EchoRequest()
#		self.ni_1._Base__sniffer = MockSniffer([p])
#		self.ni_1.receives.append(p)
#
#		t = self.prep(source_address_selection.PreferPublicAddressTestCase())
#		t.ui.inputs.extend(['n', 'y', '2001::1', '2001::d5e3:7953:13eb:22e8', 'y'])
#		o = t.run_case()
#
#		self.assertEqual(False, o.result, 'Expected test to fail, instead got: ' + repr(o.message))


class UseLongestMatchingPrefixTestCase(ComplianceTestTestCase):

    def test_longest_matching_prefix_used(self):
        self.fail("TODO")
#		self.ui_1 = UUTInterface.get('Ethernet', ['2001::2', '3ffe::2', '01:02:de:ad:be:ef'])
#		self.ni_1.configure(IPCollection(['2001::1']))
#		self.ni_1.uut_iface = self.ui_1
#		p = IPv6(src='2001::2', dst='2001::1')/ICMPv6EchoRequest()
#		self.ni_1._Base__sniffer = MockSniffer([p])
#		self.ni_1.receives.append(p)
#
#		t = self.prep(source_address_selection.UseLongestMatchingPrefixTestCase())
#		t.ui.inputs.extend(['n', 'y'])
#		o = t.run_case()
#
#		self.assertEqual(True, o.result, 'Expected test to pass, instead got: ' + repr(o.message))

    def test_longest_matching_prefix_not_used(self):
        self.fail("TODO")
#		self.ui_1 = UUTInterface.get('Ethernet', ['2001::2', '3ffe::2', '01:02:de:ad:be:ef'])
#		self.ni_1.configure(IPCollection(['2001::1']))
#		self.ni_1.uut_iface = self.ui_1
#		p = IPv6(src='3ffe::2', dst='2001::1')/ICMPv6EchoRequest()
#		self.ni_1._Base__sniffer = MockSniffer([p])
#		self.ni_1.receives.append(p)
#
#		t = self.prep(source_address_selection.UseLongestMatchingPrefixTestCase())
#		t.ui.inputs.extend(['n', 'y'])
#		o = t.run_case()
#
#		self.assertEqual(False, o.result, 'Expected test to fail, instead got: ' + repr(o.message))


class SourceAddressMustBeIPv4MappedOnSIITNodeTestCase(ComplianceTestTestCase):

    def setUp(self):
        super(SourceAddressMustBeIPv4MappedOnSIITNodeTestCase, self).setUp()

        self.ifx.ips.append("::ffff:a00:1")
        self.tn1.iface(0).ips.append("::ffff:a00:2")

    def test_source_includes_ipv4_mapped_for_ipv4_mapped_destination_nodes(self):
        self.ifx.sends(IPv6(src=str(self.ifx.ip(type='v4mapped')), dst=str(self.tn1.ip(type='v4mapped')))/ICMPv6EchoRequest(), 0)
        self.ui.inputs.append('y')
        
        o = self.get_outcome(suite.SourceAddressMustBeIPv4MappedOnSIITNodeTestCase)

        self.assertCheckPasses(o)

    def test_source_does_not_include_ipv4_mapped_for_ipv4_mapped_destination_nodes(self):
        self.ifx.sends(IPv6(src=str(self.ifx.ip(type='v6')), dst=str(self.tn1.ip(type='v4mapped')))/ICMPv6EchoRequest(), 0)
        self.ui.inputs.append('y')

        o = self.get_outcome(suite.SourceAddressMustBeIPv4MappedOnSIITNodeTestCase)

        self.assertCheckFails(o)


class SourceAddressMustNotBeIPv4MappedOnSIITNodeTestCase(ComplianceTestTestCase):

    def setUp(self):
        super(SourceAddressMustNotBeIPv4MappedOnSIITNodeTestCase, self).setUp()

        self.ifx.ips.append("::ffff:a00:1")
        self.tn1.iface(0).ips.append("::ffff:a00:2")

    def test_source_does_not_include_ipv4_mapped_for_non_ipv4_mapped_destination_nodes(self):
        self.ifx.sends(IPv6(src=str(self.ifx.ip(type='v6')), dst=str(self.tn1.ip(type='v6')))/ICMPv6EchoRequest(), 0)
        self.ui.inputs.append('y')

        o = self.get_outcome(suite.SourceAddressMustNotBeIPv4MappedOnSIITNodeTestCase)

        self.assertCheckPasses(o)

    def test_source_includes_ipv4_mapped_for_non_ipv4_mapped_destination_nodes(self):
        self.ifx.sends(IPv6(src=str(self.ifx.ip(type='v4mapped')), dst=str(self.tn1.ip(type='v6')))/ICMPv6EchoRequest(), 0)
        self.ui.inputs.append('y')

        o = self.get_outcome(suite.SourceAddressMustNotBeIPv4MappedOnSIITNodeTestCase)

        self.assertCheckFails(o)
        