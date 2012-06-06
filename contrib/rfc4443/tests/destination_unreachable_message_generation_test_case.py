from contrib.rfc4443 import destination_unreachable_message_generation as suite
from scapy.all import *
from veripy.testability import ComplianceTestTestCase


class RouteUnreachableTestCase(ComplianceTestTestCase):

    def test_route_unreachable_valid(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6DestUnreach(code=0))
        self.ui.inputs.append('y')

        o = self.get_outcome(suite.RouteUnreachableTestCase)

        self.assertCheckPasses(o)


    def test_route_unreachable_invalid_user_input(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6DestUnreach(code=0))
        self.ui.inputs.append('n')

        o = self.get_outcome(suite.RouteUnreachableTestCase)

        self.assertCheckFails(o)

    def test_route_unreachable_no_reply(self):
        self.ui.inputs.append('y')

        o = self.get_outcome(suite.RouteUnreachableTestCase)

        self.assertCheckFails(o)

    def test_route_unreachable_invalid_src(self):
        self.ifx.replies_with(IPv6(src="::", dst=str(self.tn1.global_ip()))/ICMPv6DestUnreach(code=0))
        self.ui.inputs.append('y')

        o = self.get_outcome(suite.RouteUnreachableTestCase)

        self.assertCheckFails(o)

    def test_route_unreachable_invalid_dst(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst="::")/ICMPv6DestUnreach(code=0))
        self.ui.inputs.append('y')

        o = self.get_outcome(suite.RouteUnreachableTestCase)

        self.assertCheckFails(o)

    def test_route_unreachable_invalid_layer(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip())))
        self.ui.inputs.append('y')

        o = self.get_outcome(suite.RouteUnreachableTestCase)

        self.assertCheckFails(o)

    def test_route_unreachable_invalid_code(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6DestUnreach(code=1))
        self.ui.inputs.append('y')

        o = self.get_outcome(suite.RouteUnreachableTestCase)

        self.assertCheckFails(o)

    def test_route_unreachable_invalid_mtu(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6DestUnreach(code=0)/Raw(load='A'*1300))
        self.ui.inputs.append('y')

        o = self.get_outcome(suite.RouteUnreachableTestCase)

        self.assertCheckFails(o)


class AddressUnreachableTestCase(ComplianceTestTestCase):

    def test_address_unreachable_valid(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6DestUnreach(code=3))

        o = self.get_outcome(suite.AddressUnreachableTestCase)

        self.assertCheckPasses(o)

    def test_address_unreachable_no_reply(self):
        o = self.get_outcome(suite.AddressUnreachableTestCase)

        self.assertCheckFails(o)

    def test_address_unreachable_invalid_src(self):
        self.ifx.replies_with(IPv6(src="::", dst=str(self.tn1.global_ip()))/ICMPv6DestUnreach(code=3))

        o = self.get_outcome(suite.AddressUnreachableTestCase)

        self.assertCheckFails(o)

    def test_address_unreachable_invalid_dst(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst="::")/ICMPv6DestUnreach(code=3))

        o = self.get_outcome(suite.AddressUnreachableTestCase)

        self.assertCheckFails(o)

    def test_address_unreachable_invalid_layer(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip())))

        o = self.get_outcome(suite.AddressUnreachableTestCase)

        self.assertCheckFails(o)

    def test_address_unreachable_invalid_code(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6DestUnreach(code=1))

        o = self.get_outcome(suite.AddressUnreachableTestCase)

        self.assertCheckFails(o)

    def test_address_unreachable_invalid_mtu(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6DestUnreach(code=3)/Raw(load='A'*1300))

        o = self.get_outcome(suite.AddressUnreachableTestCase)

        self.assertCheckFails(o)


class PortUnreachableLinkLocalTestCase(ComplianceTestTestCase):

    def test_port_unreachable_valid(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6DestUnreach(code=4))
        self.ui.inputs.append('n')

        o = self.get_outcome(suite.PortUnreachableLinkLocalTestCase)

        self.assertCheckPasses(o)


    def test_port_unreachable_invalid_user_input(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6DestUnreach(code=4))
        self.ui.inputs.append('y')

        o = self.get_outcome(suite.PortUnreachableLinkLocalTestCase)

        self.assertCheckFails(o)

    def test_port_unreachable_no_reply(self):
        self.ui.inputs.append('n')

        o = self.get_outcome(suite.PortUnreachableLinkLocalTestCase)

        self.assertCheckFails(o)

    def test_port_unreachable_invalid_src(self):
        self.ifx.replies_with(IPv6(src="::", dst=str(self.tn1.link_local_ip()))/ICMPv6DestUnreach(code=4))
        self.ui.inputs.append('n')

        o = self.get_outcome(suite.PortUnreachableLinkLocalTestCase)

        self.assertCheckFails(o)

    def test_port_unreachable_invalid_dst(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst="::")/ICMPv6DestUnreach(code=4))
        self.ui.inputs.append('n')

        o = self.get_outcome(suite.PortUnreachableLinkLocalTestCase)

        self.assertCheckFails(o)

    def test_port_unreachable_invalid_layer(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip())))
        self.ui.inputs.append('n')

        o = self.get_outcome(suite.PortUnreachableLinkLocalTestCase)

        self.assertCheckFails(o)

    def test_port_unreachable_invalid_code(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6DestUnreach(code=1))
        self.ui.inputs.append('n')

        o = self.get_outcome(suite.PortUnreachableLinkLocalTestCase)

        self.assertCheckFails(o)

    def test_port_unreachable_invalid_mtu(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6DestUnreach(code=4)/Raw('A'*1300))
        self.ui.inputs.append('n')

        o = self.get_outcome(suite.PortUnreachableLinkLocalTestCase)

        self.assertCheckFails(o)


class PortUnreachableGlobalTestCase(ComplianceTestTestCase):

    def test_port_global_unreachable_valid(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6DestUnreach(code=4))
        self.ui.inputs.append('n')

        o = self.get_outcome(suite.PortUnreachableGlobalTestCase)

        self.assertCheckPasses(o)

    def test_port_global_unreachable_invalid_user_input(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6DestUnreach(code=4))
        self.ui.inputs.append('y')

        o = self.get_outcome(suite.PortUnreachableGlobalTestCase)

        self.assertCheckFails(o)

    def test_port_global_unreachable_no_reply(self):
        self.ui.inputs.append('n')

        o = self.get_outcome(suite.PortUnreachableGlobalTestCase)

        self.assertCheckFails(o)

    def test_port_global_unreachable_invalid_src(self):
        self.ifx.replies_with(IPv6(src="::", dst=str(self.tn1.global_ip()))/ICMPv6DestUnreach(code=4))
        self.ui.inputs.append('n')

        o = self.get_outcome(suite.PortUnreachableGlobalTestCase)

        self.assertCheckFails(o)

    def test_port_global_unreachable_invalid_dst(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst="::")/ICMPv6DestUnreach(code=4))
        self.ui.inputs.append('n')

        o = self.get_outcome(suite.PortUnreachableGlobalTestCase)

        self.assertCheckFails(o)

    def test_port_global_unreachable_invalid_layer(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip())))
        self.ui.inputs.append('n')

        o = self.get_outcome(suite.PortUnreachableGlobalTestCase)

        self.assertCheckFails(o)

    def test_port_global_unreachable_invalid_code(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6DestUnreach(code=1))
        self.ui.inputs.append('n')

        o = self.get_outcome(suite.PortUnreachableGlobalTestCase)

        self.assertCheckFails(o)

    def test_port_global_unreachable_invalid_mtu(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6DestUnreach(code=4)/Raw('A'*1300))
        self.ui.inputs.append('n')

        o = self.get_outcome(suite.PortUnreachableGlobalTestCase)

        self.assertCheckFails(o)


class BeyondScopeOfSourceAddressTestCase(ComplianceTestTestCase):

    def test_beyond_scope_unreachable_valid(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6DestUnreach(code=2))

        o = self.get_outcome(suite.BeyondScopeOfSourceAddressTestCase)

        self.assertCheckPasses(o)

    def test_beyond_scope_unreachable_no_reply(self):
        o = self.get_outcome(suite.BeyondScopeOfSourceAddressTestCase)

        self.assertCheckFails(o)

    def test_beyond_scope_unreachable_invalid_src(self):
        self.ifx.replies_with(IPv6(src="::", dst=str(self.tn1.link_local_ip()))/ICMPv6DestUnreach(code=2))

        o = self.get_outcome(suite.BeyondScopeOfSourceAddressTestCase)

        self.assertCheckFails(o)

    def test_beyond_scope_unreachable_invalid_dst(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst="::")/ICMPv6DestUnreach(code=2))

        o = self.get_outcome(suite.BeyondScopeOfSourceAddressTestCase)

        self.assertCheckFails(o)

    def test_beyond_scope_unreachable_invalid_layer(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip())))

        o = self.get_outcome(suite.BeyondScopeOfSourceAddressTestCase)

        self.assertCheckFails(o)

    def test_beyond_scope_unreachable_invalid_code(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6DestUnreach(code=1))

        o = self.get_outcome(suite.BeyondScopeOfSourceAddressTestCase)

        self.assertCheckFails(o)

    def test_beyond_scope_unreachable_invalid_mtu(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6DestUnreach(code=2)/Raw('A'*1300))

        o = self.get_outcome(suite.BeyondScopeOfSourceAddressTestCase)

        self.assertCheckFails(o)
        