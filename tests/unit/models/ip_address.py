import unittest
from veripy.models import IPAddress, IPv4Address, IPv6Address


class IPAddressTestCase(unittest.TestCase):

    def test_it_should_recognise_a_valid_ipv4_address(self):
        self.assertTrue(IPv4Address.is_valid("192.0.43.10"))

    def test_it_should_recognise_a_valid_ipv6_address(self):
        self.assertTrue(IPv6Address.is_valid("2001:0500:0088:0200:0000:0000:0000:0010"))

    def test_it_should_recognise_a_short_form_ipv6_address(self):
        self.assertTrue(IPv6Address.is_valid("2001:500:88:200::10"))

    def test_it_should_not_recognise_an_ipv6_address_as_v4(self):
        self.assertFalse(IPv4Address.is_valid("2001:0500:0088:0200:0000:0000:0000:0010"))

    def test_it_should_not_recognise_a_non_ip_address_as_v4(self):
        self.assertFalse(IPv4Address.is_valid("not a v4 address"))

    def test_it_should_not_recognise_an_ipv4_address_as_v6(self):
        self.assertFalse(IPv6Address.is_valid("192.0.43.10"))

    def test_it_should_not_recognise_a_non_ip_address_as_v6(self):
        self.assertFalse(IPv6Address.is_valid("not a v6 address"))

    def test_it_should_identify_a_valid_ipv4_address(self):
        self.assertTrue(isinstance(IPAddress.identify("192.0.43.10"), IPv4Address))

    def test_it_should_identify_a_valid_ipv6_address(self):
        self.assertTrue(isinstance(IPAddress.identify("2001:0500:0088:0200:0000:0000:0000:0010"), IPv6Address))

    def test_it_should_identify_a_v4_mapped_address(self):
        self.assertTrue(isinstance(IPAddress.identify("::ffff:10.0.0.3"), IPv6Address))
        
    def test_it_should_not_identify_a_non_ip_address(self):
        self.assertEqual(None, IPAddress.identify("no an ip address"))

    def test_it_should_return_a_v4_address_as_a_string(self):
        ip = IPv4Address("192.0.43.10")
        
        self.assertEqual("192.0.43.10", str(ip))
    
    def test_it_should_return_a_v6_address_as_a_string(self):
        ip = IPv6Address("2001:0500:0088:0200:0000:0000:0000:0010")
        
        self.assertEqual("2001:0500:0088:0200:0000:0000:0000:0010", str(ip))
        
    def test_it_should_return_the_version_of_a_v4_address(self):
        ip = IPv4Address("192.0.43.10")

        self.assertEqual(4, ip.version())

    def test_it_should_return_the_version_of_a_v6_address(self):
        ip = IPv6Address("2001:0500:0088:0200:0000:0000:0000:0010")

        self.assertEqual(6, ip.version())

    def test_it_should_canonicalise_a_v6_address(self):
        ip = IPv6Address("2001:500:88:200::10")

        self.assertEqual("2001:0500:0088:0200:0000:0000:0000:0010", str(ip))

    def test_it_should_canonicalise_a_v4_mapped_address(self):
        ip = IPv6Address("::ffff:10.0.0.1")

        self.assertEqual("0000:0000:0000:0000:0000:ffff:0a00:0001", str(ip))

    def test_it_should_get_the_canonical_form_of_a_v6_address(self):
        ip = IPv6Address("2001:500:88:200::10")

        self.assertEqual("2001:0500:0088:0200:0000:0000:0000:0010", ip.canonical_form())

    def test_it_should_get_the_short_form_of_a_v6_address(self):
        ip = IPv6Address("2001:500:88:200::10")

        self.assertEqual("2001:500:88:200::10", ip.short_form())

    def test_it_should_get_the_short_form_of_a_v4_address(self):
        ip = IPv4Address("192.0.43.10")

        self.assertEqual("192.0.43.10", ip.short_form())

    def test_it_should_get_the_canonical_form_of_a_v4_address(self):
        ip = IPv4Address("192.0.43.10")

        self.assertEqual("192.0.43.10", ip.canonical_form())

    def test_it_should_identify_a_v6_address_as_multicast(self):
        ip = IPv6Address("ff01::2")

        self.assertTrue(ip.is_multicast())

    def test_it_should_not_identify_a_v6_address_as_multicast(self):
        ip = IPv6Address("2001:500:88:200::10")

        self.assertFalse(ip.is_multicast())
    
    def test_it_should_identify_a_v6_address_as_a_tunnel(self):
        ip = IPv6Address("2002:500:88:200::10")

        self.assertTrue(ip.is_tunnel())
    
    def test_it_should_not_identify_a_v6_address_as_a_tunnel(self):
        ip = IPv6Address("2001:500:88:200::10")

        self.assertFalse(ip.is_tunnel())

    def test_it_should_identify_the_undefined_v6_address(self):
        ip = IPv6Address("::")

        self.assertTrue(ip.is_undefined())

    def test_it_should_not_identify_a_v6_address_as_undefined(self):
        ip = IPv6Address("2001:500:88:200::10")

        self.assertFalse(ip.is_undefined())

    def test_it_should_identify_the_loopback_v6_address(self):
        ip = IPv6Address("::1")

        self.assertTrue(ip.is_loopback())

    def test_it_should_not_identify_a_v6_address_as_loopback(self):
        ip = IPv6Address("2001:500:88:200::10")

        self.assertFalse(ip.is_loopback())

    def test_it_should_identify_a_v6_address_is_v4_mapped(self):
        ip = IPv6Address("::ffff:a00:1")

        self.assertTrue(ip.is_v4_mapped())

    def test_it_should_identify_the_loopback_v6_address_as_interface_local_scope(self):
        ip = IPv6Address("::1")

        self.assertEqual('interface-local', ip.scope())
    
    def test_it_should_identify_a_v6_address_as_link_local_scope(self):
        ip = IPv6Address("fe80:500:88:200::10")

        self.assertEqual('link-local', ip.scope())
    
    def test_it_should_identify_a_v6_address_as_site_local_scope(self):
        ip = IPv6Address("fec0:500:88:200::10")

        self.assertEqual('site-local', ip.scope())
    
    def test_it_should_identify_a_v6_address_as_global_scope(self):
        ip = IPv6Address("2001:500:88:200::10")

        self.assertEqual('global', ip.scope())
    
    def test_it_should_identify_a_v6_multicast_address_as_interface_local_scope(self):
        ip = IPv6Address("ff10::200:10")

        self.assertEqual('interface-local', ip.scope())

    def test_it_should_identify_a_v6_multicast_address_as_link_local_scope(self):
        ip = IPv6Address("ff20::200:10")

        self.assertEqual('link-local', ip.scope())

    def test_it_should_identify_a_v6_multicast_address_as_subnet_local_scope(self):
        ip = IPv6Address("ff30::200:10")

        self.assertEqual('subnet-local', ip.scope())

    def test_it_should_identify_a_v6_multicast_address_as_admin_local_scope(self):
        ip = IPv6Address("ff40::200:10")

        self.assertEqual('admin-local', ip.scope())

    def test_it_should_identify_a_v6_multicast_address_as_site_local_scope(self):
        ip = IPv6Address("ff50::200:10")

        self.assertEqual('site-local', ip.scope())

    def test_it_should_identify_a_v6_multicast_address_as_organisation_local_scope(self):
        ip = IPv6Address("ff80::200:10")

        self.assertEqual('organisation-local', ip.scope())

    def test_it_should_identify_a_v6_multicast_address_as_global_scope(self):
        ip = IPv6Address("ffe0::200:10")

        self.assertEqual('global', ip.scope())

class IPv4AddressTestCase(unittest.TestCase):

    def test_it_should_have_a_subnet_prefix_size(self):
        ip = IPv4Address("192.0.43.10")

        self.assertEqual(24, ip.prefix_size)

    def test_it_should_have_a_netmask(self):
        ip = IPv4Address("192.0.43.10")

        self.assertEqual("255.255.255.0", ip.netmask())

    def test_it_should_change_the_netmask_to_reflect_the_subnet_prefix_size(self):
        ip = IPv4Address("192.0.43.10")
        ip.prefix_size = 16

        self.assertEqual("255.255.0.0", ip.netmask())

    def test_it_should_calculate_the_network_prefix_of_a_slash_16(self):
        ip = IPv4Address("192.0.43.10")
        ip.prefix_size = 16

        self.assertEqual("192.0.0.0", ip.network())

    def test_it_should_calculate_the_network_prefix_of_a_slash_24(self):
        ip = IPv4Address("192.0.43.10")

        self.assertEqual("192.0.43.0", ip.network())

class IPv6AddressTestCase(unittest.TestCase):

    def test_it_should_have_a_subnet_prefix_size(self):
        ip = IPv6Address("2001:500:88:200::10")

        self.assertEqual(64, ip.prefix_size)

    def test_it_should_have_a_netmask(self):
        ip = IPv6Address("2001:500:88:200::10")

        self.assertEqual("ffff:ffff:ffff:ffff:0000:0000:0000:0000", ip.netmask())

    def test_it_should_change_the_netmask_to_reflect_the_subnet_prefix_size(self):
        ip = IPv6Address("2001:500:88:200::10")
        ip.prefix_size = 96

        self.assertEqual("ffff:ffff:ffff:ffff:ffff:ffff:0000:0000", ip.netmask())

    def test_it_should_calculate_the_network_prefix_of_a_slash_32(self):
        ip = IPv6Address("2001:500:88:200::10")
        ip.prefix_size = 32

        self.assertEqual("2001:0500:0000:0000:0000:0000:0000:0000", ip.network())

    def test_it_should_calculate_the_network_prefix_of_a_slash_64(self):
        ip = IPv6Address("2001:500:88:200::10")

        self.assertEqual("2001:0500:0088:0200:0000:0000:0000:0000", ip.network())

    def test_it_should_calculate_the_network_prefix_of_a_slash_96(self):
        ip = IPv6Address("2001:500:88:200::10")
        ip.prefix_size = 96

        self.assertEqual("2001:0500:0088:0200:0000:0000:0000:0000", ip.network())


class IPEquivalenceTestCase(unittest.TestCase):
    
    def test_it_should_implement__eq__for_two_v6_addresses(self):
        ip1 = IPv6Address("2001:500:88:200::10")
        ip2 = IPv6Address("2001:500:88:200::20")

        self.assertTrue(ip1 == ip1)
        self.assertFalse(ip1 == ip2)

    def test_it_should_implement__eq__for_two_v4_addresses(self):
        ip1 = IPv4Address("192.0.43.10")
        ip2 = IPv4Address("192.0.43.20")

        self.assertTrue(ip1 == ip1)
        self.assertFalse(ip1 == ip2)

    def test_it_should_implement__eq__for_a_v4_and_a_v6_addresses(self):
        ip1 = IPv6Address("2001:500:88:200::10")
        ip2 = IPv4Address("192.0.43.20")
        
        self.assertFalse(ip1 == ip2)

    def test_it_should_implement__eq__for_a_v6_and_a_v4_addresses(self):
        ip1 = IPv4Address("192.0.43.10")
        ip2 = IPv6Address("2001:500:88:200::20")

        self.assertFalse(ip1 == ip2)

    def test_it_should_implement__eq__for_a_v6_and_a_v6str_addresses(self):
        ip1 = IPv6Address("2001:500:88:200::10")
        ip2 = IPv6Address("2001:500:88:200::20")

        self.assertTrue(ip1 == str(ip1))
        self.assertFalse(ip1 == str(ip2))

    def test_it_should_implement__eq__for_a_v4_and_a_v4str_addresses(self):
        ip1 = IPv4Address("192.0.43.10")
        ip2 = IPv4Address("192.0.43.20")

        self.assertTrue(ip1 == str(ip1))
        self.assertFalse(ip1 == str(ip2))

    def test_it_should_implement__eq__for_a_v6_and_a_v4str_addresses(self):
        ip1 = IPv6Address("2001:500:88:200::10")
        ip2 = IPv4Address("192.0.43.20")

        self.assertFalse(ip1 == str(ip2))

    def test_it_should_implement__eq__for_a_v4_and_a_v6str_addresses(self):
        ip1 = IPv4Address("192.0.43.10")
        ip2 = IPv6Address("2001:500:88:200::20")

        self.assertFalse(ip1 == str(ip2))

    def test_it_should_implement__eq__for_a_v6str_and_a_v6_addresses(self):
        ip1 = IPv6Address("2001:500:88:200::10")
        ip2 = IPv6Address("2001:500:88:200::20")

        self.assertTrue(str(ip1) == ip1)
        self.assertFalse(str(ip2) == ip1)

    def test_it_should_implement__eq__for_a_v4str_and_a_v4_addresses(self):
        ip1 = IPv4Address("192.0.43.10")
        ip2 = IPv4Address("192.0.43.20")

        self.assertTrue(str(ip1) == ip1)
        self.assertFalse(str(ip2) == ip1)

    def test_it_should_implement__eq__for_a_v6str_and_a_v4_addresses(self):
        ip1 = IPv6Address("2001:500:88:200::10")
        ip2 = IPv4Address("192.0.43.20")

        self.assertFalse(str(ip2) == ip1)

    def test_it_should_implement__eq__for_a_v4str_and_a_v6_addresses(self):
        ip1 = IPv4Address("192.0.43.10")
        ip2 = IPv6Address("2001:500:88:200::20")

        self.assertFalse(str(ip2) == ip1)

    def test_it_should_implement__ne__for_a_pair_of_v6_addresses(self):
        ip1 = IPv6Address("2001:500:88:200::10")
        ip2 = IPv6Address("2001:500:88:200::20")

        self.assertTrue(ip1 != ip2)
        self.assertFalse(ip1 != ip1)

    def test_it_should_compare_ipv6_addresses_case_insensitively(self):
        ip1 = IPv6Address("2001:db8::1")

        self.assertTrue(ip1 == "2001:DB8::1")
        