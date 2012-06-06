import unittest
from veripy.models import IPAddress, IPAddressCollection


class IPAddressCollectionTestCase(unittest.TestCase):

    def setUp(self):
        self.c = IPAddressCollection([IPAddress.identify("2001:500:88:200::10"), IPAddress.identify("2001:500:88:200::11"), IPAddress.identify("fe80:500:88:200::10"), IPAddress.identify("192.0.43.10")])


    def test_it_should_create_a_collection_of_ip_addresses(self):
        self.assertTrue(isinstance(self.c, IPAddressCollection))

    def test_it_should_count_the_number_of_ip_addresses(self):
        self.assertEqual(4, len(self.c))

    def test_it_should_append_an_ip_address(self):
        self.assertEqual(4, len(self.c))

        self.c.append(IPAddress.identify("2001:500:88:200::15"))

        self.assertEqual(5, len(self.c))

    def test_it_should_discard_duplicate_ip_addresses(self):
        self.assertEqual(4, len(self.c))

        self.c.append(IPAddress.identify("2001:500:88:200::10"))

        self.assertEqual(4, len(self.c))

    def test_it_should_get_all_the_v6_addresses(self):
        ips = self.c.ip(offset='*', scope='*', type='v6')

        self.assertEqual(3, len(ips))
        self.assertEqual("2001:500:88:200::10", ips[0].short_form())
        self.assertEqual("2001:500:88:200::11", ips[1].short_form())
        self.assertEqual("fe80:500:88:200::10", ips[2].short_form())

    def test_it_should_get_all_the_v4_addresses(self):
        ips = self.c.ip(offset='*', type='v4')

        self.assertEqual(1, len(ips))
        self.assertEqual("192.0.43.10", str(ips[0]))

    def test_it_should_get_all_the_v6_tunnel_addresses(self):
        self.c.append("2002:500:88:200::10")

        ips = self.c.ip(offset='*', type='6in4')

        self.assertEqual(1, len(ips))
        self.assertEqual("2002:500:88:200::10", ips[0].short_form())

    def test_it_should_get_the_default_global_v6_ip(self):
        self.assertEqual("2001:500:88:200::10", self.c.global_ip().short_form())

    def test_it_should_get_the_default_v4_ip(self):
        self.assertEqual("192.0.43.10", self.c.global_ip(type='v4').short_form())

    def test_it_should_get_the_default_v6_tunnel_ip(self):
        self.c.append("2002:500:88:200::10")

        self.assertEqual("2002:500:88:200::10", self.c.global_ip(type='6in4').short_form())

    def test_it_should_get_the_default_link_local_v6_ip(self):
        self.assertEqual("fe80:500:88:200::10", self.c.link_local_ip().short_form())

    def test_it_should_get_the_second_global_v6_ip(self):
        self.assertEqual("2001:500:88:200::11", self.c.global_ip(offset=1).short_form())

    def test_it_should_get_the_second_v4_ip(self):
        self.c.append("192.0.43.11")

        self.assertEqual("192.0.43.11", self.c.global_ip(offset=1, type='v4').short_form())

    def test_it_should_get_none_if_there_are_not_enough_ips(self):
        self.assertEqual(None, self.c.global_ip(offset=5))

    def test_it_should_not_change_the_number_of_ip_addresses_when_specifying_any_type_and_any_scope(self):
        self.assertEqual(4, len(self.c))        
        ip_a = self.c.ip(type='*', scope='*')        
        ip_b = self.c.ip(type='*', scope='*')        
        self.assertEqual(4, len(self.c))
        
