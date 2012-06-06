import unittest
from libs.ipcalc import Network
from scapy.all import ARP, Ether, ICMP, ICMPv6EchoReply, ICMPv6EchoRequest, ICMPv6ND_NA, ICMPv6ND_NS, ICMPv6ND_RA, ICMPv6ND_RS, ICMPv6NDOptDstLLAddr, ICMPv6NDOptMTU, ICMPv6NDOptPrefixInfo, ICMPv6NDOptSrcLLAddr, IP, IPv6
from veripy.models import Interface, IPAddress, Link, Tap, TargetInterface, TestNetwork, TestNode, TestRouter
from tests.mocks.configuration import MockConfiguration, sampleOptions
from tests.mocks.networking import MockInterface


class TestNetworkTestCase(unittest.TestCase):

    def setUp(self):
        options, args = sampleOptions("--configuration tests/mocks/veripy.cfg host")
        self.c = MockConfiguration(args, options, None)

        self.n = self.c.build_test_network()

    def tearDown(self):
        self.n.reset()


    def test_it_should_have_three_links(self):
        self.assertEqual(3, len(self.n.links()))
        self.assertEqual('A', self.n.link(1).name)
        self.assertEqual('B', self.n.link(2).name)
        self.assertEqual('C', self.n.link(3).name)

    def test_it_should_have_four_nodes(self):
        self.assertEqual(4, len(self.n.nodes()))
        self.assertEqual('TN1', self.n.node(1).name)
        self.assertEqual('TN2', self.n.node(2).name)
        self.assertEqual('TN3', self.n.node(3).name)
        self.assertEqual('TN4', self.n.node(4).name)

    def test_it_should_have_three_routers(self):
        self.assertEqual(3, len(self.n.routers()))
        self.assertEqual('TR1', self.n.router(1).name)
        self.assertEqual('TR2', self.n.router(2).name)
        self.assertEqual('TR3', self.n.router(3).name)
        
    def test_it_should_have_bound_internal_interfaces_to_links(self):
        self.assertEqual(5, len(self.n.link(1).bound_interfaces()))
        self.assertEqual(5, len(self.n.link(2).bound_interfaces()))
        self.assertEqual(2, len(self.n.link(3).bound_interfaces()))


class InterfaceTestCase(unittest.TestCase):
    
    def test_it_should_get_the_default_v6_ip(self):
        l = Link('A')
        i = Interface(link=l, ips=[IPAddress.identify("2001:500:88:200::10"), IPAddress.identify("2001:500:88:200::11"), IPAddress.identify("fe80:500:88:200::10"), IPAddress.identify("192.0.43.10")])
        
        self.assertEqual("2001:500:88:200::10", i.ip().short_form())

    def test_it_should_get_the_default_v4_ip(self):
        l = Link('A')
        i = Interface(link=l, ips=[IPAddress.identify("2001:500:88:200::10"), IPAddress.identify("2001:500:88:200::11"), IPAddress.identify("fe80:500:88:200::10"), IPAddress.identify("192.0.43.10")])

        self.assertEqual("192.0.43.10", i.ip(type='v4').short_form())

    def test_it_should_get_the_default_v6_link_local_ip(self):
        l = Link('A')
        i = Interface(link=l, ips=[IPAddress.identify("2001:500:88:200::10"), IPAddress.identify("2001:500:88:200::11"), IPAddress.identify("fe80:500:88:200::10"), IPAddress.identify("192.0.43.10")])

        self.assertEqual("fe80:500:88:200::10", i.link_local_ip().short_form())

    def test_it_should_get_the_second_v6_global_ip(self):
        l = Link('A')
        i = Interface(link=l, ips=[IPAddress.identify("2001:500:88:200::10"), IPAddress.identify("2001:500:88:200::11"), IPAddress.identify("fe80:500:88:200::10"), IPAddress.identify("192.0.43.10")])

        self.assertEqual("2001:500:88:200::11", i.global_ip(offset=1).short_form())

    def test_it_should_send_packets_to_a_link(self):
        l = Link('A')
        i = Interface(link=l)

        i.send("This is a packet.")

        self.assertEqual(1, len(l.forwarded()))
        self.assertEqual("This is a packet.", l.forwarded()[0])

    def test_it_should_accept_packets_from_a_link(self):
        l = Link('A')
        i = Interface(link=l)
        j = Interface(link=l)

        i.send("This is a packet.")

        self.assertEqual(1, len(j.received()))
        self.assertEqual("This is a packet.", j.received()[0])
        
    def test_it_should_invoke_on_send_callbacks(self):
        l = Link('A')
        i = Interface(link=l)

        self.called = False
        self.packet = None
        def c(p, iface):
            self.called = True
            self.packet = p

        i.on_send(c)
        i.send("This is a packet.")

        self.assertTrue(self.called)
        self.assertEqual("This is a packet.", self.packet)

    def test_it_should_invoke_on_receive_callbacks(self):
        l = Link('A')
        i = Interface(link=l)

        self.called = False
        self.packet = None
        def c(p, iface):
            self.called = True
            self.packet = p

        i.on_receive(c)
        i.accept("This is a packet.")

        self.assertTrue(self.called)
        self.assertEqual("This is a packet.", self.packet)

    def test_it_should_inherit_its_layer2_protocol_from_the_link(self):
        l = Link('A')
        i = Interface(link=l)

        self.assertEqual(Link.Layer2Protocols.Ethernet, i.ll_protocol)

    def test_it_should_encapsulate_packets_with_layer_2_frames_on_send(self):
        l = Link('A')
        i = Interface(link=l)

        i.send(IPv6())
        
        self.assertEqual(1, len(l.forwarded()))
        self.assertTrue(l.forwarded()[0].haslayer(Ether))
        self.assertTrue(l.forwarded()[0].haslayer(IPv6))

    def test_it_should_set_the_source_and_destination_mac_addresses_to_defaults_for_ethernet_link_layer(self):
        l = Link('A')
        i = Interface(link=l)

        i.send(IPv6())

        self.assertEqual(1, len(l.forwarded()))
        self.assertTrue(l.forwarded()[0].haslayer(Ether))
        self.assertEqual("00:00:00:00:00:00", l.forwarded()[0].getlayer(Ether).src)
        self.assertEqual("ff:ff:ff:ff:ff:ff", l.forwarded()[0].getlayer(Ether).dst)

    def test_it_should_strip_layer_2_frames_from_packets_on_receive(self):
        l = Link('A')
        i = Interface(link=l)

        l.accept(Ether()/IPv6())
        
        self.assertEqual(1, len(i.received()))
        self.assertFalse(i.received()[0].haslayer('Ether'))
        self.assertTrue(i.received()[0].haslayer('IPv6'))

    def test_it_should_only_strip_the_layer_2_frame(self):
        l = Link('A')
        i = Interface(link=l)

        l.accept(Ether()/IP()/IPv6())

        self.assertEqual(1, len(i.received()))
        self.assertFalse(i.received()[0].haslayer('Ether'))
        self.assertTrue(i.received()[0].haslayer('IP'))
        self.assertTrue(i.received()[0].haslayer('IPv6'))

    def test_it_should_get_received_packets_filtered_by_source(self):
        l = Link('A')
        i = Interface(link=l)

        l.accept(IPv6(src="2001:db8::2", dst="2001:db8::1")/ICMPv6EchoRequest())
        l.accept(IPv6(src="2001:db8::1", dst="2001:db8::2")/ICMPv6EchoReply())

        self.assertEqual(1, len(i.received(src="2001:db8::2")))
        self.assertTrue(i.received(src="2001:db8::2")[0].haslayer(ICMPv6EchoRequest))

    def test_it_should_get_received_packets_filtered_by_destination(self):
        l = Link('A')
        i = Interface(link=l)

        l.accept(IPv6(src="2001:db8::2", dst="2001:db8::1")/ICMPv6EchoRequest())
        l.accept(IPv6(src="2001:db8::1", dst="2001:db8::2")/ICMPv6EchoReply())

        self.assertEqual(1, len(i.received(dst="2001:db8::2")))
        self.assertTrue(i.received(dst="2001:db8::2")[0].haslayer(ICMPv6EchoReply))

    def test_it_should_get_received_packets_filtered_by_type(self):
        l = Link('A')
        i = Interface(link=l)

        l.accept(IPv6(src="2001:db8::2", dst="2001:db8::1")/ICMPv6EchoRequest())
        l.accept(IPv6(src="2001:db8::1", dst="2001:db8::2")/ICMPv6EchoReply())

        self.assertEqual(1, len(i.received(type=ICMPv6EchoRequest)))
        self.assertTrue(i.received(type=ICMPv6EchoRequest)[0].haslayer(ICMPv6EchoRequest))

    def test_it_should_get_received_packets_filtered_by_sequence(self):
        l = Link('A')
        i = Interface(link=l)

        l.accept(IPv6(src="2001:db8::2", dst="2001:db8::1")/ICMPv6EchoRequest(seq=2))
        l.accept(IPv6(src="2001:db8::1", dst="2001:db8::2")/ICMPv6EchoReply(seq=2))
        
        self.assertEqual(2, len(i.received(seq=2)))
        self.assertEqual(0, len(i.received(seq=1)))

    def test_it_should_get_received_packets_filtered_by_lambda(self):
        l = Link('A')
        i = Interface(link=l)

        l.accept(IPv6(src="2001:db8::2", dst="2001:db8::1")/ICMPv6EchoRequest())
        l.accept(IP(src="192.168.0.1", dst="192.168.0.2")/ICMP())
        
        self.assertEqual(1, len(i.received(lbda=lambda p: p.haslayer(IPv6))))


class LinkTestCase(unittest.TestCase):

    def test_it_should_accept_traffic_from_an_interface(self):
        l = Link('A')
        i = Interface(link=l)

        l.accept("This is a packet.", previous_hop=i)

        self.assertEqual(1, len(l.forwarded()))
        self.assertEqual("This is a packet.", l.forwarded()[0])

    def test_it_should_forward_traffic_to_an_interface(self):
        l = Link('A')
        i = Interface(link=l)
        j = Interface(link=l)

        l.accept("This is a packet.", previous_hop=i)
        
        self.assertEqual(1, len(j.received()))
        self.assertEqual("This is a packet.", j.received()[0])

    def test_it_should_not_return_traffic_to_the_previous_hop(self):
        l = Link('A')
        i = Interface(link=l)

        l.accept("This is a packet.", previous_hop=i)

        self.assertEqual(0, len(i.received()))
        
    def test_it_should_forward_traffic_accept_a_real_interface_through_a_tap(self):
        l = Link('A')
        i = Interface(link=l)
        j = MockInterface('if0', '00:b0:d0:86:bb:f7')
        k = TargetInterface(link_addr="00:b0:d0:bb:cc:ff")
        t = Tap(l, j, k)

        l.accept("This is a packet.", previous_hop=i)
        
        self.assertEqual(1, len(j.sent))
        self.assertEqual("This is a packet.", j.sent[0])

    def test_it_should_forward_traffic_to_a_real_interface_through_a_tap(self):
        l = Link('A')
        i = Interface(link=l)
        j = MockInterface('if0', '00:b0:d0:86:bb:f7')
        k = TargetInterface(link_addr="00:b0:d0:bb:cc:ff")
        t = Tap(l, j, k)

        j.accept(["This is a packet."])
        
        self.assertEqual(1, len(l.forwarded()))
        self.assertEqual("This is a packet.", l.forwarded()[0])

    def test_it_should_have_a_layer2_protocol(self):
        l = Link('A')

        self.assertEqual(Link.Layer2Protocols.Ethernet, l.ll_protocol)


class TapTestCase(unittest.TestCase):

    def test_it_should_have_a_link(self):
        l = Link('A')
        i = MockInterface('if0', '00:b0:d0:86:bb:f7')
        k = TargetInterface(link_addr="00:b0:d0:bb:cc:ff")

        t = Tap(l, i, k)

        self.assertEqual(l, t.link)

    def test_it_should_have_an_interface(self):
        l = Link('A')
        i = MockInterface('if0', '00:b0:d0:86:bb:f7')
        k = TargetInterface(link_addr="00:b0:d0:bb:cc:ff")

        t = Tap(l, i, k)

        self.assertEqual(i, t.iface)

    def test_it_should_forward_packets_from_the_link_to_phy(self):
        l = Link('A')
        i = MockInterface('if0', '00:b0:d0:86:bb:f7')
        k = TargetInterface(link_addr="00:b0:d0:bb:cc:ff")
        t = Tap(l, i, k)

        l.accept("This is a packet.")

        self.assertEqual(1, len(i.sent))
        self.assertEqual("This is a packet.", i.sent[0])

    def test_it_should_forward_packets_from_phy_to_the_link(self):
        l = Link('A')
        i = MockInterface('if0', '00:b0:d0:86:bb:f7')
        k = TargetInterface(link_addr="00:b0:d0:bb:cc:ff")
        t = Tap(l, i, k)

        i.accept(["This is a packet."])

        self.assertEqual(1, len(l.forwarded()))
        self.assertEqual("This is a packet.", l.forwarded()[0])

    def test_it_should_have_a_target_interface(self):
        l = Link('A')
        i = MockInterface('if0', '00:b0:d0:86:bb:f7')
        j = TargetInterface(link_addr="00:b0:d0:bb:cc:ff")
        t = Tap(l, i, j)

        self.assertEqual(j, t.target_iface)

    def test_it_should_overwrite_the_source_mac_of_an_ethernet_frame(self):
        l = Link('A')
        i = Interface(link=l)
        j = MockInterface('if0', '00:b0:d0:86:bb:f7')
        k = TargetInterface(link_addr="00:b0:d0:bb:cc:ff")
        t = Tap(l, j, k)

        i.send(IPv6())

        self.assertEqual(1, len(j.sent))
        
        self.assertTrue(j.sent[0].haslayer(Ether))
        self.assertTrue(j.sent[0].haslayer(IPv6))
        self.assertEqual("00:b0:d0:86:bb:f7", j.sent[0].getlayer(Ether).src)

    def test_it_should_overwrite_the_destination_mac_of_an_ethernet_frame(self):
        l = Link('A')
        i = Interface(link=l)
        j = MockInterface('if0', '00:b0:d0:86:bb:f7')
        k = TargetInterface(link_addr="00:b0:d0:bb:cc:ff")
        t = Tap(l, j, k)

        i.send(IPv6())

        self.assertEqual(1, len(j.sent))

        self.assertTrue(j.sent[0].haslayer(Ether))
        self.assertTrue(j.sent[0].haslayer(IPv6))
        self.assertEqual("00:b0:d0:bb:cc:ff", j.sent[0].getlayer(Ether).dst)


class TestNodeTestCase(unittest.TestCase):

    def test_it_should_have_ip_addresses_on_if0(self):
        l = Link('A')
        n = TestNode('TNN',     link0=l, ips0=[IPAddress.identify("2001:500:88:200::10"), IPAddress.identify("2001:500:88:200::11"), IPAddress.identify("fe80:500:88:200::10"), IPAddress.identify("192.0.43.10")])

        self.assertEqual("2001:500:88:200::10", n.ip().short_form())
        self.assertEqual("2001:500:88:200::10", n.global_ip().short_form())
        self.assertEqual("2001:500:88:200::11", n.global_ip(offset=1).short_form())
        self.assertEqual("192.0.43.10", n.ip(type='v4').short_form())

    def test_it_should_send_traffic_on_if0(self):
        l = Link('A')
        n = TestNode('TNN',     link0=l, ips0=[IPAddress.identify("2001:500:88:200::10"), IPAddress.identify("2001:500:88:200::11"), IPAddress.identify("fe80:500:88:200::10"), IPAddress.identify("192.0.43.10")])

        n.send("This is a packet.")

        self.assertEqual(1, len(l.forwarded()))
        self.assertEqual("This is a packet.", l.forwarded()[0])

    def test_it_should_receive_traffic_from_if0(self):
        l = Link('A')
        n = TestNode('TNN',     link0=l, ips0=[IPAddress.identify("2001:500:88:200::10"), IPAddress.identify("2001:500:88:200::11"), IPAddress.identify("fe80:500:88:200::10"), IPAddress.identify("192.0.43.10")])

        l.accept(IPv6(src="2001:500:88:200::90", dst="2001:500:88:200::10"))

        self.assertEqual(1, len(n.received()))
        self.assertTrue(n.received()[0].haslayer(IPv6))

    def test_it_should_get_received_packets_for_its_own_global(self):
        l = Link('A')
        n = TestNode('TNN',     link0=l, ips0=[IPAddress.identify("2001:db8::1"), IPAddress.identify("fe80::1")])

        l.accept(IPv6(src="2001:db8::2", dst="2001:db8::1")/ICMPv6EchoRequest())
        l.accept(IPv6(src="2001:db8::1", dst="2001:db8::2")/ICMPv6EchoReply())

        self.assertEqual(1, len(n.received()))
        self.assertTrue(n.received()[0].haslayer(ICMPv6EchoRequest))

    def test_it_should_get_received_packets_for_its_own_link_local(self):
        l = Link('A')
        n = TestNode('TNN',     link0=l, ips0=[IPAddress.identify("2001:db8::1"), IPAddress.identify("fe80::1")])

        l.accept(IPv6(src="fe80::2", dst="fe80::1")/ICMPv6EchoRequest())
        l.accept(IPv6(src="fe80::1", dst="fe80::2")/ICMPv6EchoReply())

        self.assertEqual(1, len(n.received()))
        self.assertTrue(n.received()[0].haslayer(ICMPv6EchoRequest))

    def test_it_should_get_received_packets_for_its_own_v4_address(self):
        l = Link('A')
        n = TestNode('TNN',     link0=l, ips0=[IPAddress.identify("2001:db8::1"), IPAddress.identify("fe80::1"), IPAddress.identify("10.0.0.1")])

        l.accept(IP(src="10.0.0.2", dst="10.0.0.1")/ICMP())
        l.accept(IP(src="10.0.0.1", dst="10.0.0.2")/ICMP())

        self.assertEqual(1, len(n.received()))
        self.assertTrue(n.received()[0].haslayer(ICMP))

    def test_it_should_not_get_received_packets_for_another_ip(self):
        l = Link('A')
        n = TestNode('TNN',     link0=l, ips0=[IPAddress.identify("2001:db8::1"), IPAddress.identify("fe80::1")])

        l.accept(IPv6(src="2001:db8::2", dst="2001:db8::3")/ICMPv6EchoRequest())
        l.accept(IPv6(src="2001:db8::3", dst="2001:db8::2")/ICMPv6EchoReply())

        self.assertEqual(0, len(n.received()))

    def test_it_should_respond_to_a_neighbourhood_solicitation_for_its_global_ip(self):
        l = Link('A')
        n = TestNode('TNN',     link0=l, ll_addr0="00:b0:d0:86:bb:f7", ips0=[IPAddress.identify("2001:500:88:200::10"), IPAddress.identify("2001:500:88:200::11"), IPAddress.identify("fe80:500:88:200::10"), IPAddress.identify("192.0.43.10")])

        l.accept(IPv6(src="fe80:500:88:200::20", dst="fe80:500:88:200::10")/ICMPv6ND_NS(tgt="2001:500:88:200::10"))

        self.assertEqual(2, len(l.forwarded()))
        self.assertTrue(l.forwarded()[0].haslayer(ICMPv6ND_NS))
        self.assertTrue(l.forwarded()[1].haslayer(ICMPv6ND_NA))
        self.assertEqual("2001:500:88:200::10", l.forwarded()[1].getlayer(IPv6).src)
        self.assertEqual("fe80:500:88:200::20", l.forwarded()[1].getlayer(IPv6).dst)
        self.assertEqual("2001:500:88:200::10", l.forwarded()[1].getlayer(ICMPv6ND_NA).tgt)

        self.assertTrue(l.forwarded()[1].haslayer(ICMPv6NDOptDstLLAddr))
        self.assertEqual("00:b0:d0:86:bb:f7", l.forwarded()[1].getlayer(ICMPv6NDOptDstLLAddr).lladdr)

    def test_it_should_respond_to_a_neighbourhood_solicitation_for_its_global_ip_sent_to_multicast(self):
        l = Link('A')
        n = TestNode('TNN',     link0=l, ll_addr0="00:b0:d0:86:bb:f7", ips0=[IPAddress.identify("2001:500:88:200::10"), IPAddress.identify("2001:500:88:200::11"), IPAddress.identify("fe80:500:88:200::10"), IPAddress.identify("192.0.43.10")])

        l.accept(IPv6(src="fe80:500:88:200::20", dst="ff02::1:ff00:20")/ICMPv6ND_NS(tgt="2001:500:88:200::10"))

        self.assertEqual(2, len(l.forwarded()))
        self.assertTrue(l.forwarded()[0].haslayer(ICMPv6ND_NS))
        self.assertTrue(l.forwarded()[1].haslayer(ICMPv6ND_NA))
        self.assertEqual("2001:500:88:200::10", str(l.forwarded()[1].getlayer(IPv6).src))
        self.assertEqual("fe80:500:88:200::20", str(l.forwarded()[1].getlayer(IPv6).dst))
        self.assertEqual("2001:500:88:200::10", str(l.forwarded()[1].getlayer(ICMPv6ND_NA).tgt))

        self.assertTrue(l.forwarded()[1].haslayer(ICMPv6NDOptDstLLAddr))
        self.assertEqual("00:b0:d0:86:bb:f7", l.forwarded()[1].getlayer(ICMPv6NDOptDstLLAddr).lladdr)

    def test_it_should_not_respond_to_a_neighbourhood_solicitation_for_another_global_ip(self):
        l = Link('A')
        n = TestNode('TNN',     link0=l, ll_addr0="00:b0:d0:86:bb:f7", ips0=[IPAddress.identify("2001:500:88:200::10"), IPAddress.identify("2001:500:88:200::11"), IPAddress.identify("fe80:500:88:200::10"), IPAddress.identify("192.0.43.10")])

        l.accept(IPv6(src="fe80:500:88:200::20", dst="fe80:500:88:200::10")/ICMPv6ND_NS(tgt="2001:500:88:200::15"))

        self.assertEqual(1, len(l.forwarded()))
        self.assertTrue(l.forwarded()[0].haslayer(ICMPv6ND_NS))

    def test_it_should_not_respond_to_a_neighbourhood_solicitation_for_another_global_ip_sent_to_multicast(self):
        l = Link('A')
        n = TestNode('TNN',     link0=l, ll_addr0="00:b0:d0:86:bb:f7", ips0=[IPAddress.identify("2001:500:88:200::10"), IPAddress.identify("2001:500:88:200::11"), IPAddress.identify("fe80:500:88:200::10"), IPAddress.identify("192.0.43.10")])

        l.accept(IPv6(src="fe80:500:88:200::20", dst="ff02::1:ff00:20")/ICMPv6ND_NS(tgt="2001:500:88:200::15"))

        self.assertEqual(1, len(l.forwarded()))
        self.assertTrue(l.forwarded()[0].haslayer(ICMPv6ND_NS))

    def test_it_should_respond_to_a_neighbourhood_solicitation_for_its_link_local_ip(self):
        l = Link('A')
        n = TestNode('TNN',     link0=l, ll_addr0="00:b0:d0:86:bb:f7", ips0=[IPAddress.identify("2001:500:88:200::10"), IPAddress.identify("2001:500:88:200::11"), IPAddress.identify("fe80:500:88:200::10"), IPAddress.identify("192.0.43.10")])

        l.accept(IPv6(src="fe80:500:88:200::20", dst="fe80:500:88:200::10")/ICMPv6ND_NS(tgt="fe80:500:88:200::10"))

        self.assertEqual(2, len(l.forwarded()))
        self.assertTrue(l.forwarded()[0].haslayer(ICMPv6ND_NS))
        self.assertTrue(l.forwarded()[1].haslayer(ICMPv6ND_NA))
        self.assertEqual("fe80:500:88:200::10", l.forwarded()[1].getlayer(IPv6).src)
        self.assertEqual("fe80:500:88:200::20", l.forwarded()[1].getlayer(IPv6).dst)
        self.assertEqual("fe80:500:88:200::10", l.forwarded()[1].getlayer(ICMPv6ND_NA).tgt)

        self.assertTrue(l.forwarded()[1].haslayer(ICMPv6NDOptDstLLAddr))
        self.assertEqual("00:b0:d0:86:bb:f7", l.forwarded()[1].getlayer(ICMPv6NDOptDstLLAddr).lladdr)

    def test_it_should_not_respond_to_a_neighbourhood_solicitation_for_another_link_local_ip(self):
        l = Link('A')
        n = TestNode('TNN',     link0=l, ll_addr0="00:b0:d0:86:bb:f7", ips0=[IPAddress.identify("2001:500:88:200::10"), IPAddress.identify("2001:500:88:200::11"), IPAddress.identify("fe80:500:88:200::10"), IPAddress.identify("192.0.43.10")])

        l.accept(IPv6(src="fe80:500:88:200::20", dst="fe80:500:88:200::10")/ICMPv6ND_NS(tgt="fe80:500:88:200::15"))

        self.assertEqual(1, len(l.forwarded()))
        self.assertTrue(l.forwarded()[0].haslayer(ICMPv6ND_NS))

    def test_it_should_not_respond_to_a_neighbourhood_solicitation_for_a_multicast_group_in_the_ips(self):
        l = Link('A')
        n = TestNode('TNN',     link0=l, ll_addr0="00:b0:d0:86:bb:f7", ips0=[IPAddress.identify("2001:500:88:200::10"), IPAddress.identify("2001:500:88:200::11"), IPAddress.identify("fe80:500:88:200::10"), IPAddress.identify("192.0.43.10")])

        l.accept(IPv6(src="fe80:500:88:200::20", dst="fe80:500:88:200::10")/ICMPv6ND_NS(tgt="ff02::1"))

        self.assertEqual(1, len(l.forwarded()))
        self.assertTrue(l.forwarded()[0].haslayer(ICMPv6ND_NS))

    def test_it_should_respond_to_arp_for_its_ipv4_address(self):
        l = Link('A')
        n = TestNode('TNN',     link0=l, ll_addr0="00:b0:d0:86:bb:f7", ips0=[IPAddress.identify("2001:500:88:200::10"), IPAddress.identify("2001:500:88:200::11"), IPAddress.identify("fe80:500:88:200::10"), IPAddress.identify("192.0.43.10")])

        l.accept(ARP(hwsrc="00:01:02:03:04:05", psrc="192.0.43.100", pdst="192.0.43.10"))

        self.assertEqual(2, len(l.forwarded()))
        self.assertTrue(l.forwarded()[1].haslayer(ARP))
        self.assertEqual(0x0002, l.forwarded()[1].getlayer(ARP).op)
        self.assertEqual("192.0.43.10", l.forwarded()[1].getlayer(ARP).psrc)
        self.assertEqual("00:b0:d0:86:bb:f7", l.forwarded()[1].getlayer(ARP).hwsrc)
        self.assertEqual("192.0.43.100", l.forwarded()[1].getlayer(ARP).pdst)
        self.assertEqual("00:01:02:03:04:05", l.forwarded()[1].getlayer(ARP).hwdst)

    def test_it_should_not_respond_to_arp_for_another_ipv4_address(self):
        l = Link('A')
        n = TestNode('TNN',     link0=l, ll_addr0="00:b0:d0:86:bb:f7", ips0=[IPAddress.identify("2001:500:88:200::10"), IPAddress.identify("2001:500:88:200::11"), IPAddress.identify("fe80:500:88:200::10"), IPAddress.identify("192.0.43.10")])

        l.accept(ARP(hwsrc="00:01:02:03:04:05", psrc="192.0.43.100", pdst="192.0.43.200"))

        self.assertEqual(1, len(l.forwarded()))

    def test_it_should_not_respond_to_an_arp_reply_address(self):
        l = Link('A')
        n = TestNode('TNN',     link0=l, ll_addr0="00:b0:d0:86:bb:f7", ips0=[IPAddress.identify("2001:500:88:200::10"), IPAddress.identify("2001:500:88:200::11"), IPAddress.identify("fe80:500:88:200::10"), IPAddress.identify("192.0.43.10")])

        l.accept(ARP(hwsrc="00:01:02:03:04:05", psrc="192.0.43.100", pdst="192.0.43.200", op=0x002))

        self.assertEqual(1, len(l.forwarded()))


class TestRouterTestCase(unittest.TestCase):

    def test_it_should_have_ip_addresses_on_if0(self):
        l = Link('A')
        m = Link('B')
        r = TestRouter('TNN',   link0=l, ips0=[IPAddress.identify("2001:500:88:200::10"), IPAddress.identify("2001:500:88:200::11"), IPAddress.identify("fe80:500:88:200::10"), IPAddress.identify("192.0.43.10")],
                                link1=m, ips1=[IPAddress.identify("2001:600:88:200::10"), IPAddress.identify("2001:600:88:200::11"), IPAddress.identify("fe80:600:88:200::10"), IPAddress.identify("192.1.43.10")])

        self.assertEqual("2001:500:88:200::10", r.ip().short_form())
        self.assertEqual("2001:500:88:200::10", r.global_ip().short_form())
        self.assertEqual("2001:500:88:200::11", r.global_ip(offset=1).short_form())
        self.assertEqual("192.0.43.10", r.ip(type='v4').short_form())

    def test_it_should_have_ip_addresses_on_if1(self):
        l = Link('A')
        m = Link('B')
        r = TestRouter('TNN',   link0=l, ips0=[IPAddress.identify("2001:500:88:200::10"), IPAddress.identify("2001:500:88:200::11"), IPAddress.identify("fe80:500:88:200::10"), IPAddress.identify("192.0.43.10")],
                                link1=m, ips1=[IPAddress.identify("2001:600:88:200::10"), IPAddress.identify("2001:600:88:200::11"), IPAddress.identify("fe80:600:88:200::10"), IPAddress.identify("192.1.43.10")])

        self.assertEqual("2001:600:88:200::10", r.ip(1).short_form())
        self.assertEqual("2001:600:88:200::10", r.global_ip(1).short_form())
        self.assertEqual("2001:600:88:200::11", r.global_ip(1, offset=1).short_form())
        self.assertEqual("192.1.43.10", r.ip(1, type='v4').short_form())

    def test_it_should_send_traffic_on_if0(self):
        l = Link('A')
        m = Link('B')
        r = TestRouter('TNN',   link0=l, ips0=[IPAddress.identify("2001:500:88:200::10"), IPAddress.identify("2001:500:88:200::11"), IPAddress.identify("fe80:500:88:200::10"), IPAddress.identify("192.0.43.10")],
                                link1=m, ips1=[IPAddress.identify("2001:600:88:200::10"), IPAddress.identify("2001:600:88:200::11"), IPAddress.identify("fe80:600:88:200::10"), IPAddress.identify("192.1.43.10")])

        r.send("This is a packet.")

        self.assertEqual(1, len(l.forwarded()))
        self.assertEqual("This is a packet.", l.forwarded()[0])
        self.assertEqual(0, len(m.forwarded()))

    def test_it_should_send_traffic_on_if1(self):
        l = Link('A')
        m = Link('B')
        r = TestRouter('TNN',   link0=l, ips0=[IPAddress.identify("2001:500:88:200::10"), IPAddress.identify("2001:500:88:200::11"), IPAddress.identify("fe80:500:88:200::10"), IPAddress.identify("192.0.43.10")],
                                link1=m, ips1=[IPAddress.identify("2001:600:88:200::10"), IPAddress.identify("2001:600:88:200::11"), IPAddress.identify("fe80:600:88:200::10"), IPAddress.identify("192.1.43.10")])

        r.send("This is a packet.", iface=1)

        self.assertEqual(0, len(l.forwarded()))
        self.assertEqual(1, len(m.forwarded()))
        self.assertEqual("This is a packet.", m.forwarded()[0])

    def test_it_should_receive_traffic_from_if0(self):
        l = Link('A')
        m = Link('B')
        r = TestRouter('TNN',   link0=l, ips0=[IPAddress.identify("2001:500:88:200::10"), IPAddress.identify("2001:500:88:200::11"), IPAddress.identify("fe80:500:88:200::10"), IPAddress.identify("192.0.43.10")],
                                link1=m, ips1=[IPAddress.identify("2001:600:88:200::10"), IPAddress.identify("2001:600:88:200::11"), IPAddress.identify("fe80:600:88:200::10"), IPAddress.identify("192.1.43.10")])

        l.accept(IPv6(src="2001:500:88:200::90", dst="2001:500:88:200::10"))

        self.assertEqual(1, len(r.received()))
        self.assertTrue(r.received()[0].haslayer(IPv6))
        self.assertEqual(0, len(r.received(1)))

    def test_it_should_receive_traffic_from_if1(self):
        l = Link('A')
        m = Link('B')
        r = TestRouter('TNN',   link0=l, ips0=[IPAddress.identify("2001:500:88:200::10"), IPAddress.identify("2001:500:88:200::11"), IPAddress.identify("fe80:500:88:200::10"), IPAddress.identify("192.0.43.10")],
                                link1=m, ips1=[IPAddress.identify("2001:600:88:200::10"), IPAddress.identify("2001:600:88:200::11"), IPAddress.identify("fe80:600:88:200::10"), IPAddress.identify("192.1.43.10")])

        m.accept(IPv6(src="2001:600:88:200::90", dst="2001:600:88:200::10"))

        self.assertEqual(0, len(r.received()))
        self.assertEqual(1, len(r.received(1)))
        self.assertTrue(r.received(1)[0].haslayer(IPv6))

    def test_it_should_not_forward_global_traffic_addressed_to_the_interface(self):
        l = Link('A')
        m = Link('B')
        r = TestRouter('TNN',   link0=l, ips0=[IPAddress.identify("2001:500:88:200::10"), IPAddress.identify("2001:500:88:200::11"), IPAddress.identify("fe80:500:88:200::10"), IPAddress.identify("192.0.43.10")],
                                link1=m, ips1=[IPAddress.identify("2001:600:88:200::10"), IPAddress.identify("2001:600:88:200::11"), IPAddress.identify("fe80:600:88:200::10"), IPAddress.identify("192.1.43.10")])

        l.accept(IPv6(dst="2001:500:88:200::10"))

        self.assertEqual(1, len(l.forwarded()))
        self.assertEqual(0, len(m.forwarded()))

    def test_it_should_forward_global_destined_for_the_other_interface(self):
        l = Link('A')
        m = Link('B')
        r = TestRouter('TNN',   link0=l, ips0=[IPAddress.identify("2001:500:88:200::10"), IPAddress.identify("2001:500:88:200::11"), IPAddress.identify("fe80:500:88:200::10"), IPAddress.identify("192.0.43.10")],
                                link1=m, ips1=[IPAddress.identify("2001:600:88:200::10"), IPAddress.identify("2001:600:88:200::11"), IPAddress.identify("fe80:600:88:200::10"), IPAddress.identify("192.1.43.10")],
                                forwards_to_0=[Network("2001:0500:0088:0200:0000:0000:0000:0000/64")],
                                forwards_to_1=[Network("2001:0600:0088:0200:0000:0000:0000:0000/64")])

        l.accept(IPv6(dst="2001:600:88:200::10"))

        self.assertEqual(1, len(l.forwarded()))
        self.assertEqual(1, len(m.forwarded()))
        
    def test_it_should_not_forward_link_local_traffic(self):
        l = Link('A')
        m = Link('B')
        r = TestRouter('TNN',   link0=l, ips0=[IPAddress.identify("2001:500:88:200::10"), IPAddress.identify("2001:500:88:200::11"), IPAddress.identify("fe80:500:88:200::10"), IPAddress.identify("192.0.43.10")],
                                link1=m, ips1=[IPAddress.identify("2001:600:88:200::10"), IPAddress.identify("2001:600:88:200::11"), IPAddress.identify("fe80:600:88:200::10"), IPAddress.identify("192.1.43.10")],
                                forwards_to_0=[Network("2001:0500:0088:0200:0000:0000:0000:0000/64")],
                                forwards_to_1=[Network("2001:0600:0088:0200:0000:0000:0000:0000/64")])

        l.accept(IPv6(dst="fe80:600:88:200::10"))

        self.assertEqual(1, len(l.forwarded()))
        self.assertEqual(0, len(m.forwarded()))

    def test_it_should_decrement_the_hlim_when_forwarding_ipv6_packets(self):
        l = Link('A')
        m = Link('B')
        r = TestRouter('TNN',   link0=l, ips0=[IPAddress.identify("2001:500:88:200::10"), IPAddress.identify("2001:500:88:200::11"), IPAddress.identify("fe80:500:88:200::10"), IPAddress.identify("192.0.43.10")],
                                link1=m, ips1=[IPAddress.identify("2001:600:88:200::10"), IPAddress.identify("2001:600:88:200::11"), IPAddress.identify("fe80:600:88:200::10"), IPAddress.identify("192.1.43.10")],
                                forwards_to_0=[Network("2001:0500:0088:0200:0000:0000:0000:0000/64")],
                                forwards_to_1=[Network("2001:0600:0088:0200:0000:0000:0000:0000/64")])
        p = IPv6(dst="2001:600:88:200::10")

        self.assertEqual(64, p.hlim)

        l.accept(p)

        self.assertEqual(1, len(l.forwarded()))
        self.assertEqual(1, len(m.forwarded()))
        self.assertTrue(m.forwarded()[0].haslayer(IPv6))
        self.assertEqual(63, m.forwarded()[0].hlim)

    def test_it_should_decrement_the_ttl_when_forwarding_ipv4_packets(self):
        l = Link('A')
        m = Link('B')
        r = TestRouter('TNN',   link0=l, ips0=[IPAddress.identify("2001:500:88:200::10"), IPAddress.identify("2001:500:88:200::11"), IPAddress.identify("fe80:500:88:200::10"), IPAddress.identify("192.0.43.10")],
                                link1=m, ips1=[IPAddress.identify("2001:600:88:200::10"), IPAddress.identify("2001:600:88:200::11"), IPAddress.identify("fe80:600:88:200::10"), IPAddress.identify("192.1.43.10")],
                                forwards_to_0=[Network("192.0.43.0/24")],
                                forwards_to_1=[Network("192.1.43.0/24")])
        p = IP(dst="192.1.43.10")

        self.assertEqual(64, p.ttl)

        l.accept(p)

        self.assertEqual(1, len(l.forwarded()))
        self.assertEqual(1, len(m.forwarded()))
        self.assertTrue(m.forwarded()[0].haslayer(IP))
        self.assertEqual(63, m.forwarded()[0].ttl)

    def test_it_should_respond_to_router_solicitations(self):
        l = Link('A')
        m = Link('B')
        r = TestRouter('TNN',   link0=l, ll_addr0="00:b0:d0:86:bb:f7", ips0=[IPAddress.identify("2001:500:88:200::10"), IPAddress.identify("2001:500:88:200::11"), IPAddress.identify("fe80:500:88:200::10"), IPAddress.identify("192.0.43.10")],
                                link1=m, ll_addr1="00:b0:d0:86:bb:f8", ips1=[IPAddress.identify("2001:600:88:200::10"), IPAddress.identify("2001:600:88:200::11"), IPAddress.identify("fe80:600:88:200::10"), IPAddress.identify("192.1.43.10")])

        l.accept(IPv6(src="fe80:500:88:200::20", dst="ff02::2")/ICMPv6ND_RS())

        self.assertEqual(2, len(l.forwarded()))
        self.assertTrue(l.forwarded()[0].haslayer(ICMPv6ND_RS))
        self.assertTrue(l.forwarded()[1].haslayer(ICMPv6ND_RA))
        self.assertEqual("fe80:500:88:200::10", l.forwarded()[1].getlayer(IPv6).src)
        self.assertEqual("ff02::1", l.forwarded()[1].getlayer(IPv6).dst)

        self.assertTrue(l.forwarded()[1].haslayer(ICMPv6NDOptSrcLLAddr))
        self.assertEqual("00:b0:d0:86:bb:f7", l.forwarded()[1].getlayer(ICMPv6NDOptSrcLLAddr).lladdr)

        self.assertTrue(l.forwarded()[1].haslayer(ICMPv6NDOptMTU))
        self.assertEqual(1500, l.forwarded()[1].getlayer(ICMPv6NDOptMTU).mtu)

        self.assertTrue(l.forwarded()[1].haslayer(ICMPv6NDOptPrefixInfo))
        self.assertEqual(64, l.forwarded()[1].getlayer(ICMPv6NDOptPrefixInfo).prefixlen)
        self.assertEqual("2001:500:88:200::", l.forwarded()[1].getlayer(ICMPv6NDOptPrefixInfo).prefix)

    def test_it_should_not_forward_neighbour_solicitations(self):
        l = Link('A')
        m = Link('B')
        r = TestRouter('TNN',   link0=l, ll_addr0="00:b0:d0:86:bb:f7", ips0=[IPAddress.identify("2001:500:88:200::10"), IPAddress.identify("2001:500:88:200::11"), IPAddress.identify("fe80:500:88:200::10"), IPAddress.identify("192.0.43.10")],
                                link1=m, ll_addr1="00:b0:d0:86:bb:f8", ips1=[IPAddress.identify("2001:600:88:200::10"), IPAddress.identify("2001:600:88:200::11"), IPAddress.identify("fe80:600:88:200::10"), IPAddress.identify("192.1.43.10")])

        l.accept(IPv6(src="fe80:500:88:200::20", dst="ff02::2")/ICMPv6ND_NS())

        self.assertEqual(0, len(m.forwarded()))

    def test_it_should_not_forward_neighbour_advertisements(self):
        l = Link('A')
        m = Link('B')
        r = TestRouter('TNN',   link0=l, ll_addr0="00:b0:d0:86:bb:f7", ips0=[IPAddress.identify("2001:500:88:200::10"), IPAddress.identify("2001:500:88:200::11"), IPAddress.identify("fe80:500:88:200::10"), IPAddress.identify("192.0.43.10")],
                                link1=m, ll_addr1="00:b0:d0:86:bb:f8", ips1=[IPAddress.identify("2001:600:88:200::10"), IPAddress.identify("2001:600:88:200::11"), IPAddress.identify("fe80:600:88:200::10"), IPAddress.identify("192.1.43.10")])

        l.accept(IPv6(src="fe80:500:88:200::20", dst="ff02::2")/ICMPv6ND_NA())

        self.assertEqual(0, len(m.forwarded()))

    def test_it_should_not_forward_router_solicitations(self):
        l = Link('A')
        m = Link('B')
        r = TestRouter('TNN',   link0=l, ll_addr0="00:b0:d0:86:bb:f7", ips0=[IPAddress.identify("2001:500:88:200::10"), IPAddress.identify("2001:500:88:200::11"), IPAddress.identify("fe80:500:88:200::10"), IPAddress.identify("192.0.43.10")],
                                link1=m, ll_addr1="00:b0:d0:86:bb:f8", ips1=[IPAddress.identify("2001:600:88:200::10"), IPAddress.identify("2001:600:88:200::11"), IPAddress.identify("fe80:600:88:200::10"), IPAddress.identify("192.1.43.10")])

        l.accept(IPv6(src="fe80:500:88:200::20", dst="ff02::2")/ICMPv6ND_RS())
        
        self.assertFalse(any(map(lambda p: p.haslayer(ICMPv6ND_RS), m.forwarded())))

    def test_it_should_not_forward_router_advertisements(self):
        l = Link('A')
        m = Link('B')
        r = TestRouter('TNN',   link0=l, ll_addr0="00:b0:d0:86:bb:f7", ips0=[IPAddress.identify("2001:500:88:200::10"), IPAddress.identify("2001:500:88:200::11"), IPAddress.identify("fe80:500:88:200::10"), IPAddress.identify("192.0.43.10")],
                                link1=m, ll_addr1="00:b0:d0:86:bb:f8", ips1=[IPAddress.identify("2001:600:88:200::10"), IPAddress.identify("2001:600:88:200::11"), IPAddress.identify("fe80:600:88:200::10"), IPAddress.identify("192.1.43.10")])

        l.accept(IPv6(src="fe80:500:88:200::20", dst="ff02::2")/ICMPv6ND_RA())

        self.assertEqual(0, len(m.forwarded()))
        