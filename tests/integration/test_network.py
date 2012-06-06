import unittest
from libs.ipcalc import Network
from scapy.all import Ether, ICMPv6EchoReply, ICMPv6EchoRequest, IPv6
from veripy.models import IPAddress, Tap, TargetInterface, TestNetwork
from tests.mocks.networking import MockInterface
from tests.mocks.test_network import TestNetworkConfiguration


class TestNetworkTestCase(unittest.TestCase):

    def setUp(self):
        self.n = TestNetwork(TestNetworkConfiguration())
        
        self.n._TestNetwork__taps[0].unbind()
        self.n._TestNetwork__taps[1].unbind()

        self.n.node(1).if0.ips.append(IPAddress.identify("2001:500:88:200::10"))
        self.n.node(1).if0.ips.append(IPAddress.identify("fe80:500:88:200::10"))
        self.n.node(2).if0.ips.append(IPAddress.identify("2001:600:88:200::10"))
        self.n.node(2).if0.ips.append(IPAddress.identify("fe80:600:88:200::10"))
        self.n.node(3).if0.ips.append(IPAddress.identify("2001:600:88:200::11"))
        self.n.node(3).if0.ips.append(IPAddress.identify("fe80:600:88:200::11"))
        self.n.node(4).if0.ips.append(IPAddress.identify("2001:700:88:200::10"))
        self.n.node(4).if0.ips.append(IPAddress.identify("fe80:700:88:200::10"))

        self.n.router(1).if0.ips.append(IPAddress.identify("2001:600:88:200::1"))
        self.n.router(1).if0.ips.append(IPAddress.identify("fe80:600:88:200::1"))
        self.n.router(1).if1.ips.append(IPAddress.identify("2001:500:88:200::1"))
        self.n.router(1).if1.ips.append(IPAddress.identify("fe80:500:88:200::1"))

        self.n.router(1)._TestRouter__forwards_to_0.append(Network("2001:0600:0088:0200::/64"))
        self.n.router(1)._TestRouter__forwards_to_1.append(Network("2001:0500:0088:0200::/64"))

        self.n.router(2).if0.ips.append(IPAddress.identify("2001:600:88:200::2"))
        self.n.router(2).if0.ips.append(IPAddress.identify("fe80:600:88:200::2"))
        self.n.router(2).if1.ips.append(IPAddress.identify("2001:500:88:200::2"))
        self.n.router(2).if1.ips.append(IPAddress.identify("fe80:500:88:200::2"))

        self.n.router(3).if0.ips.append(IPAddress.identify("2001:600:88:200::3"))
        self.n.router(3).if0.ips.append(IPAddress.identify("fe80:600:88:200::3"))
        self.n.router(3).if1.ips.append(IPAddress.identify("2001:500:88:200::3"))
        self.n.router(3).if1.ips.append(IPAddress.identify("fe80:500:88:200::3"))

        self.ethx_s = MockInterface('if0', '00:b0:d0:86:bb:f7')
        self.ethx_t = TargetInterface(ips=[IPAddress.identify("2001:500:88:200::20"), IPAddress.identify("fe80:500:88:200::20")], link_addr="00:b0:d0:bb:cc:ff")
        self.ethx = Tap(self.n.link(2), self.ethx_s, self.ethx_t)

        self.ethy_s = MockInterface('if1', '00:b0:e0:86:bb:f7')
        self.ethy_t = TargetInterface(ips=[IPAddress.identify("2001:600:88:200::20"), IPAddress.identify("fe80:600:88:200::20")], link_addr="00:b0:e0:bb:cc:ff")
        self.ethy = Tap(self.n.link(3), self.ethy_s, self.ethy_t)


    def test_it_should_deliver_a_packet_from_tn1_on_ethx(self):
        self.n.node(1).send(IPv6(src=str(self.n.node(1).global_ip()), dst=str(self.ethx_t.global_ip()))/ICMPv6EchoRequest())

        self.assertEqual(1, len(self.ethx_s.sent))

        p = self.ethx_s.sent[0]

        self.assertTrue(p.haslayer(Ether))
        self.assertEqual('00:b0:d0:86:bb:f7', p.getlayer(Ether).src)
        self.assertEqual('00:b0:d0:bb:cc:ff', p.getlayer(Ether).dst)

        self.assertTrue(p.haslayer(IPv6))
        self.assertEqual(self.n.node(1).global_ip().short_form(), p.getlayer(IPv6).src)
        self.assertEqual(self.ethx_t.global_ip().short_form(), p.getlayer(IPv6).dst)

        self.assertTrue(self.ethx_s.sent[0].haslayer(ICMPv6EchoRequest))

    def test_it_should_deliver_a_link_local_packet_from_tn1_to_ethx(self):
        self.n.node(1).send(IPv6(src=str(self.n.node(1).link_local_ip()), dst=str(self.ethx_t.link_local_ip()))/ICMPv6EchoRequest())

        self.assertEqual(1, len(self.ethx_s.sent))

        p = self.ethx_s.sent[0]

        self.assertTrue(p.haslayer(Ether))
        self.assertEqual('00:b0:d0:86:bb:f7', p.getlayer(Ether).src)
        self.assertEqual('00:b0:d0:bb:cc:ff', p.getlayer(Ether).dst)

        self.assertTrue(p.haslayer(IPv6))
        self.assertEqual(self.n.node(1).link_local_ip().short_form(), p.getlayer(IPv6).src)
        self.assertEqual(self.ethx_t.link_local_ip().short_form(), p.getlayer(IPv6).dst)

        self.assertTrue(self.ethx_s.sent[0].haslayer(ICMPv6EchoRequest))

    def test_it_should_not_deliver_a_packet_from_tn1_on_ethy(self):
        self.n.node(1).send(IPv6(src=str(self.n.node(1).link_local_ip()), dst=str(self.ethx_t.link_local_ip()))/ICMPv6EchoRequest())

        self.assertEqual(0, len(self.ethy_s.sent))

    def test_it_should_deliver_a_packet_from_tn2_on_ethx(self):
        self.n.node(2).send(IPv6(src=str(self.n.node(2).global_ip()), dst=str(self.ethx_t.global_ip()))/ICMPv6EchoRequest())

        self.assertEqual(1, len(self.ethx_s.sent))

        p = self.ethx_s.sent[0]

        self.assertTrue(p.haslayer(Ether))
        self.assertEqual('00:b0:d0:86:bb:f7', p.getlayer(Ether).src)
        self.assertEqual('00:b0:d0:bb:cc:ff', p.getlayer(Ether).dst)

        self.assertTrue(p.haslayer(IPv6))
        self.assertEqual(self.n.node(2).global_ip().short_form(), p.getlayer(IPv6).src)
        self.assertEqual(self.ethx_t.global_ip().short_form(), p.getlayer(IPv6).dst)

    def test_it_should_not_deliver_a_link_local_packet_from_tn2_on_ethx(self):
        self.n.node(2).send(IPv6(src=str(self.n.node(2).link_local_ip()), dst=str(self.ethx_t.link_local_ip()))/ICMPv6EchoRequest())

        self.assertEqual(0, len(self.ethx_s.sent))

    def test_it_should_not_deliver_a_packet_from_tn2_on_ethy(self):
        self.n.node(2).send(IPv6(src=str(self.n.node(2).link_local_ip()), dst=str(self.ethx_t.link_local_ip()))/ICMPv6EchoRequest())

        self.assertEqual(0, len(self.ethy_s.sent))

    def test_it_should_deliver_a_packet_from_tn3_on_ethx(self):
        self.n.node(3).send(IPv6(src=str(self.n.node(3).global_ip()), dst=str(self.ethx_t.global_ip()))/ICMPv6EchoRequest())

        self.assertEqual(1, len(self.ethx_s.sent))

        p = self.ethx_s.sent[0]

        self.assertTrue(p.haslayer(Ether))
        self.assertEqual('00:b0:d0:86:bb:f7', p.getlayer(Ether).src)
        self.assertEqual('00:b0:d0:bb:cc:ff', p.getlayer(Ether).dst)

        self.assertTrue(p.haslayer(IPv6))
        self.assertEqual(self.n.node(3).global_ip().short_form(), p.getlayer(IPv6).src)
        self.assertEqual(self.ethx_t.global_ip().short_form(), p.getlayer(IPv6).dst)

    def test_it_should_not_deliver_a_link_local_packet_from_tn3_on_ethx(self):
        self.n.node(3).send(IPv6(src=str(self.n.node(3).link_local_ip()), dst=str(self.ethx_t.link_local_ip()))/ICMPv6EchoRequest())

        self.assertEqual(0, len(self.ethx_s.sent))

    def test_it_should_not_deliver_a_packet_from_tn3_on_ethy(self):
        self.n.node(3).send(IPv6(src=str(self.n.node(3).link_local_ip()), dst=str(self.ethx_t.link_local_ip()))/ICMPv6EchoRequest())

        self.assertEqual(0, len(self.ethy_s.sent))

    def test_it_should_deliver_a_packet_from_tn4_on_ethy(self):
        self.n.node(4).send(IPv6(src=str(self.n.node(4).global_ip()), dst=str(self.ethy_t.global_ip()))/ICMPv6EchoRequest())

        self.assertEqual(1, len(self.ethy_s.sent))

        p = self.ethy_s.sent[0]

        self.assertTrue(p.haslayer(Ether))
        self.assertEqual('00:b0:e0:86:bb:f7', p.getlayer(Ether).src)
        self.assertEqual('00:b0:e0:bb:cc:ff', p.getlayer(Ether).dst)

        self.assertTrue(p.haslayer(IPv6))
        self.assertEqual(self.n.node(4).global_ip().short_form(), p.getlayer(IPv6).src)
        self.assertEqual(self.ethy_t.global_ip().short_form(), p.getlayer(IPv6).dst)

    def test_it_should_deliver_a_link_local_packet_from_tn4_on_ethy(self):
        self.n.node(4).send(IPv6(src=str(self.n.node(4).link_local_ip()), dst=str(self.ethy_t.link_local_ip()))/ICMPv6EchoRequest())

        self.assertEqual(1, len(self.ethy_s.sent))

        p = self.ethy_s.sent[0]

        self.assertTrue(p.haslayer(Ether))
        self.assertEqual('00:b0:e0:86:bb:f7', p.getlayer(Ether).src)
        self.assertEqual('00:b0:e0:bb:cc:ff', p.getlayer(Ether).dst)

        self.assertTrue(p.haslayer(IPv6))
        self.assertEqual(self.n.node(4).link_local_ip().short_form(), p.getlayer(IPv6).src)
        self.assertEqual(self.ethy_t.link_local_ip().short_form(), p.getlayer(IPv6).dst)

    def test_it_should_not_deliver_a_packet_from_tn4_on_ethx(self):
        self.n.node(4).send(IPv6(src=str(self.n.node(4).global_ip()), dst=str(self.ethy_t.global_ip()))/ICMPv6EchoRequest())

        self.assertEqual(0, len(self.ethx_s.sent))

    def test_it_should_deliver_a_packet_from_tr1_on_ethx(self):
        self.n.router(1).send(IPv6(src=str(self.n.router(1).global_ip()), dst=str(self.ethx_t.global_ip()))/ICMPv6EchoRequest(), iface=1)

        self.assertEqual(1, len(self.ethx_s.sent))

        p = self.ethx_s.sent[0]

        self.assertTrue(p.haslayer(Ether))
        self.assertEqual('00:b0:d0:86:bb:f7', p.getlayer(Ether).src)
        self.assertEqual('00:b0:d0:bb:cc:ff', p.getlayer(Ether).dst)

        self.assertTrue(p.haslayer(IPv6))
        self.assertEqual(self.n.router(1).global_ip().short_form(), p.getlayer(IPv6).src)
        self.assertEqual(self.ethx_t.global_ip().short_form(), p.getlayer(IPv6).dst)

    def test_it_should_deliver_a_link_local_packet_from_tr1_on_ethx(self):
        self.n.router(1).send(IPv6(src=str(self.n.router(1).link_local_ip()), dst=str(self.ethx_t.link_local_ip()))/ICMPv6EchoRequest(), iface=1)

        self.assertEqual(1, len(self.ethx_s.sent))

        p = self.ethx_s.sent[0]

        self.assertTrue(p.haslayer(Ether))
        self.assertEqual('00:b0:d0:86:bb:f7', p.getlayer(Ether).src)
        self.assertEqual('00:b0:d0:bb:cc:ff', p.getlayer(Ether).dst)

        self.assertTrue(p.haslayer(IPv6))
        self.assertEqual(self.n.router(1).link_local_ip().short_form(), p.getlayer(IPv6).src)
        self.assertEqual(self.ethx_t.link_local_ip().short_form(), p.getlayer(IPv6).dst)

    def test_it_should_not_deliver_a_packet_from_tr1_if0_to_ethx(self):
        self.n.router(1).send(IPv6(src=str(self.n.router(1).global_ip()), dst=str(self.ethx_t.global_ip()))/ICMPv6EchoRequest(), iface=0)

        self.assertEqual(0, len(self.ethx_s.sent))

    def test_it_should_not_deliver_a_packet_from_tr1_on_ethy(self):
        self.n.router(1).send(IPv6(src=str(self.n.router(1).link_local_ip(iface=1)), dst=str(self.ethx_t.link_local_ip()))/ICMPv6EchoRequest(), iface=1)

        self.assertEqual(0, len(self.ethy_s.sent))

    def test_it_should_deliver_a_packet_from_tr2_on_ethx(self):
        self.n.router(2).send(IPv6(src=str(self.n.router(2).link_local_ip(iface=1)), dst=str(self.ethx_t.link_local_ip()))/ICMPv6EchoRequest(), iface=1)

        self.assertEqual(0, len(self.ethy_s.sent))

    def test_it_should_deliver_a_packet_from_tr3_on_ethx(self):
        self.n.router(3).send(IPv6(src=str(self.n.router(3).link_local_ip(iface=1)), dst=str(self.ethx_t.link_local_ip()))/ICMPv6EchoRequest(), iface=1)

        self.assertEqual(1, len(self.ethx_s.sent))

    def test_it_should_deliver_a_packet_from_ethx_to_tn1(self):
        self.ethx_s.accept(IPv6(src=str(self.ethx_t.global_ip()), dst=str(self.n.node(1).global_ip()))/ICMPv6EchoReply())

        self.assertEqual(1, len(self.n.node(1).received()))

        p = self.n.node(1).received()[0]

        self.assertFalse(p.haslayer(Ether))

        self.assertTrue(p.haslayer(IPv6))
        self.assertEqual(self.ethx_t.global_ip().short_form(), p.getlayer(IPv6).src)
        self.assertEqual(self.n.node(1).global_ip().short_form(), p.getlayer(IPv6).dst)

    def test_it_should_deliver_a_link_local_packet_from_ethx_to_tn1(self):
        self.ethx_s.accept(IPv6(src=str(self.ethx_t.link_local_ip()), dst=str(self.n.node(1).link_local_ip()))/ICMPv6EchoReply())

        self.assertEqual(1, len(self.n.node(1).received()))

        p = self.n.node(1).received()[0]

        self.assertFalse(p.haslayer(Ether))

        self.assertTrue(p.haslayer(IPv6))
        self.assertEqual(self.ethx_t.link_local_ip().short_form(), p.getlayer(IPv6).src)
        self.assertEqual(self.n.node(1).link_local_ip().short_form(), p.getlayer(IPv6).dst)

    def test_it_should_not_deliver_a_packet_from_ethy_to_tn1(self):
        self.ethy_s.accept(IPv6(src=str(self.ethx_t.global_ip()), dst=str(self.n.node(1).global_ip()))/ICMPv6EchoReply())

        self.assertEqual(0, len(self.n.node(1).received()))

    def test_it_should_deliver_a_packet_from_ethx_to_tn2(self):
        self.ethx_s.accept(IPv6(src=str(self.ethx_t.global_ip()), dst=str(self.n.node(2).global_ip()))/ICMPv6EchoReply())
        
        self.assertEqual(1, len(self.n.node(2).received()))

        p = self.n.node(2).received()[0]

        self.assertFalse(p.haslayer(Ether))

        self.assertTrue(p.haslayer(IPv6))
        self.assertEqual(self.ethx_t.global_ip().short_form(), p.getlayer(IPv6).src)
        self.assertEqual(self.n.node(2).global_ip().short_form(), p.getlayer(IPv6).dst)

    def test_it_should_not_deliver_a_link_local_packet_from_ethx_to_tn2(self):
        self.ethx_s.accept(IPv6(src=str(self.ethx_t.link_local_ip()), dst=str(self.n.node(2).link_local_ip()))/ICMPv6EchoReply())

        self.assertEqual(0, len(self.n.node(2).received()))

    def test_it_should_not_deliver_a_packet_from_ethy_to_tn2(self):
        self.ethy_s.accept(IPv6(src=str(self.ethx_t.global_ip()), dst=str(self.n.node(2).global_ip()))/ICMPv6EchoReply())

        self.assertEqual(0, len(self.n.node(2).received()))

    def test_it_should_deliver_a_packet_from_ethx_to_tn3(self):
        self.ethx_s.accept(IPv6(src=str(self.ethx_t.global_ip()), dst=str(self.n.node(3).global_ip()))/ICMPv6EchoReply())

        self.assertEqual(1, len(self.n.node(3).received()))

        p = self.n.node(3).received()[0]

        self.assertFalse(p.haslayer(Ether))

        self.assertTrue(p.haslayer(IPv6))
        self.assertEqual(self.ethx_t.global_ip().short_form(), p.getlayer(IPv6).src)
        self.assertEqual(self.n.node(3).global_ip().short_form(), p.getlayer(IPv6).dst)

    def test_it_should_not_deliver_a_link_local_packet_from_ethx_to_tn3(self):
        self.ethx_s.accept(IPv6(src=str(self.ethx_t.link_local_ip()), dst=str(self.n.node(3).link_local_ip()))/ICMPv6EchoReply())

        self.assertEqual(0, len(self.n.node(3).received()))

    def test_it_should_not_deliver_a_packet_from_ethy_to_tn3(self):
        self.ethy_s.accept(IPv6(src=str(self.ethx_t.global_ip()), dst=str(self.n.node(3).global_ip()))/ICMPv6EchoReply())

        self.assertEqual(0, len(self.n.node(3).received()))

    def test_it_should_deliver_a_packet_from_ethy_to_tn4(self):
        self.ethy_s.accept(IPv6(src=str(self.ethy_t.global_ip()), dst=str(self.n.node(4).global_ip()))/ICMPv6EchoReply())

        self.assertEqual(1, len(self.n.node(4).received()))

        p = self.n.node(4).received()[0]

        self.assertFalse(p.haslayer(Ether))

        self.assertTrue(p.haslayer(IPv6))
        self.assertEqual(self.ethy_t.global_ip().short_form(), p.getlayer(IPv6).src)
        self.assertEqual(self.n.node(4).global_ip().short_form(), p.getlayer(IPv6).dst)

    def test_it_should_deliver_a_link_local_packet_from_ethy_to_tn4(self):
        self.ethy_s.accept(IPv6(src=str(self.ethy_t.link_local_ip()), dst=str(self.n.node(4).link_local_ip()))/ICMPv6EchoReply())

        self.assertEqual(1, len(self.n.node(4).received()))

        p = self.n.node(4).received()[0]

        self.assertFalse(p.haslayer(Ether))

        self.assertTrue(p.haslayer(IPv6))
        self.assertEqual(self.ethy_t.link_local_ip().short_form(), p.getlayer(IPv6).src)
        self.assertEqual(self.n.node(4).link_local_ip().short_form(), p.getlayer(IPv6).dst)

    def test_it_should_not_deliver_a_packet_from_ethx_to_tn4(self):
        self.ethx_s.accept(IPv6(src=str(self.ethy_t.global_ip()), dst=str(self.n.node(4).global_ip()))/ICMPv6EchoReply())

        self.assertEqual(0, len(self.n.node(4).received()))

    def test_it_should_deliver_a_packet_from_ethx_to_tr1(self):
        self.ethx_s.accept(IPv6(src=str(self.ethx_t.global_ip()), dst=str(self.n.router(1).global_ip(iface=1)))/ICMPv6EchoReply())

        self.assertEqual(1, len(self.n.router(1).received(iface=1)))

        p = self.n.router(1).received(iface=1)[0]

        self.assertFalse(p.haslayer(Ether))

        self.assertTrue(p.haslayer(IPv6))
        self.assertEqual(self.ethx_t.global_ip().short_form(), p.getlayer(IPv6).src)
        self.assertEqual(self.n.router(1).global_ip(iface=1).short_form(), p.getlayer(IPv6).dst)

    def test_it_should_deliver_a_link_local_packet_from_ethx_to_tr1(self):
        self.ethx_s.accept(IPv6(src=str(self.ethx_t.link_local_ip()), dst=str(self.n.router(1).link_local_ip(iface=1)))/ICMPv6EchoReply())

        self.assertEqual(1, len(self.n.router(1).received(iface=1)))

        p = self.n.router(1).received(iface=1)[0]

        self.assertFalse(p.haslayer(Ether))

        self.assertTrue(p.haslayer(IPv6))
        self.assertEqual(self.ethx_t.link_local_ip().short_form(), p.getlayer(IPv6).src)
        self.assertEqual(self.n.router(1).link_local_ip(iface=1).short_form(), p.getlayer(IPv6).dst)

    def test_it_should_not_deliver_a_packet_from_ethy_to_tr1(self):
        self.ethy_s.accept(IPv6(src=str(self.ethx_t.global_ip()), dst=str(self.n.router(1).global_ip(iface=1)))/ICMPv6EchoReply())

        self.assertEqual(0, len(self.n.router(1).received()))

    def test_it_should_deliver_a_packet_from_ethx_to_tr2(self):
        self.ethx_s.accept(IPv6(src=str(self.ethx_t.global_ip()), dst=str(self.n.router(2).global_ip(iface=1)))/ICMPv6EchoReply())

        self.assertEqual(1, len(self.n.router(2).received(iface=1)))

    def test_it_should_deliver_a_packet_from_ethx_to_tr3(self):
        self.ethx_s.accept(IPv6(src=str(self.ethx_t.global_ip()), dst=str(self.n.router(3).global_ip(iface=1)))/ICMPv6EchoReply())

        self.assertEqual(1, len(self.n.router(3).received(iface=1)))
