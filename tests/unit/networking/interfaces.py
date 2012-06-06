from scapy.all import *
from tests.mocks.networking import MockSniffer
import unittest
from veripy.networking import Base as NetworkInterface


class NetworkInterfaceTestCase(unittest.TestCase):

    def setUp(self):
        self.phy = 'if0'
    
    def test_it_should_create_a_network_interface_on_a_specified_physical_interface(self):
        i = TestNetworkInterface(self.phy, "de:ad:be:ef:01:02")
        
        self.assertEqual(self.phy, i.interface())

    def test_it_should_have_a_link_layer_address(self):
        i = TestNetworkInterface(self.phy, "de:ad:be:ef:01:02")
        
        self.assertEqual("de:ad:be:ef:01:02", i.ll_addr())

    def test_it_should_get_an_instance_for_a_given_interface(self):
        i = NetworkInterface.get_instance(self.phy, "de:ad:be:ef:01:02")

        self.assertTrue(isinstance(i, NetworkInterface))
        self.assertEqual(self.phy, i.interface())

    def test_it_should_maintain_singletons_for_each_interface(self):
        i = NetworkInterface.get_instance(self.phy, "de:ad:be:ef:01:02")
        j = NetworkInterface.get_instance(self.phy, "de:ad:be:ef:01:02")

        self.assertEqual(id(i), id(j))

    def test_it_should_return_a_list_of_physical_interfaces(self):
        i = NetworkInterface.get_physical_interfaces()

        self.assertTrue(isinstance(i, list))
        self.assertTrue(len(i) > 0)

    def test_it_should_allow_an_on_receive_callback_to_be_registered(self):
        i = NetworkInterface.get_instance(self.phy, "de:ad:be:ef:01:02")

        def callback(packet):
            pass

        i.on_receive(callback)

        self.assertEqual(1, len(i._Base__on_receive_callbacks))
        self.assertEqual(callback, i._Base__on_receive_callbacks[0])

    def test_it_should_invoke_on_receive_callbacks_after_accepting_a_packet(self):
        i = NetworkInterface.get_instance(self.phy, "de:ad:be:ef:01:02")

        self.called_with = None
        def callback(packet):
            self.called_with = packet

        i.on_receive(callback)

        i.accept('packet!')

        self.assertEqual('packet!', self.called_with)

    def test_it_should_invoke_on_receive_callbacks_after_accepting_packets(self):
        i = NetworkInterface.get_instance(self.phy, "de:ad:be:ef:01:02")

        self.called_with = None
        def callback(packet):
            self.called_with = packet

        i.on_receive(callback)

        i.accept(['packet!'])

        self.assertEqual(['packet!'], self.called_with)
    
    def test_it_should_send_packets(self):
        i = TestNetworkInterface(self.phy, "de:ad:be:ef:01:02")
        p = Ether()/IPv6()/ICMPv6EchoRequest()
        
        i.send(p)

        self.assertEqual(1, len(i.sent))
        self.assertEqual(p, i.sent[0])

    def test_it_should_return_true_if_packets_were_answered(self):
        i = TestNetworkInterface(self.phy, "de:ad:be:ef:01:02")
        p = Ether()/IPv6()/ICMPv6EchoRequest()
        
        i.srp_replies_with = [Ether()/IPv6()/ICMPv6EchoReply()]

        self.assertTrue(i.send(p))

    def test_it_should_return_false_if_packets_were_unanswered(self):
        i = TestNetworkInterface(self.phy, "de:ad:be:ef:01:02")
        p = Ether()/IPv6()/ICMPv6EchoRequest()

        self.assertFalse(i.send(p))

    def test_it_should_fetch_the_full_packet_capture(self):
        i = TestNetworkInterface(self.phy, "de:ad:be:ef:01:02")
        s = MockSniffer(self.phy)
        s._MockSniffer__pcap = [["the pcap data"]]
        i._Base__sniffer = s

        self.assertEqual(1, len(i.pcap()))
        self.assertEqual("the pcap data", i.pcap()[0])
    
    def test_it_should_flush_the_interfaces_sniffer(self):
        i = TestNetworkInterface(self.phy, "de:ad:be:ef:01:02")
        s = MockSniffer(self.phy)
        i._Base__sniffer = s

        i.flush_sniffer()

        self.assertTrue(s._flush)
    
    def test_it_should_flush_the_interfaces_sniffer_asynchronously(self):
        i = TestNetworkInterface(self.phy, "de:ad:be:ef:01:02")
        s = MockSniffer(self.phy)
        i._Base__sniffer = s
        
        i.flush_sniffer_asynchronously()
        i.flushing_sniffer()
        
        self.assertTrue(s._flush_asynchronously)
        self.assertTrue(s._flushing)
                

class TestNetworkInterface(NetworkInterface):

    def __init__(self, interface, ll_addr):
        super(TestNetworkInterface, self).__init__(interface, ll_addr)
        
        self.sent = []
        self.srp_replies_with = []
    
    def srp(self, frame, timeout=1):
        self.sent.append(frame)
        
        return [self.srp_replies_with, []]
    