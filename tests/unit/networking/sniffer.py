import unittest
from scapy.all import Ether, IPv6, TCP, UDP
from tests.mocks.networking import MockInterface
from time import sleep
from veripy.networking import Sniffer
from veripy.networking.arch import OSInterfaceAdapter


class SnifferTestCase(unittest.TestCase):

    def setUp(self):
        self.phy = MockInterface(OSInterfaceAdapter.get_physical_interfaces()[0], None)

    def tearDown(self):
        self.s.stop()
    
    
    def test_it_should_start_a_sniffer(self):
        self.s = TestSniffer(self.phy)
        self.s.start()
        
        self.assertTrue(self.s.isAlive())

        self.s.stop()
    
    def test_it_should_pause_a_sniffer(self):
        self.s = TestSniffer(self.phy)
        self.s.start()
        sleep(1.5)
        self.s.pause()
        
        self.assertTrue(self.s.paused())

        self.s.stop()
    
    def test_it_should_resume_a_sniffer(self):
        self.s = TestSniffer(self.phy)
        self.s.start()
        sleep(1.5)
        self.s.pause()
        sleep(1.5)
        self.s.resume()

        self.assertTrue(self.s.sniffing())

        self.s.stop()
    
    def test_it_should_stop_a_sniffer(self):
        self.s = TestSniffer(self.phy)
        self.s.start()
        
        self.assertTrue(self.s.isAlive())
        
        self.s.stop()

        self.assertFalse(self.s.isAlive())
    
    def test_it_should_reset_a_sniffer(self):
        self.s = TestSniffer(self.phy)
        self.s.start()
        sleep(1.5)

        self.assertNotEqual(0, len(self.s.pcap()))

        self.s.reset()

        self.assertEqual(0, len(self.s.pcap()))

        self.s.stop()

    def test_it_should_reset_a_paused_sniffer(self):
        self.s = TestSniffer(self.phy)
        self.s.start()
        sleep(1.5)
        self.s.pause()

        self.assertNotEqual(0, len(self.s.pcap()))

        self.s.reset()

        self.assertEqual(0, len(self.s.pcap()))

        self.s.stop()

    def test_it_should_flush_a_sniffer(self):
        self.s = TestSniffer(self.phy)
        self.s.start()
        
        sleep(1.5)
        
        ctr_b = self.s._Sniffer__ctr
        self.assertTrue(self.s.flush())
        ctr_a = self.s._Sniffer__ctr
        
        self.assertNotEqual(ctr_b, ctr_a)
        
        self.s.stop()
    
    def test_it_should_not_flush_a_paused_sniffer(self):
        self.s = TestSniffer(self.phy)
        self.s.start()
        self.s.pause()
        
        self.assertFalse(self.s.flush())

        self.s.stop()
    
    def test_it_should_not_flush_a_stopped_sniffer(self):
        self.s = TestSniffer(self.phy)
        self.s.start()
        self.s.stop()

        self.assertFalse(self.s.flush())
    
    def test_it_should_flush_a_sniffer_asynchronously(self):
        self.s = TestSniffer(self.phy)
        self.s.start()
        
        self.assertTrue(self.s.flush_asynchronously())
        self.assertTrue(self.s.flushing())
        
        while self.s.flushing():
            pass

        self.s.stop()


class TestSniffer(Sniffer):

    def sniff(self, iface, timeout):
        sleep(timeout)

        return [(Ether()/IPv6()/UDP()), (Ether()/IPv6()/TCP()), (Ether()/IPv6()/UDP())]
    