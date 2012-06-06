import unittest
from scapy.all import ICMPv6EchoReply, ICMPv6EchoRequest, IPv6
from tests.mocks.cli import MockCallbacks
from tests.mocks.networking import MockInterface
from tests.mocks.test_network import MockTap, MockTargetInterface, TestNetworkConfiguration
from veripy.models import TestNetwork


class ComplianceTestTestCase(unittest.TestCase):

    def setUp(self):
        self.test_network = TestNetwork(TestNetworkConfiguration())

        # replace the network taps with mocked taps, referencing mocked network
        # and target interfaces
        self.test_network._TestNetwork__taps[0].unbind()
        self.test_network._TestNetwork__taps[1].unbind()
        
        self.t1 = self.test_network._TestNetwork__taps[0] = MockTap(self.test_network.link(2),
                                                                MockInterface('if0', 'be:ef:ca:fe:09:01'),
                                                                MockTargetInterface(ips=["2001:800:88:200::50", "fe80::50"], ll_protocol='Ethernet', link_addr='be:ef:ba:be:09:01'))
        self.t2 = self.test_network._TestNetwork__taps[1] = MockTap(self.test_network.link(3),
                                                                MockInterface('if1', 'be:ef:ca:fe:09:02'),
                                                                MockTargetInterface(ips=["2001:900:88:200::50", "fe80::51"], ll_protocol='Ethernet', link_addr='be:ef:ba:be:09:02'))
        
        # grab references to the target interfaces and internal nodes for easy
        # reference throughout a test case
        self.ifx = self.test_network.tap(1).target_iface
        self.ify = self.test_network.tap(2).target_iface
        
        self.tn1 = self.test_network.node(1)
        self.tn2 = self.test_network.node(2)
        self.tn3 = self.test_network.node(3)
        self.tn4 = self.test_network.node(4)

        self.tr1 = self.test_network.router(1)
        # TODO: tr2 and tr3
        
        def _received_on_tn1(iface=0, src=None, dst=None, lbda=None, seq=None, type=None, timeout=5):
            return self.tn1.iface(iface).received(src=src, dst=dst == None and self.tn1.ip(iface=iface, offset='*', scope='*', type='*') or dst, lbda=lbda, seq=None, type=type)
        def _received_on_tn2(iface=0, src=None, dst=None, lbda=None, seq=None, type=None, timeout=5):
            return self.tn2.iface(iface).received(src=src, dst=dst == None and self.tn2.ip(iface=iface, offset='*', scope='*', type='*') or dst, lbda=lbda, seq=None, type=type)
        def _received_on_tn3(iface=0, src=None, dst=None, lbda=None, seq=None, type=None, timeout=5):
            return self.tn3.iface(iface).received(src=src, dst=dst == None and self.tn3.ip(iface=iface, offset='*', scope='*', type='*') or dst, lbda=lbda, seq=None, type=type)
        def _received_on_tn4(iface=0, src=None, dst=None, lbda=None, seq=None, type=None, timeout=5):
            return self.tn4.iface(iface).received(src=src, dst=dst == None and self.tn4.ip(iface=iface, offset='*', scope='*', type='*') or dst, lbda=lbda, seq=None, type=type)
        # override the #received() method on each of the TRs and TNs, to remove
        # the delay introduced
        self.tn1.received = _received_on_tn1
        self.tn2.received = _received_on_tn2
        self.tn3.received = _received_on_tn3
        self.tn4.received = _received_on_tn4

        self.ui = MockCallbacks(None)
        self.ui.test_network = self.test_network

    def assertCheckFails(self, outcome):
        messages = (not outcome.message == None and " Said: " + str(outcome.message) or "")
        if outcome.result_string() == "Error":
            messages += "\n" + outcome.backtrace

        self.assertEqual(False, outcome.result, "Expected compliance test to FAIL. Got: " + outcome.result_string() + "." + messages)
        
    def assertCheckPasses(self, outcome):
        messages = (not outcome.message == None and " Said: " + str(outcome.message) or "")
        if outcome.result_string() == "Error":
            messages += "\n" + outcome.backtrace

        self.assertEqual(True, outcome.result, "Expected compliance test to PASS. Got: " + outcome.result_string() + "." + messages)

    def break_checksum(self, packet):
        b = IPv6(packet.build())

        if b.haslayer(ICMPv6EchoReply):
            b.getlayer(ICMPv6EchoReply).cksum = None
        elif b.haslayer(ICMPv6EchoRequest):
            b.getlayer(ICMPv6EchoRequest).cksum = None

        return b
    
    def get_outcome(self, test_case):
        return self.prepare(test_case).run_case()
    
    def prepare(self, test_case):
        c = test_case(self.test_network, self.ui)

        c.send_on_set_up = self.send_on_set_up

        return c

    def send_on_set_up(self):
        self.ui.wait(0)
        
