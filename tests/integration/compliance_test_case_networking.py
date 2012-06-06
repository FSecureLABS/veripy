import unittest
from tests.mocks.test_network import TestNetworkConfiguration
from veripy.models import ComplianceTestCase, TestNetwork


class ComplianceTestCaseNetworkingTestCase(unittest.TestCase):
    
    def test_it_should_expose_links_of_the_test_network(self):
        n = TestNetwork(TestNetworkConfiguration())

        n._TestNetwork__taps[0].unbind()
        n._TestNetwork__taps[1].unbind()

        c = ComplianceTestCase(n, None)

        self.assertEqual(3, len(c.links()))
        self.assertEqual('A', c.link(1).name)
        self.assertEqual('B', c.link(2).name)
        self.assertEqual('C', c.link(3).name)

    def test_it_should_expose_nodes_of_the_test_network(self):
        n = TestNetwork(TestNetworkConfiguration())

        n._TestNetwork__taps[0].unbind()
        n._TestNetwork__taps[1].unbind()

        c = ComplianceTestCase(n, None)

        self.assertEqual(4, len(c.nodes()))
        self.assertEqual('TN1', c.node(1).name)
        self.assertEqual('TN2', c.node(2).name)
        self.assertEqual('TN3', c.node(3).name)
        self.assertEqual('TN4', c.node(4).name)

    def test_it_should_expose_routers_or_the_test_network(self):
        n = TestNetwork(TestNetworkConfiguration())

        n._TestNetwork__taps[0].unbind()
        n._TestNetwork__taps[1].unbind()

        c = ComplianceTestCase(n, None)

        self.assertEqual(3, len(c.routers()))
        self.assertEqual('TR1', c.router(1).name)
        self.assertEqual('TR2', c.router(2).name)
        self.assertEqual('TR3', c.router(3).name)
