from contrib.rfc4213 import encapsulation as suite
from scapy.all import *
from veripy.testability import ComplianceTestTestCase

class EncapsulationTestCase(ComplianceTestTestCase):

    def setUp(self):
        super(EncapsulationTestCase, self).setUp()

        self.tn1.iface(0).ips.append("192.168.0.1")
        self.tn1.iface(0).ips.append("2002:c0a8:1::1")
        self.ifx.ips.append("192.168.0.5")
        self.ifx.ips.append("2002:c0a8:5::1")

        self.u = IPv6(src=str(self.ifx.ip(type="6in4")), dst=str(self.tn1.ip(type="6in4")))/ICMPv6EchoReply()
        self.e = IP(src=str(self.ifx.ip(type="v4")), dst=str(self.tn1.ip(type="v4")))/IPv6(src=str(self.ifx.ip(type="6in4")), dst=str(self.tn1.ip(type="6in4")))/ICMPv6EchoReply()

    def test_correct_encapsulation(self):
        if self.__class__.__name__ == "EncapsulationTestCase": return
        
        self.ifx.replies_with(IP(self.e.build()))

        o = self.get_outcome(getattr(suite, self.__class__.__name__))

        self.assertCheckPasses(o)


class IPv4HeaderAddedTestCase(EncapsulationTestCase):
    
    def test_ipv4_header_not_added(self):
        self.ifx.replies_with(self.u)

        o = self.get_outcome(suite.IPv4HeaderAddedTestCase)

        self.assertCheckFails(o)


class CorrectVersionFieldTestCase(EncapsulationTestCase):
        
    def test_incorrect_version_field(self):
        self.e.getlayer(IP).version = 5
        self.ifx.replies_with(self.e)

        o = self.get_outcome(suite.CorrectVersionFieldTestCase)

        self.assertCheckFails(o)


class CorrectLengthFieldTestCase(EncapsulationTestCase):

    def test_incorrect_length_field(self):
        self.e.getlayer(IP).len = 20
        self.ifx.replies_with(self.e)

        o = self.get_outcome(suite.CorrectLengthFieldTestCase)

        self.assertCheckFails(o)

class CorrectProtocolFieldTestCase(EncapsulationTestCase):

    def test_incorrect_protocol_field(self):
        self.e.getlayer(IP).proto = 0
        self.ifx.replies_with(self.e)

        o = self.get_outcome(suite.CorrectProtocolFieldTestCase)

        self.assertCheckFails(o)


class CorrectIPv4SourceAddressTestCase(EncapsulationTestCase):
    
    def test_incorrect_ipv4_source_address(self):
        self.e.getlayer(IP).src = self.e.getlayer(IP).dst
        self.ifx.replies_with(self.e)

        o = self.get_outcome(suite.CorrectIPv4SourceAddressTestCase)

        self.assertCheckFails(o)


class CorrectIPv4DestinationAddressTestCase(EncapsulationTestCase):

    def test_incorrect_ipv4_destination_address(self):
        self.e.getlayer(IP).dst = self.e.getlayer(IP).src
        self.ifx.replies_with(self.e)

        o = self.get_outcome(suite.CorrectIPv4DestinationAddressTestCase)

        self.assertCheckFails(o)


class CorrectIPv6SourceAddressTestCase(EncapsulationTestCase):

    def test_incorrect_ipv6_source_address(self):
        self.e.getlayer(IPv6).src = self.e.getlayer(IPv6).dst
        self.ifx.replies_with(self.e)

        o = self.get_outcome(suite.CorrectIPv6SourceAddressTestCase)

        self.assertCheckFails(o)


class CorrectIPv6DestinationAddressTestCase(EncapsulationTestCase):
    
    def test_incorrect_ipv6_destination_address(self):
        self.e.getlayer(IPv6).dst = self.e.getlayer(IPv6).src
        self.ifx.replies_with(self.e)

        o = self.get_outcome(suite.CorrectIPv6DestinationAddressTestCase)

        self.assertCheckFails(o)
