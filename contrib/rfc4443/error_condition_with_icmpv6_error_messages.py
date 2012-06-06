from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase


class FlawedDstUnreachableCode0WithDestinationUnreachableTestCase(ComplianceTestCase):
    """
    Error Condition With ICMPv6 Error Message - Reception of Flawed Destination
    Unreachable Code 0 with Address Unreachable
    
    Verify that a router properly handles the reception and processing of an
    ICMPv6 Error Message that invokes an error.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Test (v6LC.5.1.9a)

    """
    
    def run(self):
        self.logger.info("Sending errorr message to NUT")
        self.node(1).send( \
            IPv6(src=str(self.node(1).global_ip()), dst="fe80::abba")/
                ICMPv6DestUnreach(code=0))
        
        self.logger.info("Checking for reply")
        r1 = self.node(1).received(type=ICMPv6DestUnreach)

        assertEqual(0, len(r1), "did not expect to receive an ICMPv6 Destination Unreachable message")
        
        
class FlawedDstUnreachableCode3WithHopLimit0TestCase(ComplianceTestCase):
    """
    Error Condition With ICMPv6 Error Message - Reception of Flawed Destination
    Unreachable Code 3 with Hop Limit = 0

    Verify that a router properly handles the reception and processing of an
    ICMPv6 Error Message that invokes an error.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Test (v6LC.5.1.9b)
    """
    
    def run(self):
        self.logger.info("Sending error message to NUT")
        self.node(1).send( \
            IPv6(src=str(self.node(1).global_ip()), dst=str(self.node(4).global_ip()), hlim=0)/
                ICMPv6DestUnreach(code=3))
        
        self.logger.info("Checking for reply")
        r1 = self.node(1).received(type=ICMPv6TimeExceeded)

        assertEqual(0, len(r1), "did not expect to receive an ICMPv6 Time Exceeded message")
        
        
class FlawedTimeExceededCode0WithNoRouteToDestinationTestCase(ComplianceTestCase):
    """
    Error Condition With ICMPv6 Error Message - Reception of Flawed Time
    Exceeded Code 0 with No Route to Destination

    Verify that a router properly handles the reception and processing of an
    ICMPv6 Error Message that invokes an error.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Test (v6LC.5.1.9c)

    """

    def run(self):
        self.logger.info("Sending errorr message to NUT")
        self.node(1).send( \
            IPv6(src=str(self.node(1).global_ip()), dst="abcd::1")/
                ICMPv6TimeExceeded(code=0))
        
        self.logger.info("Checking for reply")
        r1 = self.node(1).received(type=ICMPv6DestUnreach)

        assertEqual(0, len(r1), "did not expect to receive an ICMPv6 Destination Unreachable message")


class FlawedTimeExceededCode1WithNoRouteToDestinationTestCase(ComplianceTestCase):
    """
    Error Condition With ICMPv6 Error Message - Reception of Flawed Time
    Exceeded Code 1 with No Route to Destination

    Verify that a router properly handles the reception and processing of an
    ICMPv6 Error Message that invokes an error.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Test (v6LC.5.1.9d)
    """

    def run(self):
        self.logger.info("Sending errorr message to NUT")
        self.node(1).send( \
            IPv6(src=str(self.node(1).global_ip()), dst="abcd::1")/
                ICMPv6TimeExceeded(code=1))
        
        self.logger.info("Checking for reply")
        r1 = self.node(1).received(type=ICMPv6DestUnreach)
        
        assertEqual(0, len(r1), "did not expect to receive an ICMPv6 Destination Unreachable message")
        
        
class FlawedDstPacketTooBigWithAddressUnreachableTestCase(ComplianceTestCase):
    """
    Error Condition With ICMPv6 Error Message - Reception of Flawed Packet Too
    Big with Addres Unreachable

    Verify that a router properly handles the reception and processing of an
    ICMPv6 Error Message that invokes an error.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Test (v6LC.5.1.9e)
    """
    
    def run(self):
        self.logger.info("Sending errorr message to NUT")
        self.node(1).send( \
            IPv6(src=str(self.node(1).global_ip()), dst="fe80::abba")/
                ICMPv6PacketTooBig())
                
        self.logger.info("Checking for reply")
        r1 = self.node(1).received(type=ICMPv6DestUnreach)

        assertEqual(0, len(r1), "did not expect to receive an ICMPv6 Destination Unreachable message")

        
class FlawedParamProblemWithHopLimit0TestCase(ComplianceTestCase):
    """
    Error Condition With ICMPv6 Error Message - Reception of Flawed Parameter
    Problem with Hop Limit = 0

    Verify that a router properly handles the reception and processing of an
    ICMPv6 Error Message that invokes an error.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Test (v6LC.5.1.9f)
    """

    def run(self):
        self.logger.info("Sending errorr message to NUT")
        self.node(1).send( \
            IPv6(src=str(self.node(1).global_ip()), dst=str(self.target(1).global_ip()), hlim=0)/
                ICMPv6ParamProblem())
        
        self.logger.info("Checking for reply")
        r1 = self.node(1).received(type=ICMPv6TimeExceeded)

        assertEqual(0, len(r1), "did not expect to receive an ICMPv6 Time Exceeded message")
        