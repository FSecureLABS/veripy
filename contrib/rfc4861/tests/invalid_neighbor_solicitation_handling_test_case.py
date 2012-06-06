from contrib.rfc4861 import invalid_neighbor_solicitation_handling as suite
from scapy.all import *
from veripy.testability import ComplianceTestTestCase
from veripy.assertions import *

class InvalidNeighborSolicitationHandlingInvalidChecksumTestCaseTestCase(ComplianceTestTestCase):
    
    def test_invalid_neighbor_solicitation_handling_no_reply(self):
        o = self.get_outcome(suite.InvalidNeighborSolicitationHandlingInvalidChecksumTestCase)
        
        self.assertCheckPasses(o)
        
    def test_invalid_neighbor_solicitation_handling_reply_1(self):
        
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NA())
        
        o = self.get_outcome(suite.InvalidNeighborSolicitationHandlingInvalidChecksumTestCase)
        
        self.assertCheckFails(o)
        
    def test_invalid_neighbor_solicitation_handling_reply_2(self):
        
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ND_NA())
                
        o = self.get_outcome(suite.InvalidNeighborSolicitationHandlingInvalidChecksumTestCase)
        
        self.assertCheckFails(o)
        
class InvalidNeighborSolicitationHandlingInvalidDestinationAddressTestCaseTestCase(ComplianceTestTestCase):
    
    def test_invalid_neighbor_solicitation_handling_no_reply(self):
        o = self.get_outcome(suite.InvalidNeighborSolicitationHandlingInvalidDestinationAddressTestCase)
        
        self.assertCheckPasses(o)
        
    def test_invalid_neighbor_solicitation_handling_reply_1(self):
        
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NA())
        
        o = self.get_outcome(suite.InvalidNeighborSolicitationHandlingInvalidDestinationAddressTestCase)
        
        self.assertCheckFails(o)
        
    def test_invalid_neighbor_solicitation_handling_reply_2(self):
        
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ND_NA())
                
        o = self.get_outcome(suite.InvalidNeighborSolicitationHandlingInvalidDestinationAddressTestCase)
        
        self.assertCheckFails(o)
        
class InvalidNeighborSolicitationHandlingInvalidHopLimitTestCaseTestCase(ComplianceTestTestCase):
    
    def test_invalid_neighbor_solicitation_handling_no_reply(self):
        o = self.get_outcome(suite.InvalidNeighborSolicitationHandlingInvalidHopLimitTestCase)
        
        self.assertCheckPasses(o)
        
    def test_invalid_neighbor_solicitation_handling_reply_1(self):
        
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NA())
        
        o = self.get_outcome(suite.InvalidNeighborSolicitationHandlingInvalidHopLimitTestCase)
        
        self.assertCheckFails(o)
        
    def test_invalid_neighbor_solicitation_handling_reply_2(self):
        
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ND_NA())
                
        o = self.get_outcome(suite.InvalidNeighborSolicitationHandlingInvalidHopLimitTestCase)
        
        self.assertCheckFails(o)
        
class InvalidNeighborSolicitationHandlingInvalidICMPCodeTestCaseTestCase(ComplianceTestTestCase):
    
    def test_invalid_neighbor_solicitation_handling_no_reply(self):
        o = self.get_outcome(suite.InvalidNeighborSolicitationHandlingInvalidICMPCodeTestCase)
        
        self.assertCheckPasses(o)
 
    def test_invalid_neighbor_solicitation_handling_reply_1(self):
        
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NA())
        
        o = self.get_outcome(suite.InvalidNeighborSolicitationHandlingInvalidICMPCodeTestCase)
        
        self.assertCheckFails(o)
        
    def test_invalid_neighbor_solicitation_handling_reply_2(self):
        
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ND_NA())
                
        o = self.get_outcome(suite.InvalidNeighborSolicitationHandlingInvalidICMPCodeTestCase)
        
        self.assertCheckFails(o)
               
class InvalidNeighborSolicitationHandlingInvalidICMPLengthTestCaseTestCase(ComplianceTestTestCase):
    
    def test_invalid_neighbor_solicitation_handling_no_reply(self):
        o = self.get_outcome(suite.InvalidNeighborSolicitationHandlingInvalidICMPLengthTestCase)
        
        self.assertCheckPasses(o)
            
    def test_invalid_neighbor_solicitation_handling_reply_1(self):
        
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NA())
        
        o = self.get_outcome(suite.InvalidNeighborSolicitationHandlingInvalidICMPLengthTestCase)
        
        self.assertCheckFails(o)
        
    def test_invalid_neighbor_solicitation_handling_reply_2(self):
        
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ND_NA())
                
        o = self.get_outcome(suite.InvalidNeighborSolicitationHandlingInvalidICMPLengthTestCase)
        
        self.assertCheckFails(o)
        
class InvalidNeighborSolicitationHandlingInvalidSourceLinkLayerAddressOptionTestCaseTestCase(ComplianceTestTestCase):
    
    def test_invalid_neighbor_solicitation_handling_no_reply(self):
        o = self.get_outcome(suite.InvalidNeighborSolicitationHandlingInvalidSourceLinkLayerAddressOptionTestCase)
        
        self.assertCheckPasses(o)

    def test_invalid_neighbor_solicitation_handling_reply_1(self):
        
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NA())
        
        o = self.get_outcome(suite.InvalidNeighborSolicitationHandlingInvalidSourceLinkLayerAddressOptionTestCase)
        
        self.assertCheckFails(o)
        
    def test_invalid_neighbor_solicitation_handling_reply_2(self):
        
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ND_NA())
                
        o = self.get_outcome(suite.InvalidNeighborSolicitationHandlingInvalidSourceLinkLayerAddressOptionTestCase)
        
        self.assertCheckFails(o)
        
class InvalidNeighborSolicitationHandlingInvalidTargetAddressTestCaseTestCase(ComplianceTestTestCase):
    
    def test_invalid_neighbor_solicitation_handling_no_reply(self):
        o = self.get_outcome(suite.InvalidNeighborSolicitationHandlingInvalidTargetAddressTestCase)
        
        self.assertCheckPasses(o)

    def test_invalid_neighbor_solicitation_handling_reply_1(self):
        
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NA())
        
        o = self.get_outcome(suite.InvalidNeighborSolicitationHandlingInvalidTargetAddressTestCase)
        
        self.assertCheckFails(o)
        
    def test_invalid_neighbor_solicitation_handling_reply_2(self):
        
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ND_NA())
                
        o = self.get_outcome(suite.InvalidNeighborSolicitationHandlingInvalidTargetAddressTestCase)
        
        self.assertCheckFails(o)
                              
class InvalidNeighborSolicitationHandlingOptionOfLengthZeroCaseTestCase(ComplianceTestTestCase):
    
    def test_invalid_neighbor_solicitation_handling_no_reply(self):
        o = self.get_outcome(suite.InvalidNeighborSolicitationHandlingOptionOfLengthZeroCase)
        
        self.assertCheckPasses(o)
        
    def test_invalid_neighbor_solicitation_handling_reply_1(self):
        
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NA())
        
        o = self.get_outcome(suite.InvalidNeighborSolicitationHandlingOptionOfLengthZeroCase)
        
        self.assertCheckFails(o)
        
    def test_invalid_neighbor_solicitation_handling_reply_2(self):
        
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ND_NA())
                
        o = self.get_outcome(suite.InvalidNeighborSolicitationHandlingOptionOfLengthZeroCase)
        
        self.assertCheckFails(o)