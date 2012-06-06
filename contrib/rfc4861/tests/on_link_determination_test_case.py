from contrib.rfc4861 import on_link_determination as suite
from scapy.all import *
from veripy.testability import ComplianceTestTestCase
from veripy.assertions import *

class OnLinkDeterminationLinkLocalTestCaseTestCase(ComplianceTestTestCase):
    
    def test_on_link_determination_no_reply(self):
        o = self.get_outcome(suite.OnLinkDeterminationLinkLocalTestCase)
        
        self.assertCheckFails(o)

    def test_on_link_determination_neighbor_solicitation_without_node_local_link_address(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS(tgt=str(self.tn2.link_local_ip())))
        
        o = self.get_outcome(suite.OnLinkDeterminationLinkLocalTestCase)

        self.assertCheckFails(o)      
        
    def test_on_link_determination_neighbor_solicitation_with_node_local_link_address(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS(tgt=str(self.tn1.link_local_ip())))

        o = self.get_outcome(suite.OnLinkDeterminationLinkLocalTestCase)

        self.assertCheckPasses(o)
        
class OnLinkDeterminationGlobalTestCaseTestCase(ComplianceTestTestCase):
    
    def test_on_link_determination_no_reply(self):
        o = self.get_outcome(suite.OnLinkDeterminationGlobalTestCase)
        
        self.assertCheckFails(o)

    def test_on_link_determination_neighbor_solicitation_without_node_global_address(self):
        
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ND_NS(tgt=str(self.tn2.global_ip())))
        
        o = self.get_outcome(suite.OnLinkDeterminationGlobalTestCase)

        self.assertCheckFails(o)      
        
    def test_on_link_determination_neighbor_solicitation_with_node_global_address(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ND_NS(tgt=str(self.tn1.global_ip())))
        
        o = self.get_outcome(suite.OnLinkDeterminationGlobalTestCase)

        self.assertCheckPasses(o)
        
class OnLinkDeterminationGlobalAddressTestCaseTestCase(ComplianceTestTestCase):
    
    def test_on_link_determination_no_reply(self):
        o = self.get_outcome(suite.OnLinkDeterminationLinkLocalTestCase)
        
        self.assertCheckFails(o)

    def test_on_link_determination_neighbor_solicitation_without_TR1_global_address(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ND_NS(tgt=str(self.tn2.global_ip())))
        
        o = self.get_outcome(suite.OnLinkDeterminationGlobalAddressTestCase)

        self.assertCheckFails(o)      
        
    def test_on_link_determination_neighbor_solicitation_with_TR1_global_address(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ND_NS(tgt=str(self.tn1.global_ip())))

        o = self.get_outcome(suite.OnLinkDeterminationGlobalAddressTestCase)

#        self.assertCheckPasses(o)