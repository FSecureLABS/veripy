from contrib.rfc4861 import neighbor_solicitation_processing_nce_state_incomplete as suite
from scapy.all import *
from veripy.models import ComplianceTestCase
from veripy.testability import ComplianceTestTestCase
from veripy.assertions import *
from constants import *
from time import sleep

class NeighborSolicitationProcessingNceStateIncompleteUnicastTestCaseTestCase(ComplianceTestTestCase):
    
    def test_neighbor_solicitation_processing_nce_state_incomplete_unicast_no_reply(self):
        
        self.ui.inputs.append("n")
        o = self.get_outcome(suite.NeighborSolicitationProcessingNceStateIncompleteUnicastTestCase)
        
        self.assertCheckFails(o)
        
    def test_neighbor_solicitation_processing_nce_state_incomplete_unicast_reply(self):
        
        self.ui.inputs.append("y")  
        self.ui.inputs.append("y")
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip().solicited_node()))/ICMPv6ND_NS(),0)
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())
        self.ui.inputs.append("y")
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NA()) 
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())
        self.ui.inputs.append("y")
        sleep(DELAY_FIRST_PROBE_TIME)
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS(),DELAY_FIRST_PROBE_TIME-1)
        o = self.get_outcome(suite.NeighborSolicitationProcessingNceStateIncompleteUnicastTestCase)
        
        self.assertCheckPasses(o)
    
    def test_neighbor_solicitation_processing_nce_state_incomplete_unicast_no_ns_too_soon_reply(self):
        
        self.ui.inputs.append("y")  
        self.ui.inputs.append("y")
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip().solicited_node()))/ICMPv6ND_NS(),0)
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())
        self.ui.inputs.append("y")
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NA()) 
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())
        self.ui.inputs.append("y")
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS(),4)
        o = self.get_outcome(suite.NeighborSolicitationProcessingNceStateIncompleteUnicastTestCase)
        
        self.assertCheckFails(o)

    def test_neighbor_solicitation_processing_nce_state_incomplete_unicast_wrong_input_reply(self):
        
        self.ui.inputs.append("n")  
        self.ui.inputs.append("n")
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip().solicited_node()))/ICMPv6ND_NS(),0)
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())
        self.ui.inputs.append("n")
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NA()) 
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())
        self.ui.inputs.append("n")
        sleep(DELAY_FIRST_PROBE_TIME)
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS(),DELAY_FIRST_PROBE_TIME-1)
        o = self.get_outcome(suite.NeighborSolicitationProcessingNceStateIncompleteUnicastTestCase)
        
        self.assertCheckFails(o)        

    def test_neighbor_solicitation_processing_nce_state_incomplete_unicast_no_ns_reply(self):
    
        self.ui.inputs.append("y")  
        self.ui.inputs.append("y")
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())
        self.ui.inputs.append("y")
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NA()) 
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())
        self.ui.inputs.append("y")
        sleep(DELAY_FIRST_PROBE_TIME)
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS(),DELAY_FIRST_PROBE_TIME-1)
        o = self.get_outcome(suite.NeighborSolicitationProcessingNceStateIncompleteUnicastTestCase)
        
        self.assertCheckFails(o)
        
    def test_neighbor_solicitation_processing_nce_state_incomplete_unicast_no_na_reply(self):
        
        self.ui.inputs.append("y")  
        self.ui.inputs.append("y")
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip().solicited_node()))/ICMPv6ND_NS(),0)
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())
        self.ui.inputs.append("y") 
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())
        self.ui.inputs.append("y")
        sleep(DELAY_FIRST_PROBE_TIME)
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS(),DELAY_FIRST_PROBE_TIME-1)
        o = self.get_outcome(suite.NeighborSolicitationProcessingNceStateIncompleteUnicastTestCase)
        
        self.assertCheckPasses(o)               
class NeighborSolicitationProcessingNceStateIncompleteMulticastTestCaseTestCase(ComplianceTestTestCase):
    
    def test_neighbor_solicitation_processing_nce_state_incomplete_multicast_no_reply(self):
        
        self.ui.inputs.append("n")
        o = self.get_outcome(suite.NeighborSolicitationProcessingNceStateIncompleteMulticastTestCase)
        
        self.assertCheckFails(o)
        
    def test_neighbor_solicitation_processing_nce_state_incomplete_multicast_reply(self):
         
        self.ui.inputs.append("y")  
        self.ui.inputs.append("y")
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip().solicited_node()))/ICMPv6ND_NS(),0)
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())
        self.ui.inputs.append("y")
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NA())
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())
        self.ui.inputs.append("y")
        sleep(DELAY_FIRST_PROBE_TIME)
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS(),DELAY_FIRST_PROBE_TIME-1)
        o = self.get_outcome(suite.NeighborSolicitationProcessingNceStateIncompleteMulticastTestCase)
        
        self.assertCheckPasses(o)
        
    def test_neighbor_solicitation_processing_nce_state_incomplete_multicast_no_ns_reply(self):
         
        self.ui.inputs.append("y")  
        self.ui.inputs.append("y")
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())
        self.ui.inputs.append("y")
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NA())
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())
        self.ui.inputs.append("y")
        sleep(DELAY_FIRST_PROBE_TIME)
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS(),DELAY_FIRST_PROBE_TIME-1)
        o = self.get_outcome(suite.NeighborSolicitationProcessingNceStateIncompleteMulticastTestCase)
        
        self.assertCheckFails(o)

    def test_neighbor_solicitation_processing_nce_state_incomplete_multicast_ns_too_soon_reply(self):
         
        self.ui.inputs.append("y")  
        self.ui.inputs.append("y")
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip().solicited_node()))/ICMPv6ND_NS(),0)
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())
        self.ui.inputs.append("y")
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NA())
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())
        self.ui.inputs.append("y")
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS(),4)
        o = self.get_outcome(suite.NeighborSolicitationProcessingNceStateIncompleteMulticastTestCase)
        
        self.assertCheckFails(o)
   
   
    def test_neighbor_solicitation_processing_nce_state_incomplete_multicast_wrong_input_reply(self):
         
        self.ui.inputs.append("n")  
        self.ui.inputs.append("n")
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip().solicited_node()))/ICMPv6ND_NS(),0)
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())
        self.ui.inputs.append("n")
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NA())
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())
        self.ui.inputs.append("n")
        sleep(DELAY_FIRST_PROBE_TIME)
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS(),DELAY_FIRST_PROBE_TIME-1)
        o = self.get_outcome(suite.NeighborSolicitationProcessingNceStateIncompleteMulticastTestCase)
        
        self.assertCheckFails(o)  
    
    def test_neighbor_solicitation_processing_nce_state_incomplete_multicast_no_na_reply(self):
         
        self.ui.inputs.append("y")  
        self.ui.inputs.append("y")
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip().solicited_node()))/ICMPv6ND_NS(),0)
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())
        self.ui.inputs.append("y")
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())
        self.ui.inputs.append("y")
        sleep(DELAY_FIRST_PROBE_TIME)
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS(),DELAY_FIRST_PROBE_TIME-1)
        o = self.get_outcome(suite.NeighborSolicitationProcessingNceStateIncompleteMulticastTestCase)
        
        self.assertCheckFails(o)
           
class NeighborSolicitationProcessingNceStateIncompleteUnicastNoSllTestCaseTestCase(ComplianceTestTestCase):
    
    def test_neighbor_solicitation_processing_nce_state_incomplete_uniicast_no_sll_no_reply(self):
        
        self.ui.inputs.append("n")
        o = self.get_outcome(suite.NeighborSolicitationProcessingNceStateIncompleteUnicastNoSllTestCase)
        
        self.assertCheckFails(o)
        
    def test_neighbor_solicitation_processing_nce_state_incomplete_uniicast_no_sll_reply(self):
        
        self.ui.inputs.append("y")  
        self.ui.inputs.append("y")
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip().solicited_node()))/ICMPv6ND_NS(),0)
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())
        self.ui.inputs.append("y")
        o = self.get_outcome(suite.NeighborSolicitationProcessingNceStateIncompleteUnicastNoSllTestCase)
        
        self.assertCheckPasses(o)
        
    def test_neighbor_solicitation_processing_nce_state_incomplete_uniicast_no_sll_wrong_reply(self):
        
        self.ui.inputs.append("n")  
        self.ui.inputs.append("n")
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip().solicited_node()))/ICMPv6ND_NS(),0)
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())
        self.ui.inputs.append("n")
        o = self.get_outcome(suite.NeighborSolicitationProcessingNceStateIncompleteUnicastNoSllTestCase)
        
        self.assertCheckFails(o)

    def test_neighbor_solicitation_processing_nce_state_incomplete_uniicast_no_sll_no_ns_reply(self):
        
        self.ui.inputs.append("y")  
        self.ui.inputs.append("y")
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())
        self.ui.inputs.append("y")
        o = self.get_outcome(suite.NeighborSolicitationProcessingNceStateIncompleteUnicastNoSllTestCase)
        
        self.assertCheckFails(o)
        
    def test_neighbor_solicitation_processing_nce_state_incomplete_uniicast_no_sll_no_icmp_reply(self):
        
        self.ui.inputs.append("y")  
        self.ui.inputs.append("y")
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip().solicited_node()))/ICMPv6ND_NS(),0)
        self.ui.inputs.append("y")
        o = self.get_outcome(suite.NeighborSolicitationProcessingNceStateIncompleteUnicastNoSllTestCase)
        
        self.assertCheckFails(o)