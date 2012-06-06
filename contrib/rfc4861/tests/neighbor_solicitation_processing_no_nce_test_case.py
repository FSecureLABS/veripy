from contrib.rfc4861 import neighbor_solicitation_processing_no_nce as suite
from scapy.all import *
from veripy.models import ComplianceTestCase
from veripy.testability import ComplianceTestTestCase
from veripy.assertions import *
from constants import *
from time import sleep

class NeighborSolicitationProcessingNoNCEUnicastTestCaseTestCase(ComplianceTestTestCase):
    
    def test_neighbor_solicitation_processing_no_nce_unicast_no_reply(self):
        
        self.ui.inputs.append("n")
        o = self.get_outcome(suite.NeighborSolicitationProcessingNoNCEUnicastTestCase)
        
        self.assertCheckFails(o)
        
    def test_neighbor_solicitation_processing_no_nce_unicast_reply(self):
        
        self.ui.inputs.append("y")  
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NA())
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        self.ui.inputs.append("y")
        sleep(DELAY_FIRST_PROBE_TIME)
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS(),DELAY_FIRST_PROBE_TIME)
        o = self.get_outcome(suite.NeighborSolicitationProcessingNoNCEUnicastTestCase)
        
        self.assertCheckPasses(o)
        
    def test_neighbor_solicitation_processing_no_nce_unicast_wrong_delay_reply(self):
        
        self.ui.inputs.append("y")  
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NA())
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        self.ui.inputs.append("y")
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS(),4)
        o = self.get_outcome(suite.NeighborSolicitationProcessingNoNCEUnicastTestCase)
        
        self.assertCheckFails(o)
        
    def test_neighbor_solicitation_processing_no_nce_unicast_wrong_response_reply(self):
        
        self.ui.inputs.append("y")  
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NA())
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        self.ui.inputs.append("n")
        sleep(DELAY_FIRST_PROBE_TIME)
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS(),DELAY_FIRST_PROBE_TIME)
        o = self.get_outcome(suite.NeighborSolicitationProcessingNoNCEUnicastTestCase)
        
        self.assertCheckFails(o)
        
    def test_neighbor_solicitation_processing_no_nce_unicast_wrong_response_ns_reply(self):
        
        self.ui.inputs.append("y")  
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS())
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        self.ui.inputs.append("y")
        sleep(DELAY_FIRST_PROBE_TIME)
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS(),DELAY_FIRST_PROBE_TIME)
        o = self.get_outcome(suite.NeighborSolicitationProcessingNoNCEUnicastTestCase)
        
        self.assertCheckFails(o)
        
    def test_neighbor_solicitation_processing_no_nce_unicast_wrong_1_response_reply(self):
        
        self.ui.inputs.append("n")  
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NA())
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        self.ui.inputs.append("y")
        sleep(DELAY_FIRST_PROBE_TIME)
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS(),DELAY_FIRST_PROBE_TIME)
        o = self.get_outcome(suite.NeighborSolicitationProcessingNoNCEUnicastTestCase)
        
        self.assertCheckFails(o)
        
class NeighborSolicitationProcessingNoNCEMulticastTestCaseTestCase(ComplianceTestTestCase):
    
    def test_neighbor_solicitation_processing_no_nce_multicast_no_reply(self):
        
        self.ui.inputs.append("n")
        o = self.get_outcome(suite.NeighborSolicitationProcessingNoNCEMulticastTestCase)
        
        self.assertCheckFails(o)
 
    def test_neighbor_solicitation_processing_no_nce_unicast_reply(self):
        
        self.ui.inputs.append("y")  
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NA())
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        self.ui.inputs.append("y")
        sleep(DELAY_FIRST_PROBE_TIME)
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS(),DELAY_FIRST_PROBE_TIME)
        o = self.get_outcome(suite.NeighborSolicitationProcessingNoNCEMulticastTestCase)
        
        self.assertCheckPasses(o)
    
    def test_neighbor_solicitation_processing_no_nce_unicast_wrong_delay_reply(self): 
     
        self.ui.inputs.append("y")  
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NA())
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        self.ui.inputs.append("y")
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS(),4)
        o = self.get_outcome(suite.NeighborSolicitationProcessingNoNCEMulticastTestCase)
        
        self.assertCheckFails(o)   
         
    def test_neighbor_solicitation_processing_no_nce_unicast_wrong_response_reply(self):
    
        self.ui.inputs.append("y")  
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NA())
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        self.ui.inputs.append("n")
        sleep(DELAY_FIRST_PROBE_TIME)
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS(),DELAY_FIRST_PROBE_TIME)
        o = self.get_outcome(suite.NeighborSolicitationProcessingNoNCEMulticastTestCase)
        
        self.assertCheckFails(o)
      
    def test_neighbor_solicitation_processing_no_nce_unicast_wrong_response_ns_reply(self):
    
        self.ui.inputs.append("y")  
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS())
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        self.ui.inputs.append("y")
        sleep(DELAY_FIRST_PROBE_TIME)
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS(),DELAY_FIRST_PROBE_TIME)
        o = self.get_outcome(suite.NeighborSolicitationProcessingNoNCEMulticastTestCase)
        
        self.assertCheckFails(o)
        
    def test_neighbor_solicitation_processing_no_nce_unicast_wrong_1_response_reply(self):
                        
        self.ui.inputs.append("n")  
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NA())
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        self.ui.inputs.append("y")
        sleep(DELAY_FIRST_PROBE_TIME)
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS(),DELAY_FIRST_PROBE_TIME)
        o = self.get_outcome(suite.NeighborSolicitationProcessingNoNCEMulticastTestCase)
        
        self.assertCheckFails(o)
         
class NeighborSolicitationProcessingNoNCEUnicastNoSLLTestCaseTestCase(ComplianceTestTestCase):
    
    def test_neighbor_solicitation_processing_no_nce_unicast_no_sll_no_reply(self):
        
        self.ui.inputs.append("n")
        o = self.get_outcome(suite.NeighborSolicitationProcessingNoNCEUnicastNoSLLTestCase)
        
        self.assertCheckFails(o)
        
    def test_neighbor_solicitation_processing_no_nce_unicast_reply(self):
        
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip().solicited_node()))/ICMPv6ND_NS())
        self.ui.inputs.append("y")    
        pckts = []
        for i in range(0,2):
            pckts.append(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS())   
        self.ifx.replies_with(pckts)
        self.ui.inputs.append("y")  
        o = self.get_outcome(suite.NeighborSolicitationProcessingNoNCEUnicastNoSLLTestCase)
        
        self.assertCheckPasses(o)
        
    def test_neighbor_solicitation_processing_no_nce_unicast_wrong_response_reply(self):
        
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip().solicited_node()))/ICMPv6ND_NS())
        self.ui.inputs.append("y")    
        pckts = []
        for i in range(0,2):
            pckts.append(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS())   
        self.ifx.replies_with(pckts)
        self.ui.inputs.append("n")  
        o = self.get_outcome(suite.NeighborSolicitationProcessingNoNCEUnicastNoSLLTestCase)
        
        self.assertCheckFails(o)
        
    def test_neighbor_solicitation_processing_no_nce_unicast_wrong_response_1_reply(self):
        
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip().solicited_node()))/ICMPv6ND_NS())
        self.ui.inputs.append("n")    
        pckts = []
        for i in range(0,2):
            pckts.append(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS())   
        self.ifx.replies_with(pckts)
        self.ui.inputs.append("y")  
        o = self.get_outcome(suite.NeighborSolicitationProcessingNoNCEUnicastNoSLLTestCase)
        
        self.assertCheckFails(o)
        
    def test_neighbor_solicitation_processing_no_nce_unicast_na_reply(self):
        
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip().solicited_node()))/ICMPv6ND_NS())
        self.ui.inputs.append("y")    
        pckts = []
        for i in range(0,2):
            pckts.append(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NA())   
        self.ifx.replies_with(pckts)
        self.ui.inputs.append("y")  
        o = self.get_outcome(suite.NeighborSolicitationProcessingNoNCEUnicastNoSLLTestCase)
        
        self.assertCheckFails(o)
        
    def test_neighbor_solicitation_processing_no_nce_unicast_one_ns_reply(self):
        
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip().solicited_node()))/ICMPv6ND_NS())
        self.ui.inputs.append("y")     
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS())
        self.ui.inputs.append("y")  
        o = self.get_outcome(suite.NeighborSolicitationProcessingNoNCEUnicastNoSLLTestCase)
        
        self.assertCheckFails(o)
        
    def test_neighbor_solicitation_processing_no_nce_unicast_link_local_reply(self):
        
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS())
        self.ui.inputs.append("y")    
        pckts = []
        for i in range(0,2):
            pckts.append(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS())   
        self.ifx.replies_with(pckts)
        self.ui.inputs.append("y")  
        o = self.get_outcome(suite.NeighborSolicitationProcessingNoNCEUnicastNoSLLTestCase)
        
        self.assertCheckFails(o)
        
    def test_neighbor_solicitation_processing_no_nce_unicast_na_1_reply(self):
        
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip().solicited_node()))/ICMPv6ND_NA())
        self.ui.inputs.append("y")    
        pckts = []
        for i in range(0,2):
            pckts.append(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS())   
        self.ifx.replies_with(pckts)
        self.ui.inputs.append("y")  
        o = self.get_outcome(suite.NeighborSolicitationProcessingNoNCEUnicastNoSLLTestCase)
        
        self.assertCheckFails(o)
        