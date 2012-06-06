from contrib.rfc4861 import resolution_wait_queue as suite
from scapy.all import *
from veripy.models import ComplianceTestCase
from veripy.testability import ComplianceTestTestCase
from veripy.assertions import *

class ResolutionWaitQueueSingleQueueTestCaseTestCase(ComplianceTestTestCase):
    
    def test_resolution_wait_single_queue_no_reply(self):
        o = self.get_outcome(suite.ResolutionWaitQueueSingleQueueTestCase)
        
        self.assertCheckFails(o)
        
    def test_resolution_wait_single_queue_neighbor_solicitation_no_reply(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ND_NS())
                
        o = self.get_outcome(suite.ResolutionWaitQueueSingleQueueTestCase)
        
        self.assertCheckFails(o)

    def test_resolution_wait_single_queue_neighbor_solicitation_reply(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ND_NS())
        
        for i in range(0,3):       
            self.ifx.sends(IPv6(src=str(self.ifx.global_ip()),dst=str(self.tn1.global_ip()))/ICMPv6EchoReply(seq=ComplianceTestCase.sequence + i + 1), 4)
        
        o = self.get_outcome(suite.ResolutionWaitQueueSingleQueueTestCase)
        
        self.assertCheckPasses(o)          
        
    def test_resolution_wait_single_queue_reply(self):
 
        for i in range(0,3):       
            self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()),dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        
        o = self.get_outcome(suite.ResolutionWaitQueueSingleQueueTestCase)
        
        self.assertCheckPasses(o) 

class ResolutionWaitQueueMultipleQueueTestCaseTestCase(ComplianceTestTestCase):
    
    def test_resolution_wait_multiple_queue_no_reply(self):
        o = self.get_outcome(suite.ResolutionWaitQueueMultipleQueueTestCase)
        
        self.assertCheckFails(o)
 
    def test_resolution_wait_multiple_queue_neighbor_solicitation_node_1_no_reply(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ND_NS())
        
        o = self.get_outcome(suite.ResolutionWaitQueueMultipleQueueTestCase)
        
        self.assertCheckFails(o)
        
    def test_resolution_wait_multiple_queue_neighbor_solicitation_node_2_no_reply(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6ND_NS())
        
        o = self.get_outcome(suite.ResolutionWaitQueueMultipleQueueTestCase)
        
        self.assertCheckFails(o)

    def test_resolution_wait_multiple_queue_neighbor_solicitation_node_1_reply(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ND_NS())
 
        for i in range(0,3):       
            self.ifx.sends(IPv6(src=str(self.ifx.global_ip()),dst=str(self.tn1.global_ip()))/ICMPv6EchoReply(), 4)
        
        o = self.get_outcome(suite.ResolutionWaitQueueMultipleQueueTestCase)
        
        self.assertCheckFails(o) 
         
    def test_resolution_wait_multiple_queue_neighbor_solicitation_node_2_reply(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6ND_NS())
 
        for i in range(0,3):       
            self.ifx.sends(IPv6(src=str(self.ifx.global_ip()),dst=str(self.tn2.global_ip()))/ICMPv6EchoReply(), 4)
        
        o = self.get_outcome(suite.ResolutionWaitQueueMultipleQueueTestCase)

    def test_resolution_wait_multiple_queue_reply(self):

        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ND_NS())
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6ND_NS())        
         
        for i in range(0,3):       
            self.ifx.sends(IPv6(src=str(self.ifx.global_ip()),dst=str(self.tn1.global_ip()))/ICMPv6EchoReply(seq=ComplianceTestCase.sequence + i + 1),4)
        
        for j in range(0,4):       
            self.ifx.sends(IPv6(src=str(self.ifx.global_ip()),dst=str(self.tn2.global_ip()))/ICMPv6EchoReply(seq=ComplianceTestCase.sequence + j + 4),4)
        
        o = self.get_outcome(suite.ResolutionWaitQueueMultipleQueueTestCase)
        
        self.assertCheckPasses(o)                 