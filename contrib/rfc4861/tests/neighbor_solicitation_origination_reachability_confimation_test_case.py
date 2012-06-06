from contrib.rfc4861 import neighbor_solicitation_origination_reachability_confimation as suite
from scapy.all import *
from veripy.testability import ComplianceTestTestCase
from veripy.assertions import *
from time import sleep
from sys import *

class NeighborSolicitationOriginationReachabilityConfirmationLinkLocalToLinkLocalTestCaseTestCase(ComplianceTestTestCase):
    
    def test_prefix_information_option_processing_no_reply_all(self):
        o = self.get_outcome(suite.NeighborSolicitationOriginationReachabilityConfirmationLinkLocalToLinkLocalTestCase)
        
        self.assertCheckFails(o)
    
    def test_prefix_information_option_processing_reply(self):
        
        pckts = []
        
        for i in range(0,3):  
            sleep(1)
            pckts.append(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS())

        pckts.append(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())
        
        self.ifx.replies_with(pckts)
        
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())
        
        pckts = []
        
        sleep(1)
        
        for i in range(0,3):  
            sleep(1)
            self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS(), 4+i)   
        
        o = self.get_outcome(suite.NeighborSolicitationOriginationReachabilityConfirmationLinkLocalToLinkLocalTestCase)
        
        self.assertCheckPasses(o)
        
    def test_prefix_information_option_processing_reply_direct_to_icmp(self):
        
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())

        o = self.get_outcome(suite.NeighborSolicitationOriginationReachabilityConfirmationLinkLocalToLinkLocalTestCase)
        
        self.assertCheckFails(o)
        
    def test_prefix_information_option_processing_ns_too_many(self):
        
        pckts = []
        
        for i in range(0,4):  
            sleep(1)
            pckts.append(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS())

        pckts.append(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())
        
        self.ifx.replies_with(pckts)
        
        o = self.get_outcome(suite.NeighborSolicitationOriginationReachabilityConfirmationLinkLocalToLinkLocalTestCase)
        
        self.assertCheckFails(o)

    def test_prefix_information_option_processing_no_icmp_1(self):
        
        pckts = []
        
        for i in range(0,3):  
            sleep(1)
            pckts.append(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS())
        
        self.ifx.replies_with(pckts)
        
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())
        
        pckts = []
        
        sleep(1)
        
        for i in range(0,3):  
            sleep(1)
            self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS(), 4+i)   
        
        o = self.get_outcome(suite.NeighborSolicitationOriginationReachabilityConfirmationLinkLocalToLinkLocalTestCase)
        
        self.assertCheckFails(o)
        
    def test_prefix_information_option_processing_no_icmp_2(self):
        
        pckts = []
        
        for i in range(0,3):  
            sleep(1)
            pckts.append(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS())

        pckts.append(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())
        
        self.ifx.replies_with(pckts)
        
        pckts = []
        
        sleep(1)
        
        for i in range(0,3):  
            sleep(1)
            self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS(), 4+i)   
        
        o = self.get_outcome(suite.NeighborSolicitationOriginationReachabilityConfirmationLinkLocalToLinkLocalTestCase)
        
        self.assertCheckFails(o)      
        
    def test_prefix_information_option_processing_ns_too_many_1(self):
        
        pckts = []
        
        for i in range(0,3):  
            sleep(1)
            pckts.append(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS())

        pckts.append(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())
        
        self.ifx.replies_with(pckts)
        
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())
        
        pckts = []
        
        sleep(1)
        
        for i in range(0,4):  
            sleep(1)
            self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS(), 4+i)   
        
        o = self.get_outcome(suite.NeighborSolicitationOriginationReachabilityConfirmationLinkLocalToLinkLocalTestCase)
        
        self.assertCheckFails(o)
        
    def test_prefix_information_option_processing_ns_too_little(self):
        
        pckts = []
        
        for i in range(0,3):  
            sleep(1)
            pckts.append(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS())

        pckts.append(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())
        
        self.ifx.replies_with(pckts)
        
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())
        
        o = self.get_outcome(suite.NeighborSolicitationOriginationReachabilityConfirmationLinkLocalToLinkLocalTestCase)
        
        self.assertCheckFails(o)
        
    def test_prefix_information_option_processing_ns_too_long(self):
        
        pckts = []
        
        for i in range(0,3):  
            sleep(2)
            pckts.append(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS())

        pckts.append(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())
        
        self.ifx.replies_with(pckts)
        
        o = self.get_outcome(suite.NeighborSolicitationOriginationReachabilityConfirmationLinkLocalToLinkLocalTestCase)
        
        self.assertCheckFails(o)
        
    def test_prefix_information_option_processing_ns_too_short(self):
        
        pckts = []
        
        for i in range(0,3):  
            sleep(0.5)
            pckts.append(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS())

        pckts.append(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())
        
        self.ifx.replies_with(pckts)
        
        o = self.get_outcome(suite.NeighborSolicitationOriginationReachabilityConfirmationLinkLocalToLinkLocalTestCase)
                
        self.assertCheckFails(o)        
    
class NeighborSolicitationOriginationReachabilityConfirmationGlobalToGlobalTestCaseTestCase(ComplianceTestTestCase):
    
    def test_prefix_information_option_processing_no_reply_all(self):
        o = self.get_outcome(suite.NeighborSolicitationOriginationReachabilityConfirmationGlobalToGlobalTestCase)
        
        self.assertCheckFails(o)
    
    def test_prefix_information_option_processing_reply(self):
        
        pckts = []
        
        for i in range(0,3):  
            sleep(1)
            pckts.append(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ND_NS())

        pckts.append(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        
        self.ifx.replies_with(pckts)
        
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        
        pckts = []
        
        sleep(1)
        
        for i in range(0,3):  
            sleep(1)
            self.ifx.sends(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ND_NS(), 4+i)   
        
        o = self.get_outcome(suite.NeighborSolicitationOriginationReachabilityConfirmationGlobalToGlobalTestCase)
        
        self.assertCheckPasses(o)
        
    def test_prefix_information_option_processing_reply_direct_to_icmp(self):
        
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())

        o = self.get_outcome(suite.NeighborSolicitationOriginationReachabilityConfirmationGlobalToGlobalTestCase)
        
        self.assertCheckFails(o)
        
    def test_prefix_information_option_processing_ns_too_many(self):
        
        pckts = []
        
        for i in range(0,4):  
            sleep(1)
            pckts.append(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ND_NS())

        pckts.append(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        
        self.ifx.replies_with(pckts)
        
        o = self.get_outcome(suite.NeighborSolicitationOriginationReachabilityConfirmationLinkLocalToLinkLocalTestCase)
        
        self.assertCheckFails(o)
        
 
    def test_prefix_information_option_processing_no_icmp_1(self):
        
        pckts = []
        
        for i in range(0,3):  
            sleep(1)
            pckts.append(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ND_NS())
        
        self.ifx.replies_with(pckts)
        
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        
        pckts = []
        
        sleep(1)
        
        for i in range(0,3):  
            sleep(1)
            self.ifx.sends(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ND_NS(), 4+i)   
        
        o = self.get_outcome(suite.NeighborSolicitationOriginationReachabilityConfirmationLinkLocalToLinkLocalTestCase)
        
        self.assertCheckFails(o) 
        
    def test_prefix_information_option_processing_no_icmp_2(self):
        
        pckts = []
        
        for i in range(0,3):  
            sleep(1)
            pckts.append(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ND_NS())

        pckts.append(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        
        self.ifx.replies_with(pckts)
        
        pckts = []
        
        sleep(1)
        
        for i in range(0,3):  
            sleep(1)
            self.ifx.sends(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ND_NS(), 4+i)   
        
        o = self.get_outcome(suite.NeighborSolicitationOriginationReachabilityConfirmationLinkLocalToLinkLocalTestCase)
        
        self.assertCheckFails(o)
        
    def test_prefix_information_option_processing_ns_too_many_1(self):
        
        pckts = []
        
        for i in range(0,3):  
            sleep(1)
            pckts.append(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ND_NS())

        pckts.append(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        
        self.ifx.replies_with(pckts)
        
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        
        pckts = []
        
        sleep(1)
        
        for i in range(0,4):  
            sleep(1)
            self.ifx.sends(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ND_NS(), 4+i)   
        
        o = self.get_outcome(suite.NeighborSolicitationOriginationReachabilityConfirmationLinkLocalToLinkLocalTestCase)
        
        self.assertCheckFails(o) 
        
    def test_prefix_information_option_processing_ns_too_little(self):
        
        pckts = []
        
        for i in range(0,3):  
            sleep(1)
            pckts.append(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ND_NS())

        pckts.append(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        
        self.ifx.replies_with(pckts)
        
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        
        o = self.get_outcome(suite.NeighborSolicitationOriginationReachabilityConfirmationLinkLocalToLinkLocalTestCase)
        
        self.assertCheckFails(o)   
        
    def test_prefix_information_option_processing_ns_too_long(self):
        
        pckts = []
        
        for i in range(0,3):  
            sleep(2)
            pckts.append(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ND_NS())

        pckts.append(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        
        self.ifx.replies_with(pckts)
        
        o = self.get_outcome(suite.NeighborSolicitationOriginationReachabilityConfirmationLinkLocalToLinkLocalTestCase)
        
        self.assertCheckFails(o)   
        
    def test_prefix_information_option_processing_ns_too_short(self):
        
        pckts = []
        
        for i in range(0,3):  
            sleep(0.5)
            pckts.append(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ND_NS())

        pckts.append(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        
        self.ifx.replies_with(pckts)
        
        o = self.get_outcome(suite.NeighborSolicitationOriginationReachabilityConfirmationLinkLocalToLinkLocalTestCase)
                
        self.assertCheckFails(o) 

class NeighborSolicitationOriginationReachabilityConfirmationLinkLocalToGlobalTestCaseTestCase(ComplianceTestTestCase):
    
    def test_prefix_information_option_processing_no_reply_all(self):
        o = self.get_outcome(suite.NeighborSolicitationOriginationReachabilityConfirmationLinkLocalToGlobalTestCase)
        
        self.assertCheckFails(o)
    
    def test_prefix_information_option_processing_reply(self):
        
        pckts = []
        
        for i in range(0,3):  
            sleep(1)
            pckts.append(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS())

        pckts.append(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())
        
        self.ifx.replies_with(pckts)
        
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())
        
        pckts = []
        
        sleep(1)
        
        for i in range(0,3):  
            sleep(1)
            self.ifx.sends(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS(), 4+i)   
        
        o = self.get_outcome(suite.NeighborSolicitationOriginationReachabilityConfirmationLinkLocalToGlobalTestCase)
        
        self.assertCheckPasses(o)
        
    def test_prefix_information_option_processing_reply_direct_to_icmp(self):
        
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())

        o = self.get_outcome(suite.NeighborSolicitationOriginationReachabilityConfirmationLinkLocalToLinkLocalTestCase)
            
        self.assertCheckFails(o)
        
    def test_prefix_information_option_processing_ns_too_many(self):
        
        pckts = []
        
        for i in range(0,3):  
            sleep(1)
            pckts.append(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS())

        pckts.append(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())
        
        self.ifx.replies_with(pckts)
        
        o = self.get_outcome(suite.NeighborSolicitationOriginationReachabilityConfirmationLinkLocalToLinkLocalTestCase)
        
        self.assertCheckFails(o)

    def test_prefix_information_option_processing_no_icmp_1(self):
        
        pckts = []
        
        for i in range(0,3):  
            sleep(1)
            pckts.append(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS())
        
        self.ifx.replies_with(pckts)
        
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())
        
        pckts = []
        
        sleep(1)
        
        for i in range(0,3):  
            sleep(1)
            self.ifx.sends(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS(), 4+i)   
        
        o = self.get_outcome(suite.NeighborSolicitationOriginationReachabilityConfirmationLinkLocalToGlobalTestCase)
        
        self.assertCheckFails(o)

        
    def test_prefix_information_option_processing_no_icmp_2(self):
        
        
        pckts = []
        
        for i in range(0,3):  
            sleep(1)
            pckts.append(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS())

        pckts.append(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())
        
        self.ifx.replies_with(pckts)
        
        pckts = []
        
        sleep(1)
        
        for i in range(0,3):  
            sleep(1)
            self.ifx.sends(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS(), 4+i)   
        
        o = self.get_outcome(suite.NeighborSolicitationOriginationReachabilityConfirmationLinkLocalToGlobalTestCase)
        
        self.assertCheckFails(o)     
        
    def test_prefix_information_option_processing_ns_too_many_1(self):
        
        
        pckts = []
        
        for i in range(0,3):  
            sleep(1)
            pckts.append(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS())

        pckts.append(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())
        
        self.ifx.replies_with(pckts)
        
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())
        
        pckts = []
        
        sleep(1)
        
        for i in range(0,4):  
            sleep(1)
            self.ifx.sends(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS(), 4+i)   
        
        o = self.get_outcome(suite.NeighborSolicitationOriginationReachabilityConfirmationLinkLocalToGlobalTestCase)
        
        self.assertCheckFails(o)
        
    def test_prefix_information_option_processing_ns_too_little(self):
        
        pckts = []
        
        for i in range(0,3):  
            sleep(1)
            pckts.append(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS())

        pckts.append(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())
        
        self.ifx.replies_with(pckts)
        
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())
        
        o = self.get_outcome(suite.NeighborSolicitationOriginationReachabilityConfirmationLinkLocalToLinkLocalTestCase)
        
        self.assertCheckFails(o)
        
    def test_prefix_information_option_processing_ns_too_long(self):
        
        pckts = []
        
        for i in range(0,3):  
            sleep(2)
            pckts.append(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS())

        pckts.append(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())
        
        self.ifx.replies_with(pckts)
        
        o = self.get_outcome(suite.NeighborSolicitationOriginationReachabilityConfirmationLinkLocalToLinkLocalTestCase)
        
        self.assertCheckFails(o)
        
    def test_prefix_information_option_processing_ns_too_short(self):
        
        pckts = []
        
        for i in range(0,3):  
            sleep(0.5)
            pckts.append(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS())

        pckts.append(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6EchoReply())
        
        self.ifx.replies_with(pckts)
        
        o = self.get_outcome(suite.NeighborSolicitationOriginationReachabilityConfirmationLinkLocalToLinkLocalTestCase)
                
        self.assertCheckFails(o)        
        
class NeighborSolicitationOriginationReachabilityConfirmationGlobalToLinkLocalTestCaseTestCase(ComplianceTestTestCase):
    
    def test_prefix_information_option_processing_no_reply_all(self):
        o = self.get_outcome(suite.NeighborSolicitationOriginationReachabilityConfirmationGlobalToLinkLocalTestCase)
        
        self.assertCheckFails(o)
    
    def test_prefix_information_option_processing_reply(self):
        
        pckts = []
        
        for i in range(0,3):  
            sleep(1)
            pckts.append(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ND_NS())

        pckts.append(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        
        self.ifx.replies_with(pckts)
        
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        
        pckts = []
        
        sleep(1)
        
        for i in range(0,3):  
            sleep(1)
            self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ND_NS(), 4+i)   
        
        o = self.get_outcome(suite.NeighborSolicitationOriginationReachabilityConfirmationGlobalToLinkLocalTestCase)
        
        self.assertCheckPasses(o)
        
    def test_prefix_information_option_processing_reply_direct_to_icmp(self):
        
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())

        o = self.get_outcome(suite.NeighborSolicitationOriginationReachabilityConfirmationLinkLocalToLinkLocalTestCase)
        
        self.assertCheckFails(o)
        
    def test_prefix_information_option_processing_ns_too_many(self):
        
        pckts = []
        
        for i in range(0,4):  
            sleep(1)
            pckts.append(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ND_NS())

        pckts.append(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        
        self.ifx.replies_with(pckts)
        
        o = self.get_outcome(suite.NeighborSolicitationOriginationReachabilityConfirmationLinkLocalToLinkLocalTestCase)
        
        self.assertCheckFails(o)

    def test_prefix_information_option_processing_no_icmp_1(self):
        
        pckts = []
        
        for i in range(0,3):  
            sleep(1)
            pckts.append(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ND_NS())
        
        self.ifx.replies_with(pckts)
        
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        
        pckts = []
        
        sleep(1)
        
        for i in range(0,3):  
            sleep(1)
            self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ND_NS(), 4+i)  
        
        o = self.get_outcome(suite.NeighborSolicitationOriginationReachabilityConfirmationLinkLocalToLinkLocalTestCase)
        
        self.assertCheckFails(o)
        
    def test_prefix_information_option_processing_no_icmp_2(self):
        
        pckts = []
        
        for i in range(0,3):  
            sleep(1)
            pckts.append(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ND_NS())

        pckts.append(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        
        self.ifx.replies_with(pckts)
        
        pckts = []
        
        sleep(1)
        
        for i in range(0,3):  
            sleep(1)
            self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ND_NS(), 4+i) 
        
        o = self.get_outcome(suite.NeighborSolicitationOriginationReachabilityConfirmationLinkLocalToLinkLocalTestCase)
        
        self.assertCheckFails(o)      
        
    def test_prefix_information_option_processing_ns_too_many_1(self):
        
        pckts = []
        
        for i in range(0,3):  
            sleep(1)
            pckts.append(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ND_NS())

        pckts.append(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        
        self.ifx.replies_with(pckts)
        
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        
        pckts = []
        
        sleep(1)
        
        for i in range(0,4):  
            sleep(1)
            self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ND_NS(), 4+i) 
            
        o = self.get_outcome(suite.NeighborSolicitationOriginationReachabilityConfirmationLinkLocalToLinkLocalTestCase)
        
        self.assertCheckFails(o)
        
    def test_prefix_information_option_processing_ns_too_little(self):
        
        pckts = []
        
        for i in range(0,3):  
            sleep(1)
            pckts.append(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ND_NS())

        pckts.append(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        
        self.ifx.replies_with(pckts)
        
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        
        o = self.get_outcome(suite.NeighborSolicitationOriginationReachabilityConfirmationLinkLocalToLinkLocalTestCase)
        
        self.assertCheckFails(o)
        
    def test_prefix_information_option_processing_ns_too_long(self):
        
        pckts = []
        
        for i in range(0,3):  
            sleep(2)
            pckts.append(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ND_NS())

        pckts.append(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        
        self.ifx.replies_with(pckts)
        
        o = self.get_outcome(suite.NeighborSolicitationOriginationReachabilityConfirmationLinkLocalToLinkLocalTestCase)
        
        self.assertCheckFails(o)
        
    def test_prefix_information_option_processing_ns_too_short(self):
        
        pckts = []
        
        for i in range(0,3):  
            sleep(0.5)
            pckts.append(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ND_NS())

        pckts.append(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        
        self.ifx.replies_with(pckts)
        
        o = self.get_outcome(suite.NeighborSolicitationOriginationReachabilityConfirmationLinkLocalToLinkLocalTestCase)
                
        self.assertCheckFails(o)        