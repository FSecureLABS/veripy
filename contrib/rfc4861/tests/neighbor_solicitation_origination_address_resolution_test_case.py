from contrib.rfc4861 import neighbor_solicitation_origination_address_resolution as suite
from scapy.all import *
from veripy.testability import ComplianceTestTestCase
from veripy.assertions import *
from time import sleep

class NeighborSolicitationOriginationAddressResolutionLinkLocalTestCaseTestCase(ComplianceTestTestCase):
    
    def test_neighbor_solicitation_origination_address_resolution_linklocal_no_reply(self):
        o = self.get_outcome(suite.NeighborSolicitationOriginationAddressResolutionLinkLocalTestCase)
        
        self.assertCheckFails(o)    
    
    def test_neighbor_solicitation_origination_address_resolution_linklocal_reply(self):
        
        pckts = []
        
        for i in range(0,3):  
            sleep(1)
            pckts.append(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS()/ICMPv6NDOptLLA(lla=str(self.ifx.ll_addr())))

        self.ifx.replies_with(pckts)
        
        pckts = []
        
        for i in range(0,3):  
            sleep(5)
            pckts.append(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS()/ICMPv6NDOptLLA(lla=str(self.ifx.ll_addr())))
        
        self.ifx.replies_with(pckts)

        o = self.get_outcome(suite.NeighborSolicitationOriginationAddressResolutionLinkLocalTestCase)
        
        self.assertCheckPasses(o)    
    
    def test_neighbor_solicitation_origination_address_resolution_linklocal_ignore_timeout_5(self):
        
        pckts = []
        
        for i in range(0,3):  
            sleep(1)
            pckts.append(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/
                         ICMPv6ND_NS()/ICMPv6NDOptLLA(lla=str(self.ifx.ll_addr())))

        self.ifx.replies_with(pckts)
        
        pckts = []
        
        for i in range(0,3):  
            sleep(1)
            pckts.append(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/
                         ICMPv6ND_NS()/ICMPv6NDOptLLA(lla=str(self.ifx.ll_addr())))
        
        self.ifx.replies_with(pckts)

        o = self.get_outcome(suite.NeighborSolicitationOriginationAddressResolutionLinkLocalTestCase)
        
        self.assertCheckFails(o)

    def test_neighbor_solicitation_origination_address_resolution_linklocal_ignore_timeout_1(self):
        
        pckts = []
        
        for i in range(0,3):  
            sleep(5)
            pckts.append(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/
                         ICMPv6ND_NS()/ICMPv6NDOptLLA(lla=str(self.ifx.ll_addr())))

        self.ifx.replies_with(pckts)
        
        pckts = []
        
        for i in range(0,3):  
            sleep(5)
            pckts.append(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/
                         ICMPv6ND_NS()/ICMPv6NDOptLLA(lla=str(self.ifx.ll_addr())))
        
        self.ifx.replies_with(pckts)

        o = self.get_outcome(suite.NeighborSolicitationOriginationAddressResolutionLinkLocalTestCase)
        
        self.assertCheckFails(o)

    def test_neighbor_solicitation_origination_address_resolution_linklocal_wrong_lla_1(self):
        
        pckts = []
        
        for i in range(0,3):  
            sleep(1)
            pckts.append(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/
                         ICMPv6ND_NS()/ICMPv6NDOptLLA(lla=str(self.ifx.ll_addr)))

        self.ifx.replies_with(pckts)
        
        pckts = []
        
        for i in range(0,3):  
            sleep(1)
            pckts.append(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/
                         ICMPv6ND_NS()/ICMPv6NDOptLLA())
        
        self.ifx.replies_with(pckts)

        o = self.get_outcome(suite.NeighborSolicitationOriginationAddressResolutionLinkLocalTestCase)
        
        self.assertCheckFails(o)   
        
    def test_neighbor_solicitation_origination_address_resolution_linklocal_wrong_lla_2(self):
        
        pckts = []
        
        for i in range(0,3):  
            sleep(1)
            pckts.append(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/
                         ICMPv6ND_NS()/ICMPv6NDOptLLA())

        self.ifx.replies_with(pckts)
        
        pckts = []
        
        for i in range(0,3):  
            sleep(1)
            pckts.append(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/
                         ICMPv6ND_NS()/ICMPv6NDOptLLA())
        
        self.ifx.replies_with(pckts)

        o = self.get_outcome(suite.NeighborSolicitationOriginationAddressResolutionLinkLocalTestCase)
        
        self.assertCheckFails(o)

    def test_neighbor_solicitation_origination_address_resolution_linklocal_no_lla_1(self):
        
        pckts = []
        
        for i in range(0,3):  
            sleep(1)
            pckts.append(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS())

        self.ifx.replies_with(pckts)
        
        pckts = []
        
        for i in range(0,3):  
            sleep(5)
            pckts.append(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS()/ICMPv6NDOptLLA(lla=str(self.ifx.ll_addr())))
        
        self.ifx.replies_with(pckts)

        o = self.get_outcome(suite.NeighborSolicitationOriginationAddressResolutionLinkLocalTestCase)
        
        self.assertCheckFails(o)      
        
    def test_neighbor_solicitation_origination_address_resolution_linklocal_no_lla_2(self):
        
        pckts = []
        
        for i in range(0,3):  
            sleep(1)
            pckts.append(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS()/ICMPv6NDOptLLA(lla=str(self.ifx.ll_addr())))

        self.ifx.replies_with(pckts)
        
        pckts = []
        
        for i in range(0,3):  
            sleep(5)
            pckts.append(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.link_local_ip()))/ICMPv6ND_NS())
        
        self.ifx.replies_with(pckts)

        o = self.get_outcome(suite.NeighborSolicitationOriginationAddressResolutionLinkLocalTestCase)
        
        self.assertCheckFails(o)   
        
class NeighborSolicitationOriginationAddressResolutionGlobalTestCaseTestCase(ComplianceTestTestCase):
    
    def test_neighbor_solicitation_origination_address_resolution_global_no_reply(self):
        o = self.get_outcome(suite.NeighborSolicitationOriginationAddressResolutionGlobalTestCase)
        
        self.assertCheckFails(o)    
    
    def test_neighbor_solicitation_origination_address_resolution_global_reply(self):
        
        pckts = []
        
        for i in range(0,3):  
            sleep(1)
            pckts.append(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ND_NS()/ICMPv6NDOptLLA(lla=str(self.ifx.ll_addr())))

        self.ifx.replies_with(pckts)
        
        pckts = []
        
        for i in range(0,3):  
            sleep(5)
            pckts.append(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ND_NS()/ICMPv6NDOptLLA(lla=str(self.ifx.ll_addr())))
        
        self.ifx.replies_with(pckts)

        o = self.get_outcome(suite.NeighborSolicitationOriginationAddressResolutionGlobalTestCase)
        
        self.assertCheckPasses(o)    
    
    def test_neighbor_solicitation_origination_address_resolution_global_ignore_timeout_5(self):
        
        pckts = []
        
        for i in range(0,3):  
            sleep(1)
            pckts.append(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/
                         ICMPv6ND_NS()/ICMPv6NDOptLLA(lla=str(self.ifx.ll_addr())))

        self.ifx.replies_with(pckts)
        
        pckts = []
        
        for i in range(0,3):  
            sleep(1)
            pckts.append(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/
                         ICMPv6ND_NS()/ICMPv6NDOptLLA(lla=str(self.ifx.ll_addr())))
        
        self.ifx.replies_with(pckts)

        o = self.get_outcome(suite.NeighborSolicitationOriginationAddressResolutionGlobalTestCase)
        
        self.assertCheckFails(o)

    def test_neighbor_solicitation_origination_address_resolution_global_ignore_timeout_1(self):
        
        pckts = []
        
        for i in range(0,3):  
            sleep(5)
            pckts.append(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/
                         ICMPv6ND_NS()/ICMPv6NDOptLLA(lla=str(self.ifx.ll_addr())))

        self.ifx.replies_with(pckts)
        
        pckts = []
        
        for i in range(0,3):  
            sleep(5)
            pckts.append(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/
                         ICMPv6ND_NS()/ICMPv6NDOptLLA(lla=str(self.ifx.ll_addr())))
        
        self.ifx.replies_with(pckts)

        o = self.get_outcome(suite.NeighborSolicitationOriginationAddressResolutionGlobalTestCase)
        
        self.assertCheckFails(o)

    def test_neighbor_solicitation_origination_address_resolution_global_wrong_lla_1(self):
        
        pckts = []
        
        for i in range(0,3):  
            sleep(1)
            pckts.append(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/
                         ICMPv6ND_NS()/ICMPv6NDOptLLA(lla=str(self.ifx.ll_addr)))

        self.ifx.replies_with(pckts)
        
        pckts = []
        
        for i in range(0,3):  
            sleep(1)
            pckts.append(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/
                         ICMPv6ND_NS()/ICMPv6NDOptLLA())
        
        self.ifx.replies_with(pckts)

        o = self.get_outcome(suite.NeighborSolicitationOriginationAddressResolutionGlobalTestCase)
        
        self.assertCheckFails(o)   
        
    def test_neighbor_solicitation_origination_address_resolution_global_wrong_lla_2(self):
        
        pckts = []
        
        for i in range(0,3):  
            sleep(1)
            pckts.append(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/
                         ICMPv6ND_NS()/ICMPv6NDOptLLA())

        self.ifx.replies_with(pckts)
        
        pckts = []
        
        for i in range(0,3):  
            sleep(1)
            pckts.append(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/
                         ICMPv6ND_NS()/ICMPv6NDOptLLA())
        
        self.ifx.replies_with(pckts)

        o = self.get_outcome(suite.NeighborSolicitationOriginationAddressResolutionGlobalTestCase)
        
        self.assertCheckFails(o)

    def test_neighbor_solicitation_origination_address_resolution_global_no_lla_1(self):
        
        pckts = []
        
        for i in range(0,3):  
            sleep(1)
            pckts.append(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ND_NS())

        self.ifx.replies_with(pckts)
        
        pckts = []
        
        for i in range(0,3):  
            sleep(5)
            pckts.append(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ND_NS()/ICMPv6NDOptLLA(lla=str(self.ifx.ll_addr())))
        
        self.ifx.replies_with(pckts)

        o = self.get_outcome(suite.NeighborSolicitationOriginationAddressResolutionGlobalTestCase)
        
        self.assertCheckFails(o)      
        
    def test_neighbor_solicitation_origination_address_resolution_global_no_lla_2(self):
        
        pckts = []
        
        for i in range(0,3):  
            sleep(1)
            pckts.append(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ND_NS()/ICMPv6NDOptLLA(lla=str(self.ifx.ll_addr())))

        self.ifx.replies_with(pckts)
        
        pckts = []
        
        for i in range(0,3):  
            sleep(5)
            pckts.append(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ND_NS())
        
        self.ifx.replies_with(pckts)

        o = self.get_outcome(suite.NeighborSolicitationOriginationAddressResolutionGlobalTestCase)
        
        self.assertCheckFails(o) 