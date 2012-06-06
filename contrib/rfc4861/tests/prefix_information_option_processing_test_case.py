from contrib.rfc4861 import prefix_information_option_processing as suite
from scapy.all import *
from veripy.testability import ComplianceTestTestCase
from veripy.assertions import *

class PrefixInformationOptionProcessingTestCaseTestCase(ComplianceTestTestCase):
    
    def test_prefix_information_option_processing_no_reply_all(self):
        o = self.get_outcome(suite.PrefixInformationOptionProcessingTestCase)
        
        self.assertCheckFails(o)

    def test_prefix_information_option_processing_no_reply_one(self):
        #try an array of packets in replies with
        pckts = []
        
        for i in range(0,3):  
            pckts.append(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tr1.global_ip()))/ICMPv6ND_NS())

        self.ifx.replies_with(pckts)
        
        o = self.get_outcome(suite.PrefixInformationOptionProcessingTestCase)
        
        self.assertCheckFails(o)
     
    def test_prefix_information_option_processing_wrong_number_of_min_replies(self
                                                        ):
        #try an array of packets in replies with
        pckts = []
        
        for i in range(0,2):  
            pckts.append(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tr1.global_ip()))/ICMPv6ND_NS())

        self.ifx.replies_with(pckts)

        o = self.get_outcome(suite.PrefixInformationOptionProcessingTestCase)
        
        self.assertCheckFails(o)   
        
    def test_prefix_information_option_processing_wrong_number_of_max_replies(self):
        #try an array of packets in replies with
        pckts = []
        
        for i in range(0,2):  
            pckts.append(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tr1.global_ip()))/ICMPv6ND_NS())

        self.ifx.replies_with(pckts)

        o = self.get_outcome(suite.PrefixInformationOptionProcessingTestCase)
        
        self.assertCheckFails(o)   

    def test_prefix_information_option_processing_wrong_reply(self):
        #try an array of packets in replies with
        pckts = []
        
        for i in range(0,3):  
            pckts.append(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tr1.global_ip()))/ICMPv6EchoReply())

        self.ifx.replies_with(pckts)
            
        o = self.get_outcome(suite.PrefixInformationOptionProcessingTestCase)
        
        self.assertCheckFails(o)
                     
    def test_prefix_information_option_processing_reply(self):
        #try an array of packets in replies with
        pckts = []
        
        for i in range(0,3):  
            pckts.append(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tr1.global_ip()))/ICMPv6ND_NS())

        self.ifx.replies_with(pckts)

        self.ifx.replies_with(pckts)
        
        o = self.get_outcome(suite.PrefixInformationOptionProcessingTestCase)
        
        self.assertCheckPasses(o)