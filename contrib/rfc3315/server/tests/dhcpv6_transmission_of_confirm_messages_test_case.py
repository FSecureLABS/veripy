from contrib.rfc3315.server import dhcpv6_transmission_of_confirm_messages as suite
from scapy.all import *
from veripy.testability import ComplianceTestTestCase

class DHCPv6TransmissionOfConfirmMessagesTestCaseTestCase(ComplianceTestTestCase):

    def test_flow_label_DHCP_normal_test_case(self):
        #Start by responding to solicit broadcast:
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/DHCP6_Advertise())
        #respond to request with reply
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/DHCP6_Reply()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"))
        #echo request
        self.ifx.sends(IPv6(src=str(self.ifx.global_ip()), dst=self.test_network.link(2).prefix+"3131")/ICMPv6EchoRequest(),1)
        
        #Get the reply packet but do nothing
        self.ifx.replies_with(None)
        
        #wait for a confirm
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()),dst=str(self.tn1.link_local_ip()))/DHCP6_Reply()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"))
         
        #echo request
        self.ifx.sends(IPv6(src=str(self.ifx.global_ip()), dst=self.test_network.link(2).prefix+"3131")/ICMPv6EchoRequest(),3)
        #Get the reply packet but do nothing
        self.ifx.replies_with(None)
        
        
        o = self.get_outcome(suite.DHCPv6TransmissionOfConfirmMessagesTestCase)
        
        self.assertCheckPasses(o)
        

    def test_flow_label_DHCP_no_advertise_test_case(self):
        #SKIP this step!
        #self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/DHCP6_Advertise())
        #respond to request with reply
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/DHCP6_Reply()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"))
        #echo request
        self.ifx.sends(IPv6(src=str(self.ifx.global_ip()), dst=self.test_network.link(2).prefix+"3131")/ICMPv6EchoRequest(),1)
        
        #Get the reply packet but do nothing
        self.ifx.replies_with(None)
        
        #wait for a confirm
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()),dst=str(self.tn1.link_local_ip()))/DHCP6_Reply()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"))
         
        #echo request
        self.ifx.sends(IPv6(src=str(self.ifx.global_ip()), dst=self.test_network.link(2).prefix+"3131")/ICMPv6EchoRequest(),3)
        #Get the reply packet but do nothing
        self.ifx.replies_with(None)
        
        
        o = self.get_outcome(suite.DHCPv6TransmissionOfConfirmMessagesTestCase)
        
        self.assertCheckFails(o)        
  
  
  
  
  
  
    def test_flow_label_DHCP_no_reply_test_case(self):
        #Start by responding to solicit broadcast:
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/DHCP6_Advertise())
        #Skip this step!
        #self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/DHCP6_Reply()/DHCP6OptIAAddress(addr="2001:16d8:ee47::bbbb"))
        #echo request
        self.ifx.sends(IPv6(src=str(self.ifx.global_ip()), dst=self.test_network.link(2).prefix+"3131")/ICMPv6EchoRequest(),1)
        
        #Get the reply packet but do nothing
        self.ifx.replies_with(None)
        
        #wait for a confirm
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()),dst=str(self.tn1.link_local_ip()))/DHCP6_Reply()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"))
         
        #echo request
        self.ifx.sends(IPv6(src=str(self.ifx.global_ip()), dst=self.test_network.link(2).prefix+"3131")/ICMPv6EchoRequest(),3)
        #Get the reply packet but do nothing
        self.ifx.replies_with(None)
        
        
        o = self.get_outcome(suite.DHCPv6TransmissionOfConfirmMessagesTestCase)
        
        self.assertCheckFails(o)          
                             
                             
    def test_flow_label_DHCP_no_echo_request_test_case(self):
        #Start by responding to solicit broadcast:
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/DHCP6_Advertise())
        #respond to request with reply
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/DHCP6_Reply()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"))
        #SKIP this step
        #self.ifx.sends(IPv6(src=str(self.ifx.global_ip()), dst="2001:16d8:ee47::bbbb")/ICMPv6EchoRequest(),1)
        
        #Get the reply packet but do nothing
        self.ifx.replies_with(None)
        
        #wait for a confirm
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()),dst=str(self.tn1.link_local_ip()))/DHCP6_Reply()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"))
         
        #echo request
        self.ifx.sends(IPv6(src=str(self.ifx.global_ip()), dst=self.test_network.link(2).prefix+"3131")/ICMPv6EchoRequest(),3)
        #Get the reply packet but do nothing
        self.ifx.replies_with(None)
        
        
        o = self.get_outcome(suite.DHCPv6TransmissionOfConfirmMessagesTestCase)
        
        self.assertCheckFails(o)                            
                             
                             
                             
    def test_flow_label_DHCP_no_echo_request_test_case(self):
        #Start by responding to solicit broadcast:
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/DHCP6_Advertise())
        #respond to request with reply
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/DHCP6_Reply()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"))
        #echo request
        self.ifx.sends(IPv6(src=str(self.ifx.global_ip()), dst=self.test_network.link(2).prefix+"3131")/ICMPv6EchoRequest(),1)
        
        #Get the reply packet but do nothing
        self.ifx.replies_with(None)
        
        #SKIP this step!
        #self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()),dst=str(self.tn1.link_local_ip()))/DHCP6_Reply()/DHCP6OptIAAddress(addr="2001:16d8:ee47::bbbb"))
         
        #echo request
        self.ifx.sends(IPv6(src=str(self.ifx.global_ip()), dst=self.test_network.link(2).prefix+"3131")/ICMPv6EchoRequest(),3)
        #Get the reply packet but do nothing
        self.ifx.replies_with(None)
        
        
        o = self.get_outcome(suite.DHCPv6TransmissionOfConfirmMessagesTestCase)
        
        self.assertCheckFails(o)                                
          
          
                             
    def test_flow_label_DHCP_no_2nd_echo_test_case(self):
        #Start by responding to solicit broadcast:
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/DHCP6_Advertise())
        #respond to request with reply
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/DHCP6_Reply()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"))
        #echo request
        self.ifx.sends(IPv6(src=str(self.ifx.global_ip()), dst=self.test_network.link(2).prefix+"3131")/ICMPv6EchoRequest(),1)
        
        #Get the reply packet but do nothing
        self.ifx.replies_with(None)
        
        #wait for a confirm
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()),dst=str(self.tn1.link_local_ip()))/DHCP6_Reply()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"))
         
        #SKIP
        #self.ifx.sends(IPv6(src=str(self.ifx.global_ip()), dst="2001:16d8:ee47::bbbb")/ICMPv6EchoRequest(),3)
        #Get the reply packet but do nothing
        self.ifx.replies_with(None)
        
        
        o = self.get_outcome(suite.DHCPv6TransmissionOfConfirmMessagesTestCase)
        
        self.assertCheckFails(o)                             
                             
                             
                             
    def test_flow_label_DHCP_no_address_option_test_case(self):
        #Start by responding to solicit broadcast:
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/DHCP6_Advertise())
        #NO ADDRESS OPTION
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/DHCP6_Reply())
        #echo request
        self.ifx.sends(IPv6(src=str(self.ifx.global_ip()), dst=self.test_network.link(2).prefix+"3131")/ICMPv6EchoRequest(),1)
        
        #Get the reply packet but do nothing
        self.ifx.replies_with(None)
        
        #wait for a confirm
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()),dst=str(self.tn1.link_local_ip()))/DHCP6_Reply()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"))
         
        #echo request
        self.ifx.sends(IPv6(src=str(self.ifx.global_ip()), dst=self.test_network.link(2).prefix+"3131")/ICMPv6EchoRequest(),3)
        #Get the reply packet but do nothing
        self.ifx.replies_with(None)
        
        
        o = self.get_outcome(suite.DHCPv6TransmissionOfConfirmMessagesTestCase)
        
        self.assertCheckFails(o)                             
                          
                          
                             
    def test_flow_label_DHCP_no_comfirm_address_test_case(self):
        #Start by responding to solicit broadcast:
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/DHCP6_Advertise())
        #respond to request with reply
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/DHCP6_Reply()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"))
        #echo request
        self.ifx.sends(IPv6(src=str(self.ifx.global_ip()), dst=self.test_network.link(2).prefix+"3131")/ICMPv6EchoRequest(),1)
        
        #Get the reply packet but do nothing
        self.ifx.replies_with(None)
        
        #wait for a confirm
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()),dst=str(self.tn1.link_local_ip()))/DHCP6_Reply())
         
        #echo request
        self.ifx.sends(IPv6(src=str(self.ifx.global_ip()), dst=self.test_network.link(2).prefix+"3131")/ICMPv6EchoRequest(),3)
        #Get the reply packet but do nothing
        self.ifx.replies_with(None)
        
        
        o = self.get_outcome(suite.DHCPv6TransmissionOfConfirmMessagesTestCase)
        
        self.assertCheckFails(o)                             
                             
                           
                             
    def test_flow_label_DHCP_bad_reply_address_test_case(self):
        #Start by responding to solicit broadcast:
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/DHCP6_Advertise())
        #respond to request with reply
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/DHCP6_Reply()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3333"))
        #echo request
        self.ifx.sends(IPv6(src=str(self.ifx.global_ip()), dst=self.test_network.link(2).prefix+"3131")/ICMPv6EchoRequest(),1)
        
        #Get the reply packet but do nothing
        self.ifx.replies_with(None)
        
        #wait for a confirm
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()),dst=str(self.tn1.link_local_ip()))/DHCP6_Reply())
         
        #echo request
        self.ifx.sends(IPv6(src=str(self.ifx.global_ip()), dst=self.test_network.link(2).prefix+"3131")/ICMPv6EchoRequest(),3)
        #Get the reply packet but do nothing
        self.ifx.replies_with(None)
        
        
        o = self.get_outcome(suite.DHCPv6TransmissionOfConfirmMessagesTestCase)
        
        self.assertCheckFails(o)       
        
        
    def test_flow_label_DHCP_bad_confirm_address_test_case(self):
        #Start by responding to solicit broadcast:
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/DHCP6_Advertise())
        #respond to request with reply
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/DHCP6_Reply()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"))
        #echo request
        self.ifx.sends(IPv6(src=str(self.ifx.global_ip()), dst=self.test_network.link(2).prefix+"3131")/ICMPv6EchoRequest(),1)
        
        #Get the reply packet but do nothing
        self.ifx.replies_with(None)
        
        #wait for a confirm
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()),dst=str(self.tn1.link_local_ip()))/DHCP6_Reply()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"1131"))
         
        #echo request
        self.ifx.sends(IPv6(src=str(self.ifx.global_ip()), dst=self.test_network.link(2).prefix+"3131")/ICMPv6EchoRequest(),3)
        #Get the reply packet but do nothing
        self.ifx.replies_with(None)
        
        
        o = self.get_outcome(suite.DHCPv6TransmissionOfConfirmMessagesTestCase)
        
        self.assertCheckFails(o)      
        
        
        
        
        
        
        
        
        
                              
                             
                             
                             