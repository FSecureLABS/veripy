from contrib.rfc3315.server import dhcpv6_transmission_of_renew_messages as suite
from scapy.all import *
from veripy.testability import ComplianceTestTestCase

class DHCPv6TransmissionOfConfirmMessagesTestCaseTestCase(ComplianceTestTestCase):

    def test_flow_label_DHCP_renew_normal_test_case(self):
        self.ui.inputs.append("y")         
        #Start by responding to solicit broadcast:
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/DHCP6_Advertise())
        #respond to request with reply
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/DHCP6_Reply()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131",preflft=50,validlft=80))
        #echo request
        self.ifx.sends(IPv6(src=str(self.ifx.global_ip()), dst=self.test_network.link(2).prefix+"3131")/ICMPv6EchoRequest(),0)
        #Get the reply packet but do nothing
        self.ui.inputs.append("y")        
        self.ifx.replies_with(None)        

        #replies to renew with DHCP reply:
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()),dst=str(self.tn1.link_local_ip()))/DHCP6_Reply()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"))
                    
        self.ifx.sends(IPv6(src=str(self.ifx.global_ip()),dst=self.test_network.link(2).prefix+"3131")/ICMPv6EchoRequest(),52)

        o = self.get_outcome(suite.DHCPv6TransmissionOfRenewMessagesTestCase)
        
        self.assertCheckPasses(o)
        
    def test_flow_label_DHCP_renew_no_advertise_test_case(self):
        self.ui.inputs.append("y")         
        #Start by responding to solicit broadcast:
        #self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/DHCP6_Advertise())
        #respond to request with reply
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/DHCP6_Reply()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131",preflft=50,validlft=80))
        #echo request
        self.ifx.sends(IPv6(src=str(self.ifx.global_ip()), dst=self.test_network.link(2).prefix+"3131")/ICMPv6EchoRequest(),0)
        #Get the reply packet but do nothing
        self.ui.inputs.append("y")        
        self.ifx.replies_with(None)        

        #replies to renew with DHCP reply:
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()),dst=str(self.tn1.link_local_ip()))/DHCP6_Reply()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"))
                    
        self.ifx.sends(IPv6(src=str(self.ifx.global_ip()),dst=self.test_network.link(2).prefix+"3131")/ICMPv6EchoRequest(),52)

        o = self.get_outcome(suite.DHCPv6TransmissionOfRenewMessagesTestCase)
        
        self.assertCheckFails(o)
        
    
    def test_flow_label_DHCP_renew_non_unicast_advertise_test_case(self):
        self.ui.inputs.append("y")         
        #Start by responding to solicit broadcast:
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst="ff02::1:2")/DHCP6_Advertise())
        #respond to request with reply
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/DHCP6_Reply()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131",preflft=50,validlft=80))
        #echo request
        self.ifx.sends(IPv6(src=str(self.ifx.global_ip()), dst=self.test_network.link(2).prefix+"3131")/ICMPv6EchoRequest(),0)
        #Get the reply packet but do nothing
        self.ui.inputs.append("y")        
        self.ifx.replies_with(None)        

        #replies to renew with DHCP reply:
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()),dst=str(self.tn1.link_local_ip()))/DHCP6_Reply()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"))
                    
        self.ifx.sends(IPv6(src=str(self.ifx.global_ip()),dst=self.test_network.link(2).prefix+"3131")/ICMPv6EchoRequest(),52)

        o = self.get_outcome(suite.DHCPv6TransmissionOfRenewMessagesTestCase)
        
        self.assertCheckFails(o)        
        
        
    def test_flow_label_DHCP_renew_no_reply_test_case(self):
        self.ui.inputs.append("y")         
        #Start by responding to solicit broadcast:
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/DHCP6_Advertise())
        #respond to request with reply
        #self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/DHCP6_Reply()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131",preflft=50,validlft=80))
        #echo request
        self.ifx.sends(IPv6(src=str(self.ifx.global_ip()), dst=self.test_network.link(2).prefix+"3131")/ICMPv6EchoRequest(),0)
        #Get the reply packet but do nothing
        self.ui.inputs.append("y")        
        self.ifx.replies_with(None)        

        #replies to renew with DHCP reply:
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()),dst=str(self.tn1.link_local_ip()))/DHCP6_Reply()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"))
                    
        self.ifx.sends(IPv6(src=str(self.ifx.global_ip()),dst=self.test_network.link(2).prefix+"3131")/ICMPv6EchoRequest(),52)

        o = self.get_outcome(suite.DHCPv6TransmissionOfRenewMessagesTestCase)
        
        self.assertCheckFails(o)   
        
        
    def test_flow_label_DHCP_renew_no_reply_DHCP6OptIAAddress_test_case(self):
        self.ui.inputs.append("y")         
        #Start by responding to solicit broadcast:
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/DHCP6_Advertise())
        #respond to request with reply
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/DHCP6_Reply())
        #echo request
        self.ifx.sends(IPv6(src=str(self.ifx.global_ip()), dst=self.test_network.link(2).prefix+"3131")/ICMPv6EchoRequest(),0)
        #Get the reply packet but do nothing
        self.ui.inputs.append("y")        
        self.ifx.replies_with(None)        

        #replies to renew with DHCP reply:
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()),dst=str(self.tn1.link_local_ip()))/DHCP6_Reply()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"))
                    
        self.ifx.sends(IPv6(src=str(self.ifx.global_ip()),dst=self.test_network.link(2).prefix+"3131")/ICMPv6EchoRequest(),52)

        o = self.get_outcome(suite.DHCPv6TransmissionOfRenewMessagesTestCase)
        
        self.assertCheckFails(o)   
        
        
    def test_flow_label_DHCP_renew_different_DHCP6OptIAAddress_test_case(self):
        self.ui.inputs.append("y")         
        #Start by responding to solicit broadcast:
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/DHCP6_Advertise())
        #respond to request with reply
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/DHCP6_Reply()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3000",preflft=50,validlft=80))
        #echo request
        self.ifx.sends(IPv6(src=str(self.ifx.global_ip()), dst=self.test_network.link(2).prefix+"3131")/ICMPv6EchoRequest(),0)
        #Get the reply packet but do nothing
        self.ui.inputs.append("y")        
        self.ifx.replies_with(None)        

        #replies to renew with DHCP reply:
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()),dst=str(self.tn1.link_local_ip()))/DHCP6_Reply()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"))
                    
        self.ifx.sends(IPv6(src=str(self.ifx.global_ip()),dst=self.test_network.link(2).prefix+"3131")/ICMPv6EchoRequest(),52)

        o = self.get_outcome(suite.DHCPv6TransmissionOfRenewMessagesTestCase)
        
        self.assertCheckFails(o)  


    def test_flow_label_DHCP_renew_bad_prelft_val_test_case(self):
        self.ui.inputs.append("y")         
        #Start by responding to solicit broadcast:
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/DHCP6_Advertise())
        #respond to request with reply
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/DHCP6_Reply()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131",preflft=1,validlft=80))
        #echo request
        self.ifx.sends(IPv6(src=str(self.ifx.global_ip()), dst=self.test_network.link(2).prefix+"3131")/ICMPv6EchoRequest(),0)
        #Get the reply packet but do nothing
        self.ui.inputs.append("y")        
        self.ifx.replies_with(None)        

        #replies to renew with DHCP reply:
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()),dst=str(self.tn1.link_local_ip()))/DHCP6_Reply()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"))
                    
        self.ifx.sends(IPv6(src=str(self.ifx.global_ip()),dst=self.test_network.link(2).prefix+"3131")/ICMPv6EchoRequest(),52)

        o = self.get_outcome(suite.DHCPv6TransmissionOfRenewMessagesTestCase)
        
        self.assertCheckFails(o)
        
    def test_flow_label_DHCP_renew_bad_validlft_val_test_case(self):
        self.ui.inputs.append("y")         
        #Start by responding to solicit broadcast:
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/DHCP6_Advertise())
        #respond to request with reply
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/DHCP6_Reply()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131",preflft=50,validlft=1))
        #echo request
        self.ifx.sends(IPv6(src=str(self.ifx.global_ip()), dst=self.test_network.link(2).prefix+"3131")/ICMPv6EchoRequest(),0)
        #Get the reply packet but do nothing
        self.ui.inputs.append("y")        
        self.ifx.replies_with(None)        

        #replies to renew with DHCP reply:
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()),dst=str(self.tn1.link_local_ip()))/DHCP6_Reply()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"))
                    
        self.ifx.sends(IPv6(src=str(self.ifx.global_ip()),dst=self.test_network.link(2).prefix+"3131")/ICMPv6EchoRequest(),52)

        o = self.get_outcome(suite.DHCPv6TransmissionOfRenewMessagesTestCase)
        
        self.assertCheckFails(o) 
        
    def test_flow_label_DHCP_renew_no_prelft_or_validlft_test_case(self):
        self.ui.inputs.append("y")         
        #Start by responding to solicit broadcast:
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/DHCP6_Advertise())
        #respond to request with reply
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/DHCP6_Reply()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"))
        #echo request
        self.ifx.sends(IPv6(src=str(self.ifx.global_ip()), dst=self.test_network.link(2).prefix+"3131")/ICMPv6EchoRequest(),0)
        #Get the reply packet but do nothing
        self.ui.inputs.append("y")        
        self.ifx.replies_with(None)        

        #replies to renew with DHCP reply:
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()),dst=str(self.tn1.link_local_ip()))/DHCP6_Reply()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"))
                    
        self.ifx.sends(IPv6(src=str(self.ifx.global_ip()),dst=self.test_network.link(2).prefix+"3131")/ICMPv6EchoRequest(),52)

        o = self.get_outcome(suite.DHCPv6TransmissionOfRenewMessagesTestCase)
        
        self.assertCheckFails(o)  
        
        
    def test_flow_label_DHCP_renew_no_echoreply_test_case(self):
        self.ui.inputs.append("y")         
        #Start by responding to solicit broadcast:
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/DHCP6_Advertise())
        #respond to request with reply
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/DHCP6_Reply()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131",preflft=50,validlft=80))
        #echo request
        #self.ifx.sends(IPv6(src=str(self.ifx.global_ip()), dst=self.test_network.link(2).prefix+"3131")/ICMPv6EchoRequest(),0)
        #Get the reply packet but do nothing
        self.ui.inputs.append("y")        
        self.ifx.replies_with(None)        

        #replies to renew with DHCP reply:
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()),dst=str(self.tn1.link_local_ip()))/DHCP6_Reply()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"))
                    
        self.ifx.sends(IPv6(src=str(self.ifx.global_ip()),dst=self.test_network.link(2).prefix+"3131")/ICMPv6EchoRequest(),52)

        o = self.get_outcome(suite.DHCPv6TransmissionOfRenewMessagesTestCase)
        
        self.assertCheckFails(o)   
        
        
    def test_flow_label_DHCP_bad_echo_dst_test_case(self):
        self.ui.inputs.append("y")         
        #Start by responding to solicit broadcast:
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/DHCP6_Advertise())
        #respond to request with reply
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/DHCP6_Reply()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131",preflft=50,validlft=80))
        #echo request
        self.ifx.sends(IPv6(src=str(self.ifx.global_ip()), dst=self.test_network.link(2).prefix+"0100")/ICMPv6EchoRequest(),0)
        #Get the reply packet but do nothing
        self.ui.inputs.append("y")        
        self.ifx.replies_with(None)        

        #replies to renew with DHCP reply:
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()),dst=str(self.tn1.link_local_ip()))/DHCP6_Reply()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"))
                    
        self.ifx.sends(IPv6(src=str(self.ifx.global_ip()),dst=self.test_network.link(2).prefix+"3131")/ICMPv6EchoRequest(),52)

        o = self.get_outcome(suite.DHCPv6TransmissionOfRenewMessagesTestCase)
        
        self.assertCheckFails(o)       
        
        
    def test_flow_label_DHCP_renew_no_DHCP6reply_test_case(self):
        self.ui.inputs.append("y")         
        #Start by responding to solicit broadcast:
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/DHCP6_Advertise())
        #respond to request with reply
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/DHCP6_Reply()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131",preflft=50,validlft=80))
        #echo request
        self.ifx.sends(IPv6(src=str(self.ifx.global_ip()), dst=self.test_network.link(2).prefix+"3131")/ICMPv6EchoRequest(),0)
        #Get the reply packet but do nothing
        self.ui.inputs.append("y")        
        self.ifx.replies_with(None)        

        #replies to renew with DHCP reply:
        #self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()),dst=str(self.tn1.link_local_ip()))/DHCP6_Reply()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"))
                    
        self.ifx.sends(IPv6(src=str(self.ifx.global_ip()),dst=self.test_network.link(2).prefix+"3131")/ICMPv6EchoRequest(),52)

        o = self.get_outcome(suite.DHCPv6TransmissionOfRenewMessagesTestCase)
        
        self.assertCheckFails(o)      
        
        
    def test_flow_label_DHCP_renew_bad_DHCP6reply_address_test_case(self):
        self.ui.inputs.append("y")         
        #Start by responding to solicit broadcast:
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/DHCP6_Advertise())
        #respond to request with reply
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/DHCP6_Reply()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131",preflft=50,validlft=80))
        #echo request
        self.ifx.sends(IPv6(src=str(self.ifx.global_ip()), dst=self.test_network.link(2).prefix+"3131")/ICMPv6EchoRequest(),0)
        #Get the reply packet but do nothing
        self.ui.inputs.append("y")        
        self.ifx.replies_with(None)        

        #replies to renew with DHCP reply:
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()),dst=str(self.tn1.link_local_ip()))/DHCP6_Reply()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3000"))
                    
        self.ifx.sends(IPv6(src=str(self.ifx.global_ip()),dst=self.test_network.link(2).prefix+"3131")/ICMPv6EchoRequest(),52)

        o = self.get_outcome(suite.DHCPv6TransmissionOfRenewMessagesTestCase)
        
        self.assertCheckFails(o)
        
    def test_flow_label_DHCP_renew_no_DHCP6replyDHCP6OptIAAddress_test_case(self):
        self.ui.inputs.append("y")         
        #Start by responding to solicit broadcast:
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/DHCP6_Advertise())
        #respond to request with reply
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/DHCP6_Reply()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131",preflft=50,validlft=80))
        #echo request
        self.ifx.sends(IPv6(src=str(self.ifx.global_ip()), dst=self.test_network.link(2).prefix+"3131")/ICMPv6EchoRequest(),0)
        #Get the reply packet but do nothing
        self.ui.inputs.append("y")        
        self.ifx.replies_with(None)        

        #replies to renew with DHCP reply:
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()),dst=str(self.tn1.link_local_ip()))/DHCP6_Reply())
                    
        self.ifx.sends(IPv6(src=str(self.ifx.global_ip()),dst=self.test_network.link(2).prefix+"3131")/ICMPv6EchoRequest(),52)

        o = self.get_outcome(suite.DHCPv6TransmissionOfRenewMessagesTestCase)
        
        self.assertCheckFails(o)           
        
        
    def test_flow_label_DHCP_renew_no_2nd_echo_reply_test_case(self):
        self.ui.inputs.append("y")         
        #Start by responding to solicit broadcast:
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/DHCP6_Advertise())
        #respond to request with reply
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/DHCP6_Reply()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131",preflft=50,validlft=80))
        #echo request
        self.ifx.sends(IPv6(src=str(self.ifx.global_ip()), dst=self.test_network.link(2).prefix+"3131")/ICMPv6EchoRequest(),0)
        #Get the reply packet but do nothing
        self.ui.inputs.append("y")        
        self.ifx.replies_with(None)        

        #replies to renew with DHCP reply:
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()),dst=str(self.tn1.link_local_ip()))/DHCP6_Reply()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"))
                    
        #self.ifx.sends(IPv6(src=str(self.ifx.global_ip()),dst=self.test_network.link(2).prefix+"3131")/ICMPv6EchoRequest(),52)

        o = self.get_outcome(suite.DHCPv6TransmissionOfRenewMessagesTestCase)
        
        self.assertCheckFails(o)                                                 