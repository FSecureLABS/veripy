from contrib.rfc3315.client import dhcpv6_transmission_of_renew_messages as suite
from scapy.all import *
from veripy.testability import ComplianceTestTestCase

class DHCPv6TransmissionOfRenewMessagesTestCase(ComplianceTestTestCase):

    
    def test_flow_label_DHCP_normal_test_case(self):
        #Start by sending solicit broadcast:
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1:2")/DHCP6_Solicit(),1)
        #Reply to the advertise with a request
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1:2")/DHCP6_Request()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"))
        
        #Respond to the reply with nothing
        self.ifx.replies_with(None)
        
        #As per the test, wait 50s
        #self.ui.wait(50) # This breaks it!
        self.ifx.sends((IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.global_ip()))/DHCP6_Renew()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131",preflft=50,validlft=80)),1)
        #Respond to the reply with nothing
        self.ifx.replies_with(None)        
        
        #Respond to the echo:
        self.ifx.replies_with(IPv6(src=self.test_network.link(2).prefix+"3131",dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
    
        self.ui.inputs.append("y")
        o = self.get_outcome(suite.DHCPv6TransmissionOfRenewMessagesTestCase)
        
        self.assertCheckPasses(o)
        

        
    def test_flow_label_DHCP_no_solicit_test_case(self):
        #Start by sending solicit broadcast:
        #self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1:2")/DHCP6_Solicit(),1)
        #Reply to the advertise with a request
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1:2")/DHCP6_Request()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"))
        
        #Respond to the reply with nothing
        self.ifx.replies_with(None)
        
        #As per the test, wait 50s
        #self.ui.wait(50) # This breaks it!
        self.ifx.sends((IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.global_ip()))/DHCP6_Renew()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131",preflft=50,validlft=80)),1)
        #Respond to the reply with nothing
        self.ifx.replies_with(None)        
        
        #Respond to the echo:
        self.ifx.replies_with(IPv6(src=self.test_network.link(2).prefix+"3131",dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
    
        self.ui.inputs.append("y")
        o = self.get_outcome(suite.DHCPv6TransmissionOfRenewMessagesTestCase)
        
        self.assertCheckFails(o)
        
        
        
    def test_flow_label_DHCP_non_broadcast_solicit_test_case(self):
        #Start by sending solicit broadcast:
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.global_ip()))/DHCP6_Solicit(),1)
        #Reply to the advertise with a request
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1:2")/DHCP6_Request()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"))
        
        #Respond to the reply with nothing
        self.ifx.replies_with(None)
        
        #As per the test, wait 50s
        #self.ui.wait(50) # This breaks it!
        self.ifx.sends((IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.global_ip()))/DHCP6_Renew()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131",preflft=50,validlft=80)),1)
        #Respond to the reply with nothing
        self.ifx.replies_with(None)        
        
        #Respond to the echo:
        self.ifx.replies_with(IPv6(src=self.test_network.link(2).prefix+"3131",dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
    
        self.ui.inputs.append("y")
        o = self.get_outcome(suite.DHCPv6TransmissionOfRenewMessagesTestCase)
        
        self.assertCheckFails(o)  
        
     
    def test_flow_label_DHCP_no_Request_test_case(self):
        #Start by sending solicit broadcast:
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1:2")/DHCP6_Solicit(),1)
        #Reply to the advertise with a request
        #self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1:2")/DHCP6_Request()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"))
        
        #Respond to the reply with nothing
        self.ifx.replies_with(None)
        
        #As per the test, wait 50s
        #self.ui.wait(50) # This breaks it!
        self.ifx.sends((IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.global_ip()))/DHCP6_Renew()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131",preflft=50,validlft=80)),1)
        #Respond to the reply with nothing
        self.ifx.replies_with(None)        
        
        #Respond to the echo:
        self.ifx.replies_with(IPv6(src=self.test_network.link(2).prefix+"3131",dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
    
        self.ui.inputs.append("y")
        o = self.get_outcome(suite.DHCPv6TransmissionOfRenewMessagesTestCase)
        
        self.assertCheckFails(o)
        
        
    def test_flow_label_DHCP_non_broadcast_request_test_case(self):
        #Start by sending solicit broadcast:
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1:2")/DHCP6_Solicit(),1)
        #Reply to the advertise with a request
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.global_ip()))/DHCP6_Request()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"))
        
        #Respond to the reply with nothing
        self.ifx.replies_with(None)
        
        #As per the test, wait 50s
        #self.ui.wait(50) # This breaks it!
        self.ifx.sends((IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.global_ip()))/DHCP6_Renew()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131",preflft=50,validlft=80)),1)
        #Respond to the reply with nothing
        self.ifx.replies_with(None)        
        
        #Respond to the echo:
        self.ifx.replies_with(IPv6(src=self.test_network.link(2).prefix+"3131",dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
    
        self.ui.inputs.append("y")
        o = self.get_outcome(suite.DHCPv6TransmissionOfRenewMessagesTestCase)
        
        self.assertCheckFails(o)               


    def test_flow_label_DHCP_no_ICMP6OptIAAddress_request_test_case(self):
        #Start by sending solicit broadcast:
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1:2")/DHCP6_Solicit(),1)
        #Reply to the advertise with a request
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.global_ip()))/DHCP6_Request()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"))
        
        #Respond to the reply with nothing
        self.ifx.replies_with(None)
        
        #As per the test, wait 50s
        #self.ui.wait(50) # This breaks it!
        self.ifx.sends((IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1:2")/DHCP6_Renew()),1)
        #Respond to the reply with nothing
        self.ifx.replies_with(None)        
        
        #Respond to the echo:
        self.ifx.replies_with(IPv6(src=self.test_network.link(2).prefix+"3131",dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
    
        self.ui.inputs.append("y")
        o = self.get_outcome(suite.DHCPv6TransmissionOfRenewMessagesTestCase)
        
        self.assertCheckFails(o)  

    def test_flow_label_DHCP_no_renew_test_case(self):
        #Start by sending solicit broadcast:
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1:2")/DHCP6_Solicit(),1)
        #Reply to the advertise with a request
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.global_ip()))/DHCP6_Request()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"))
        
        #Respond to the reply with nothing
        self.ifx.replies_with(None)
        
        #As per the test, wait 50s
        #self.ui.wait(50) # This breaks it!
        #self.ifx.sends((IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1:2")/DHCP6_Renew()),1)
        #Respond to the reply with nothing
        self.ifx.replies_with(None)        
        
        #Respond to the echo:
        self.ifx.replies_with(IPv6(src=self.test_network.link(2).prefix+"3131",dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
    
        self.ui.inputs.append("y")
        o = self.get_outcome(suite.DHCPv6TransmissionOfRenewMessagesTestCase)
        
        self.assertCheckFails(o)   
   
   
    def test_flow_label_DHCP_non_broadcast_renew_test_case(self):
        #Start by sending solicit broadcast:
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1:2")/DHCP6_Solicit(),1)
        #Reply to the advertise with a request
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.global_ip()))/DHCP6_Request()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"))
        
        #Respond to the reply with nothing
        self.ifx.replies_with(None)
        
        #As per the test, wait 50s
        #self.ui.wait(50) # This breaks it!
        self.ifx.sends((IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.global_ip()))/DHCP6_Renew()),1)
        #Respond to the reply with nothing
        self.ifx.replies_with(None)        
        
        #Respond to the echo:
        self.ifx.replies_with(IPv6(src=self.test_network.link(2).prefix+"3131",dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
    
        self.ui.inputs.append("y")
        o = self.get_outcome(suite.DHCPv6TransmissionOfRenewMessagesTestCase)
        
        self.assertCheckFails(o)      
        
    def test_flow_label_DHCP_no_echo_test_case(self):
        #Start by sending solicit broadcast:
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1:2")/DHCP6_Solicit(),1)
        #Reply to the advertise with a request
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.global_ip()))/DHCP6_Request()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"))
        
        #Respond to the reply with nothing
        self.ifx.replies_with(None)
        
        #As per the test, wait 50s
        #self.ui.wait(50) # This breaks it!
        self.ifx.sends((IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1:2")/DHCP6_Renew()),1)
        #Respond to the reply with nothing
        self.ifx.replies_with(None)        
        
        #Respond to the echo:
        #self.ifx.replies_with(IPv6(src=self.test_network.link(2).prefix+"3131",dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
    
        self.ui.inputs.append("y")
        o = self.get_outcome(suite.DHCPv6TransmissionOfRenewMessagesTestCase)
        
        self.assertCheckFails(o)  
        
        
    def test_flow_label_DHCP_non_echo_test_case(self):
        #Start by sending solicit broadcast:
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1:2")/DHCP6_Solicit(),1)
        #Reply to the advertise with a request
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.global_ip()))/DHCP6_Request()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"))
        
        #Respond to the reply with nothing
        self.ifx.replies_with(None)
        
        #As per the test, wait 50s
        #self.ui.wait(50) # This breaks it!
        self.ifx.sends((IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1:2")/DHCP6_Renew()),1)
        #Respond to the reply with nothing
        self.ifx.replies_with(None)        
        
        #Respond to the echo:
        self.ifx.replies_with(IPv6(src=self.test_network.link(2).prefix+"3131",dst=str(self.tn1.global_ip()))/DHCP6_Request())
    
        self.ui.inputs.append("y")
        o = self.get_outcome(suite.DHCPv6TransmissionOfRenewMessagesTestCase)
        
        self.assertCheckFails(o)