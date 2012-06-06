from contrib.rfc3315.client import dhcpv6_transmission_of_rebind_messages as suite
from scapy.all import *
from veripy.testability import ComplianceTestTestCase

class DHCPv6TransmissionOfRebindMessagesTestCase(ComplianceTestTestCase):

    
    def test_flow_label_DHCP_normal_test_case(self):
        #Start by sending solicit broadcast:
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1:2")/DHCP6_Solicit(),1)
        #Reply to the advertise with a request
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1:2")/DHCP6_Request()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"))
        
        #Respond to the reply with nothing
        self.ifx.replies_with(None)
        
        #As per the test, wait 50s
        #self.ui.wait(80) # This breaks it!
        self.ifx.sends((IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.global_ip()))/DHCP6_Rebind()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131",preflft=50,validlft=80)),80)
        #Respond to the reply with nothing
        self.ifx.replies_with(None)        
        
        #Respond to the echo:
        self.ifx.replies_with(IPv6(src=self.test_network.link(2).prefix+"3131",dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
    
        self.ui.inputs.append("y")
        o = self.get_outcome(suite.DHCPv6TransmissionOfRebindMessagesTestCase)
        
        self.assertCheckPasses(o)
        
        
    def test_flow_label_DHCP_no_solicit_test_case(self):
        #Start by sending solicit broadcast:
        #self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1:2")/DHCP6_Solicit(),1)
        #Reply to the advertise with a request
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1:2")/DHCP6_Request()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"))
        
        #Respond to the reply with nothing
        self.ifx.replies_with(None)
        
        #As per the test, wait 50s
        #self.ui.wait(80) # This breaks it!
        self.ifx.sends((IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.global_ip()))/DHCP6_Rebind()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131",preflft=50,validlft=80)),80)
        #Respond to the reply with nothing
        self.ifx.replies_with(None)        
        
        #Respond to the echo:
        self.ifx.replies_with(IPv6(src=self.test_network.link(2).prefix+"3131",dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
    
        self.ui.inputs.append("y")
        o = self.get_outcome(suite.DHCPv6TransmissionOfRebindMessagesTestCase)
        
        self.assertCheckFails(o)     
        
    def test_flow_label_DHCP_non_broadcast_solicit_test_case(self):
        #Start by sending solicit broadcast:
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.global_ip()))/DHCP6_Solicit(),1)
        #Reply to the advertise with a request
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1:2")/DHCP6_Request()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"))
        
        #Respond to the reply with nothing
        self.ifx.replies_with(None)
        
        #As per the test, wait 50s
        #self.ui.wait(80) # This breaks it!
        self.ifx.sends((IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.global_ip()))/DHCP6_Rebind()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131",preflft=50,validlft=80)),80)
        #Respond to the reply with nothing
        self.ifx.replies_with(None)        
        
        #Respond to the echo:
        self.ifx.replies_with(IPv6(src=self.test_network.link(2).prefix+"3131",dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
    
        self.ui.inputs.append("y")
        o = self.get_outcome(suite.DHCPv6TransmissionOfRebindMessagesTestCase)
        
        self.assertCheckFails(o)        
        
    def test_flow_label_DHCP_no_request_test_case(self):
        #Start by sending solicit broadcast:
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1:2")/DHCP6_Solicit(),1)
        #Reply to the advertise with a request
        #self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1:2")/DHCP6_Request()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"))
        
        #Respond to the reply with nothing
        self.ifx.replies_with(None)
        
        #As per the test, wait 50s
        #self.ui.wait(80) # This breaks it!
        self.ifx.sends((IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.global_ip()))/DHCP6_Rebind()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131",preflft=50,validlft=80)),80)
        #Respond to the reply with nothing
        self.ifx.replies_with(None)        
        
        #Respond to the echo:
        self.ifx.replies_with(IPv6(src=self.test_network.link(2).prefix+"3131",dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
    
        self.ui.inputs.append("y")
        o = self.get_outcome(suite.DHCPv6TransmissionOfRebindMessagesTestCase)
        
        self.assertCheckFails(o)      
        
    def test_flow_label_DHCP_no_request_IAAddress_test_case(self):
        #Start by sending solicit broadcast:
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1:2")/DHCP6_Solicit(),1)
        #Reply to the advertise with a request
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1:2")/DHCP6_Request())
        
        #Respond to the reply with nothing
        self.ifx.replies_with(None)
        
        #As per the test, wait 50s
        #self.ui.wait(80) # This breaks it!
        self.ifx.sends((IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.global_ip()))/DHCP6_Rebind()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131",preflft=50,validlft=80)),80)
        #Respond to the reply with nothing
        self.ifx.replies_with(None)        
        
        #Respond to the echo:
        self.ifx.replies_with(IPv6(src=self.test_network.link(2).prefix+"3131",dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
    
        self.ui.inputs.append("y")
        o = self.get_outcome(suite.DHCPv6TransmissionOfRebindMessagesTestCase)
        
        self.assertCheckFails(o)        
    
    def test_flow_label_DHCP_non_broadcast_request_test_case(self):
        #Start by sending solicit broadcast:
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1:2")/DHCP6_Solicit(),1)
        #Reply to the advertise with a request
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.global_ip()))/DHCP6_Request()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"))
        
        #Respond to the reply with nothing
        self.ifx.replies_with(None)
        
        #As per the test, wait 50s
        #self.ui.wait(80) # This breaks it!
        self.ifx.sends((IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.global_ip()))/DHCP6_Rebind()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131",preflft=50,validlft=80)),80)
        #Respond to the reply with nothing
        self.ifx.replies_with(None)        
        
        #Respond to the echo:
        self.ifx.replies_with(IPv6(src=self.test_network.link(2).prefix+"3131",dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
    
        self.ui.inputs.append("y")
        o = self.get_outcome(suite.DHCPv6TransmissionOfRebindMessagesTestCase)
        
        self.assertCheckFails(o)        
        
         
           