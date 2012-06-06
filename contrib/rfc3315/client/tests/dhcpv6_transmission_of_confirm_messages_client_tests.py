from contrib.rfc3315.client import dhcpv6_transmission_of_confirm_messages as suite
from scapy.all import *
from veripy.testability import ComplianceTestTestCase

class DHCPv6TransmissionOfConfirmMessagesTestCase(ComplianceTestTestCase):

    def test_flow_label_DHCP_normal_test_case(self):
        #Start by sending solicit broadcast:
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1:2")/DHCP6_Solicit(),1)
        #Respond to the Advertise message with a DHCP request:
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1:2")/DHCP6_Request()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"))
        #Respond to the reply with nothing
        self.ifx.replies_with(None)
        
        #Respond to the ICMPEchoRequest with an EchoReply:
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()) )/ICMPv6EchoReply())
        
        #client would be disconnected then reconnected at this point, so send a confirm packet to the server:
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()),dst="ff02::1:2")/DHCP6_Confirm()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"),1)
        #Get the reply packet but do nothing
        self.ifx.replies_with(None)
        
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()),dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        
        self.ui.inputs.append("y")
        self.ui.inputs.append("y")
        o = self.get_outcome(suite.DHCPv6TransmissionOfConfirmMessagesTestCase)
        
        self.assertCheckPasses(o)
        
    def test_flow_label_DHCP_no_solicit_test_case(self):
        #Start by sending solicit broadcast:
        #self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1:2")/DHCP6_Solicit(),1)
        #Respond to the Advertise message with a DHCP request:
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1:2")/DHCP6_Request()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"))
        #Respond to the reply with nothing
        self.ifx.replies_with(None)
        
        #Respond to the ICMPEchoRequest with an EchoReply:
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()) )/ICMPv6EchoReply())
        
        #client would be disconnected then reconnected at this point, so send a confirm packet to the server:
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()),dst="ff02::1:2")/DHCP6_Confirm()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"),1)
        #Get the reply packet but do nothing
        self.ifx.replies_with(None)
        
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()),dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        
        self.ui.inputs.append("y")
        self.ui.inputs.append("y")
        o = self.get_outcome(suite.DHCPv6TransmissionOfConfirmMessagesTestCase)
        
        self.assertCheckFails(o)  

    def test_flow_label_DHCP_non_broadcast_solicit_test_case(self):
        #Start by sending solicit broadcast:
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.global_ip()))/DHCP6_Solicit(),1)
        #Respond to the Advertise message with a DHCP request:
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1:2")/DHCP6_Request()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"))
        #Respond to the reply with nothing
        self.ifx.replies_with(None)
        
        #Respond to the ICMPEchoRequest with an EchoReply:
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()) )/ICMPv6EchoReply())
        
        #client would be disconnected then reconnected at this point, so send a confirm packet to the server:
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()),dst="ff02::1:2")/DHCP6_Confirm()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"),1)
        #Get the reply packet but do nothing
        self.ifx.replies_with(None)
        
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()),dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        
        self.ui.inputs.append("y")
        self.ui.inputs.append("y")
        o = self.get_outcome(suite.DHCPv6TransmissionOfConfirmMessagesTestCase)
        
        self.assertCheckFails(o)  
               
    def test_flow_label_DHCP_no_request_test_case(self):
        #Start by sending solicit broadcast:
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1:2")/DHCP6_Solicit(),1)
        #Respond to the Advertise message with a DHCP request:
        #self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1:2")/DHCP6_Request()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"))
        #Respond to the reply with nothing
        self.ifx.replies_with(None)
        
        #Respond to the ICMPEchoRequest with an EchoReply:
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()) )/ICMPv6EchoReply())
        
        #client would be disconnected then reconnected at this point, so send a confirm packet to the server:
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()),dst="ff02::1:2")/DHCP6_Confirm()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"),1)
        #Get the reply packet but do nothing
        self.ifx.replies_with(None)
        
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()),dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        
        self.ui.inputs.append("y")
        self.ui.inputs.append("y")
        o = self.get_outcome(suite.DHCPv6TransmissionOfConfirmMessagesTestCase)
        
        self.assertCheckFails(o)


    def test_flow_label_DHCP_non_broadcast_request_test_case(self):
        #Start by sending solicit broadcast:
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1:2")/DHCP6_Solicit(),1)
        #Respond to the Advertise message with a DHCP request:
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()),  dst=str(self.tn1.global_ip()))/DHCP6_Request()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"))
        #Respond to the reply with nothing
        self.ifx.replies_with(None)
        
        #Respond to the ICMPEchoRequest with an EchoReply:
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()) )/ICMPv6EchoReply())
        
        #client would be disconnected then reconnected at this point, so send a confirm packet to the server:
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()),dst="ff02::1:2")/DHCP6_Confirm()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"),1)
        #Get the reply packet but do nothing
        self.ifx.replies_with(None)
        
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()),dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        
        self.ui.inputs.append("y")
        self.ui.inputs.append("y")
        o = self.get_outcome(suite.DHCPv6TransmissionOfConfirmMessagesTestCase)
        
        self.assertCheckFails(o)     
 
    def test_flow_label_DHCP_non_DHCP6OptIAAddress_request_test_case(self):
        #Start by sending solicit broadcast:
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1:2")/DHCP6_Solicit(),1)
        #Respond to the Advertise message with a DHCP request:
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()),  dst=str(self.tn1.global_ip()))/DHCP6_Request())
        #Respond to the reply with nothing
        self.ifx.replies_with(None)
        
        #Respond to the ICMPEchoRequest with an EchoReply:
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()) )/ICMPv6EchoReply())
        
        #client would be disconnected then reconnected at this point, so send a confirm packet to the server:
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()),dst="ff02::1:2")/DHCP6_Confirm()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"),1)
        #Get the reply packet but do nothing
        self.ifx.replies_with(None)
        
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()),dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        
        self.ui.inputs.append("y")
        self.ui.inputs.append("y")
        o = self.get_outcome(suite.DHCPv6TransmissionOfConfirmMessagesTestCase)
        
        self.assertCheckFails(o)     
        
    def test_flow_label_DHCP_no_EchoReply_test_case(self):
        #Start by sending solicit broadcast:
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1:2")/DHCP6_Solicit(),1)
        #Respond to the Advertise message with a DHCP request:
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1:2")/DHCP6_Request()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"))
        #Respond to the reply with nothing
        self.ifx.replies_with(None)
        
        #Respond to the ICMPEchoRequest with an EchoReply:
        #self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst="ff02::1:2") )/ICMPv6EchoReply())
        
        #client would be disconnected then reconnected at this point, so send a confirm packet to the server:
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()),dst="ff02::1:2")/DHCP6_Confirm()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"),1)
        #Get the reply packet but do nothing
        self.ifx.replies_with(None)
        
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()),dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        
        self.ui.inputs.append("y")
        self.ui.inputs.append("y")
        o = self.get_outcome(suite.DHCPv6TransmissionOfConfirmMessagesTestCase)
        
        self.assertCheckFails(o)   
        
    def test_flow_label_DHCP_bad_dst_echoreply_test_case(self):
        #Start by sending solicit broadcast:
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1:2")/DHCP6_Solicit(),1)
        #Respond to the Advertise message with a DHCP request:
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1:2")/DHCP6_Request()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"))
        #Respond to the reply with nothing
        self.ifx.replies_with(None)
        
        #Respond to the ICMPEchoRequest with an EchoReply:
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst="ff02::1:2") /ICMPv6EchoReply())
        
        #client would be disconnected then reconnected at this point, so send a confirm packet to the server:
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()),dst="ff02::1:2")/DHCP6_Confirm()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"),1)
        #Get the reply packet but do nothing
        self.ifx.replies_with(None)
        
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()),dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        
        self.ui.inputs.append("y")
        self.ui.inputs.append("y")
        o = self.get_outcome(suite.DHCPv6TransmissionOfConfirmMessagesTestCase)
        
        self.assertCheckFails(o)     
        
    def test_flow_label_DHCP_no_confirm_test_case(self):
        #Start by sending solicit broadcast:
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1:2")/DHCP6_Solicit(),1)
        #Respond to the Advertise message with a DHCP request:
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1:2")/DHCP6_Request()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"))
        #Respond to the reply with nothing
        self.ifx.replies_with(None)
        #Respond to the ICMPEchoRequest with an EchoReply:
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()) )/ICMPv6EchoReply())
        #client would be disconnected then reconnected at this point, so send a confirm packet to the server:
        #self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()),dst="ff02::1:2")/DHCP6_Confirm()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"),1)
        #Get the reply packet but do nothing
        self.ifx.replies_with(None)
        
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()),dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        
        self.ui.inputs.append("y")
        self.ui.inputs.append("y")
        o = self.get_outcome(suite.DHCPv6TransmissionOfConfirmMessagesTestCase)
        
        self.assertCheckFails(o)   
         
    def test_flow_label_DHCP_non_broadcast_confirm_test_case(self):
        #Start by sending solicit broadcast:
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1:2")/DHCP6_Solicit(),1)
        #Respond to the Advertise message with a DHCP request:
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1:2")/DHCP6_Request()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"))
        #Respond to the reply with nothing
        self.ifx.replies_with(None)
        #Respond to the ICMPEchoRequest with an EchoReply:
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()) )/ICMPv6EchoReply())
        #client would be disconnected then reconnected at this point, so send a confirm packet to the server:
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()),dst=str(self.tn1.global_ip()))/DHCP6_Confirm()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"),1)
        #Get the reply packet but do nothing
        self.ifx.replies_with(None)
        
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()),dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        
        self.ui.inputs.append("y")
        self.ui.inputs.append("y")
        o = self.get_outcome(suite.DHCPv6TransmissionOfConfirmMessagesTestCase)
        
        self.assertCheckFails(o)         

        
    def test_flow_label_DHCP_no_2nd_echoreply_test_case(self):
        #Start by sending solicit broadcast:
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1:2")/DHCP6_Solicit(),1)
        #Respond to the Advertise message with a DHCP request:
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1:2")/DHCP6_Request()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"))
        #Respond to the reply with nothing
        self.ifx.replies_with(None)
        #Respond to the ICMPEchoRequest with an EchoReply:
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()) )/ICMPv6EchoReply())
        #client would be disconnected then reconnected at this point, so send a confirm packet to the server:
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()),dst="ff02::1:2")/DHCP6_Confirm(),1)
        #Get the reply packet but do nothing
        self.ifx.replies_with(None)
        
        #self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()),dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        
        self.ui.inputs.append("y")
        self.ui.inputs.append("y")
        o = self.get_outcome(suite.DHCPv6TransmissionOfConfirmMessagesTestCase)
        
        self.assertCheckFails(o) 
        
                                       