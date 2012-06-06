from contrib.rfc3315.client import dhcpv6_initialization as suite
from scapy.all import *
from veripy.testability import ComplianceTestTestCase

class DHCPv6InitializationClientTestCase(ComplianceTestTestCase):

    
    def test_flow_label_DHCP_normal_test_case(self):
        #Start by sending solicit broadcast:
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1:2")/DHCP6_Solicit(), 1)
        #Respond to the Advertise message with a DHCP request:        
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1:2")/DHCP6_Request()/DHCP6OptIAAddress( addr=self.test_network.link(2).prefix+"3131"))
        #Don't respond to the server's reply packet:
        self.ifx.replies_with(None)
        #Respond to the ICMPEchoRequest with an EchoReply:
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()) )/ICMPv6EchoReply())
        
        self.ui.inputs.append("y")
        o = self.get_outcome(suite.DHCPv6InitializationClientTestCase)
        
        self.assertCheckPasses(o)
        
        
    def test_flow_label_DHCP_empty_IAA_IP_test_case(self):
        #Uses a DHCP6_Request instead of a DHCPv6_Request_Full so there's no IAA value
                
        #Start by sending solicit broadcast:
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1:2")/DHCP6_Solicit(), 1)
        #Respond to the Advertise message with a DHCP request:
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1:2")/DHCP6_Request())
        #Don't respond to the server's reply packet:
        self.ifx.replies_with(None)
        #Respond to the ICMPEchoRequest with an EchoReply:
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()) )/ICMPv6EchoReply())
        
        self.ui.inputs.append("y")
        o = self.get_outcome(suite.DHCPv6InitializationClientTestCase)
        
        self.assertCheckFails(o)
        
    def test_flow_label_Non_Broadcast_Solicit_test_case(self):
        #The solicit message is not sent as a broadcast 
        
        #Start by sending solicit broadcast:
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst=str(self.tn1.global_ip()))/DHCP6_Solicit(), 1)
        #Respond to the Advertise message with a DHCP request:
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1:2")/DHCP6_Request()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"))
        #Don't respond to the server's reply packet:
        self.ifx.replies_with(None)
        #Respond to the ICMPEchoRequest with an EchoReply:
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()) )/ICMPv6EchoReply())
        
        self.ui.inputs.append("y")
        o = self.get_outcome(suite.DHCPv6InitializationClientTestCase)
        
        self.assertCheckFails(o)
        
    def test_flow_label_No_Solicit_test_case(self):
        #Missing the initial DHCP_solicit broadcast 
        
        #Respond to the Advertise message with a DHCP request:
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1:2")/DHCP6_Request()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"))
        #Don't respond to the server's reply packet:
        self.ifx.replies_with(None)
        #Respond to the ICMPEchoRequest with an EchoReply:
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()) )/ICMPv6EchoReply())
        
        self.ui.inputs.append("y")
        o = self.get_outcome(suite.DHCPv6InitializationClientTestCase)
        
        self.assertCheckFails(o)
        
    
    def test_flow_label_No_Request_test_case(self):
        #Start by sending solicit broadcast:
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1:2")/DHCP6_Solicit(), 1)
        #Don't respond to the server's reply packet:
        self.ifx.replies_with(None)
        #Respond to the ICMPEchoRequest with an EchoReply:
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()) )/ICMPv6EchoReply())
        
        self.ui.inputs.append("y")
        o = self.get_outcome(suite.DHCPv6InitializationClientTestCase)
        
        self.assertCheckFails(o)
        
    
    def test_flow_label_No_Echo_Response_test_case(self):
        #Start by sending solicit broadcast:
        self.ifx.sends(IPv6(src=str(self.ifx.link_local_ip()), dst="ff02::1:2")/DHCP6_Solicit(), 1)
        #Respond to the Advertise message with a DHCP request:
        self.ifx.replies_with(IPv6(src=str(self.ifx.link_local_ip()),dst="ff02::1:2")/DHCP6_Request()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"))
        #Don't respond to the server's reply packet:
        self.ifx.replies_with(None)
                
        self.ui.inputs.append("y")
        o = self.get_outcome(suite.DHCPv6InitializationClientTestCase)
        
        self.assertCheckFails(o)
