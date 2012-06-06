from contrib.rfc3315.server import dhcpv6_initialization as suite
from scapy.all import *
from veripy.testability import ComplianceTestTestCase

class DHCPv6InitializationServerTestCase(ComplianceTestTestCase):

    
    def test_flow_label_DHCP_normal_test_case(self):
        #Normal operation test
        
        #Start replying to a solicit broadcast with a advertise message:
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/DHCP6_Advertise())
        
        #Then when you get a DHCP request, reply with a DHCP reply
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()) )/DHCP6_Reply()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"))
        
        o = self.get_outcome(suite.DHCPv6InitializationServerTestCase)
        
        self.assertCheckPasses(o)
        

    def test_flow_label_DHCP_No_Advertise(self):
        #Start replying to a solicit broadcast with a advertise message:
        #REMOVED
        
        #Then when you get a DHCP request, reply with a DHCP reply
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()) )/DHCP6_Reply()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3131"))
        
        o = self.get_outcome(suite.DHCPv6InitializationServerTestCase)
        
        self.assertCheckFails(o)
        
        
    def test_flow_label_DHCP_No_DHCP_Reply(self):
        #Start replying to a solicit broadcast with a advertise message:
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/DHCP6_Advertise())
        
        #Then when you get a DHCP request, reply with a DHCP reply
        #REMOVED

        o = self.get_outcome(suite.DHCPv6InitializationServerTestCase)
        
        self.assertCheckFails(o)    
        
        
    def test_flow_label_DHCP_Different_IAA(self):
        #Start replying to a solicit broadcast with a advertise message:
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()))/DHCP6_Advertise())
        
        #Then when you get a DHCP request, reply with a DHCP reply
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.link_local_ip()) )/DHCP6_Reply()/DHCP6OptIAAddress(addr=self.test_network.link(2).prefix+"3333"))

        o = self.get_outcome(suite.DHCPv6InitializationServerTestCase)
        
        self.assertCheckFails(o)    