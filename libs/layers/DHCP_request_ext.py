from scapy.all import *


dhcp6types = {   1:"SOLICIT",
                 2:"ADVERTISE",
                 3:"REQUEST",
                 4:"CONFIRM",
                 5:"RENEW",
                 6:"REBIND",
                 7:"REPLY",
                 8:"RELEASE",
                 9:"DECLINE",
                10:"RECONFIGURE",
                11:"INFORMATION-REQUEST",
                12:"RELAY-FORW",
                13:"RELAY-REPL" }

class DHCPv6_Request_Full(Packet):
    name = "DHCPv6 Full Request packet"
    fields_desc = [ ByteEnumField("msgtype", 1,dhcp6types),
                    X3BytesField("trid", 2), 
                    IP6Field("IAA","::")]

class DHCPv6_Reply_Full(Packet):
    name = "DHCPv6 Full Reply packet"
    fields_desc = [ ByteEnumField("msgtype", 1,dhcp6types),
                    X3BytesField("trid", 2), 
                    IP6Field("IAA","::")]

class DHCPv6_Confirm_Full(Packet):
    name="DHCPv6 Full Confirm Packet"
    fields_desc = [ ByteEnumField("msgtype",1,dhcp6types),
                   X3BytesField("trid",2),
                   IP6Field("IA","::")]

def make_request(x,y,z):
    return Ether()/IP()/DHCPv6_Request_Full(msgtype=x,trid=y,IAA=z)

def make_reply(x,y,z):
    return Ether()/IP()/DHCPv6_Reply_Full(msgtype=x,trid=y,IAA=z)

def make_confirm(x,y,z):
    return Ether()/IP()/DHCPv6_Confirm_Full(msgtype=x,trid=y,IA=z)