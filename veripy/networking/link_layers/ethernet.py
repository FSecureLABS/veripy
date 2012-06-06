from scapy.all import Ether
import re
from veripy.networking.link_layers.abstract import LinkLayer


class Ethernet(LinkLayer):

    DefaultSrc = '00:00:00:00:00:00'
    DefaultDst = 'ff:ff:ff:ff:ff:ff'

    frame = Ether
    
    max_mtu = 1500
    min_mtu = 46
    mtu = 1500
    
    def __init__(self):
        self.expected_arguments = { -1: { 'name': 'mac', 'validator': 'valid_mac' } }

    @classmethod
    def encapsulate(cls, packet_or_frame, src_mac, dst_mac):
        if dst_mac == None:
            dst_mac = Ethernet.DefaultDst
        if src_mac == None:
            src_mac = Ethernet.DefaultSrc

        try:
            if not packet_or_frame.haslayer(Ether):
                packet_or_frame = Ether()/packet_or_frame

            packet_or_frame.getlayer(Ether).src = src_mac
            packet_or_frame.getlayer(Ether).dst = dst_mac
        except AttributeError:
            pass

        return packet_or_frame

    def name(self):
        return 'Ethernet'

    def valid_mac(self, mac):
        return not re.match("^([0-9a-z]{1,2}:){5}[0-9a-z]{1,2}$", mac, flags=re.IGNORECASE) == None
