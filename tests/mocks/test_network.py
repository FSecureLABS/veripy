from scapy.all import ICMPv6EchoReply, ICMPv6EchoRequest, ICMPv6ND_NA, ICMPv6ND_RA
from tests.mocks.networking import MockInterface
from veripy.models import Tap, TargetInterface


class MockTap(Tap):

    def __init__(self, link, iface, target_iface=None):
        super(MockTap, self).__init__(link, iface, target_iface)

        target_iface.tap = self

        self.__receiving = False
        
    def accept(self, packet):
        if self.__receiving: return

        # attempt to build the packet - this will spit out an error if the
        # packet would be invalid when it was really sent on the wire
        packet.build()

        self.__receiving = True
        # get the next reply (if there is one) from the target interface and
        # send it
        self.target_iface.send_next_reply(packet)
        self.__receiving = False


class MockTargetInterface(TargetInterface):

    def __init__(self, ips, ll_protocol, link_addr):
        super(MockTargetInterface, self).__init__(ips, ll_protocol, link_addr)

        self.__deliveries = {}
        self.__last_delivery_at = -1
        self.__replies = []
        self.__reply_ctr = -1

        self.tap = None

    def sends(self, packet, after):
        if not after in self.__deliveries:
            self.__deliveries[after] = []

        self.__deliveries[after].append(packet)

    def next_delivery(self, seconds):
        deliveries = []
        
        for s in filter(lambda s: s > self.__last_delivery_at and s <= max(self.__last_delivery_at + seconds, 0), self.__deliveries.keys()):
            deliveries.extend(self.__deliveries[s])

        self.__last_delivery_at = seconds + max(self.__last_delivery_at, 0)
        
        return deliveries

    def replies_with(self, packet, to=None, expect=None):
        self.__replies.append([packet, to == None and self or to, expect])

    def send_next_reply(self, to):
        self.__reply_ctr += 1
        
        if self.__reply_ctr < len(self.__replies):
            reply = self.__replies[self.__reply_ctr][0]
            reply_to = self.__replies[self.__reply_ctr][1]
            expect = self.__replies[self.__reply_ctr][2]

            if to.haslayer(ICMPv6ND_NA) and expect != ICMPv6ND_NA or to.haslayer(ICMPv6ND_RA) and expect != ICMPv6ND_RA:
                self.__reply_ctr -= 1

                return None
            elif expect == None or hasattr(to, 'haslayer') and to.haslayer(expect):
                if hasattr(to, 'haslayer') and to.haslayer(ICMPv6EchoRequest) and \
                        hasattr(reply, 'haslayer') and reply.haslayer(ICMPv6EchoReply):
                    reply.getlayer(ICMPv6EchoReply).seq = to.getlayer(ICMPv6EchoRequest).seq
                elif hasattr(to, 'haslayer') and to.haslayer(ICMPv6EchoRequest) and \
                        hasattr(reply, 'haslayer') and reply.haslayer(ICMPv6EchoRequest):
                    reply.getlayer(ICMPv6EchoRequest).seq = to.getlayer(ICMPv6EchoRequest).seq

                if not reply == None:
                    reply_to.tap._MockTap__receiving = True
                    if isinstance(reply, list):
                        for r in reply: reply_to.tap.receive(r)
                    else:
                        reply_to.tap.receive(reply)
                    reply_to.tap._MockTap__receiving = False

                return reply
            else:
                self.__reply_ctr -= 1

                return None


class TestNetworkConfiguration:

    def __init__(self):
        self.link_layer = "Ethernet"
        self.ifaces = [ MockInterface('if0', "be:ef:ca:fe:09:00"),
                        MockInterface('if1', "be:ef:ca:fe:09:01") ]

        self.link1 = LinkConfiguration( v6_prefix = "2012:7665:7269:7079::",
                                        v6_prefix_size = 64,
                                        v4_prefix = "10.0.0.0",
                                        v4_prefix_size = 24)
        self.link2 = LinkConfiguration( v6_prefix = "2012:6970:7636::",
                                        v6_prefix_size = 64,
                                        v4_prefix = "10.1.0.0",
                                        v4_prefix_size = 24)
        self.link3 = LinkConfiguration( v6_prefix = "2012:6d77:7269::",
                                        v6_prefix_size = 64,
                                        v4_prefix = "10.2.0.0",
                                        v4_prefix_size = 24)
        
        self.tn1 = NodeConfiguration(   ips0 = ["2001:500:88:200::11", "fe80::11"],
                                        ll_addr0 = "de:ad:be:ef:01:01")
        self.tn2 = NodeConfiguration(   ips0 = ["2001:600:88:200::12", "fe80::12"],
                                        ll_addr0 = "de:ad:be:ef:01:02")
        self.tn3 = NodeConfiguration(   ips0 = ["2001:600:88:200::13", "fe80::13"],
                                        ll_addr0 = "de:ad:be:ef:01:03")
        self.tn4 = NodeConfiguration(   ips0 = ["2001:700:88:200::14", "fe80::14"],
                                        ll_addr0 = "de:ad:be:ef:01:04")

        self.tp1 = TapConfiguration('if0', 'de:ad:be:ef:01:02')
        self.tp2 = TapConfiguration('if0', 'de:ad:be:ef:01:02')

        self.tr1 = RouterConfiguration( ips0 = ["2001:600:88:200::1", "fe80::1"],
                                        ll_addr0 = "de:ad:be:ef:02:01",
                                        ips1 = ["2001:500:88:200::1", "fe80::5"],
                                        ll_addr1 = "de:ad:be:ef:02:02")
        self.tr2 = RouterConfiguration( ips0 = ["2001:600:88:200::2", "fe80::2"],
                                        ll_addr0 = "de:ad:be:ef:02:03",
                                        ips1 = ["2001:500:88:200::2", "fe80::6"],
                                        ll_addr1 = "de:ad:be:ef:02:04")
        self.tr3 = RouterConfiguration( ips0 = ["2001:600:88:200::3", "fe80::3"],
                                        ll_addr0 = "de:ad:be:ef:02:04",
                                        ips1 = ["2001:500:88:200::3", "fe80::7"],
                                        ll_addr1 = "de:ad:be:ef:02:05")

        self.uut1 = TargetConfiguration(ips = ["2012:6970:7636:0:20c:29ff:fef4:b890", "fe80::20c:29ff:fef4:b890"], ll_addr = "be:ef:ca:fe:01:02")
        self.uut2 = TargetConfiguration(ips = ["2012:6970:7636:0:20c:29ff:fef4:b890", "fe80::20c:29ff:fef4:b890"], ll_addr = "be:ef:ca:fe:01:02")

    def phy(self, id):
        return self.ifaces[id-1]


class LinkConfiguration:

    def __init__(self, v6_prefix, v6_prefix_size, v4_prefix, v4_prefix_size):
        self.v4_prefix = v4_prefix
        self.v4_prefix_size = v4_prefix_size
        
        self.v6_prefix = v6_prefix
        self.v6_prefix_size = v6_prefix_size

    def v4_cidr(self):
        return "%s/%s" % (self.v4_prefix, self.v4_prefix_size)
    
    def v6_cidr(self):
        return "%s/%s" % (self.v6_prefix, self.v6_prefix_size)
    
        
class NodeConfiguration:

    def __init__(self, ips0, ll_addr0):
        self.if0_ips = ips0
        self.if0_address = ll_addr0

class RouterConfiguration:

    def __init__(self, ips0, ll_addr0, ips1, ll_addr1):
        self.if0_ips = ips0
        self.if0_address = ll_addr0
        self.if1_ips = ips1
        self.if1_address = ll_addr1

class TapConfiguration:

    def __init__(self, dev, ll_addr):
        self.dev = dev
        self.ll_addr = ll_addr

class TargetConfiguration:

    def __init__(self, ips, ll_addr):
        self.ips = ips
        self.ll_addr = ll_addr
        
