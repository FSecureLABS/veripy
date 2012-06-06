from re import sub
from libs.ipcalc import Network
from scapy.all import ARP, ICMPv6EchoReply, ICMPv6EchoRequest, ICMPv6ND_NA, ICMPv6ND_NS, ICMPv6ND_RA, ICMPv6ND_RS, ICMPv6NDOptDstLLAddr, ICMPv6NDOptMTU, ICMPv6NDOptPrefixInfo, ICMPv6NDOptSrcLLAddr, IP, IPv6, PacketList
from time import sleep
from veripy.models.ip_address import IPAddress, IPv4Address, IPv6Address
from veripy.models.ip_address_collection import IPAddressCollection
from veripy.networking import Base as NetworkInterface
from veripy.networking import link_layers


class Interface(object):

    def __init__(self, ips=None, link=None, link_addr=None):
        self.ips = IPAddressCollection(ips or [])
        self.link = link
        self.ll_addr = link_addr
        self.ll_protocol = self.link.ll_protocol
        self.__on_receive_callbacks = []
        self.__on_send_callbacks = []

        self.link.bind(self)
        self.reset()

    def accept(self, frame):
        try:
            if frame.haslayer(self.ll_protocol.frame):
                packet = frame.getlayer(self.ll_protocol.frame)[1]
            else:
                packet = frame
        except AttributeError:
            packet = frame

        self.__raw_buffer.append(frame)
        self.__receive_buffer.append(packet)

        for callback in self.__on_receive_callbacks:
            callback(packet, self)

    def clear_received(self):
        self.__raw_buffer = []
        self.__receive_buffer = []

    def global_ip(self, offset=0, type='v6'):
        return self.ips.global_ip(offset=offset, type=type)

    def has_ip(self, ip):
        return str(ip) in self.ips
    
    def ip(self, offset=0, scope=IPAddressCollection.GLOBAL, type='v6'):
        return self.ips.ip(offset=offset, scope=scope, type=type)

    def link_local_ip(self, offset=0, type='v6'):
        return self.ips.link_local_ip(offset=offset, type=type)

    def on_send(self, callback):
        self.__on_send_callbacks.append(callback)

    def on_receive(self, callback):
        self.__on_receive_callbacks.append(callback)

    def real(self):
        return RealInterface(self)

    def received(self, src=None, dst=None, lbda=None, seq=None, type=None, raw=False):
        packet_list = PacketList(raw and self.__raw_buffer[:] or self.__receive_buffer[:])

        def packet_dst_in(dsts, p):
            dsts = isinstance(dsts, list) and dsts or [dsts]
            
            for d in dsts:
                d = IPAddress.identify(d)
                
                if d.version() == 4 and p.haslayer(IP) and IPAddress.identify(p.getlayer(IP).dst) == d:
                    return True
                elif d.version() == 6 and p.haslayer(IPv6) and IPAddress.identify(p.getlayer(IPv6).dst) == d:
                    return True

            return False

        def packet_src_in(srcs, p):
            srcs = isinstance(srcs, list) and srcs or [srcs]

            for s in srcs:
                s = IPAddress.identify(s)

                if s.version() == 4 and p.haslayer(IP) and IPAddress.identify(p.getlayer(IP).src) == s:
                    return True
                elif s.version() == 6 and p.haslayer(IPv6) and IPAddress.identify(p.getlayer(IPv6).src) == s:
                    return True

            return False

        if not (src == None and dst == None and lbda == None and seq == None and type == None):
            packet_list = packet_list.filter(lambda p: (src == None or hasattr(p, 'haslayer') and packet_src_in(src, p)) and \
                                                        (dst == None or hasattr(p, 'haslayer') and packet_dst_in(dst, p)) and \
                                                        (seq == None or hasattr(p, 'haslayer') and (p.haslayer(ICMPv6EchoRequest) and p.getlayer(ICMPv6EchoRequest).seq == seq or p.haslayer(ICMPv6EchoReply) and p.getlayer(ICMPv6EchoReply).seq == seq)) and \
                                                        (type == None or hasattr(p, 'haslayer') and p.getlayer(type)) and \
                                                        (lbda == None or lbda(p)))
        
        return packet_list

    def reset(self):
        self.__raw_buffer = []
        self.__receive_buffer = []
        self.__send_buffer = []
    
    def send(self, packet):
        try:
            if not packet.haslayer(self.ll_protocol.frame):
                # TODO: is ff:ff:ff:ff:ff:ff acceptable as the target address
                #       here? or do we need to resolve the target MAC address?
                frame = self.ll_protocol.frame(src=self.ll_addr, dst="ff:ff:ff:ff:ff:ff")/packet
            else:
                frame = packet
        except AttributeError:
            frame = packet
        
        self.__send_buffer.append(packet)
        
        for callback in self.__on_send_callbacks:
            callback(frame, self)
        
        self.link.accept(frame, previous_hop=self)

    def __str__(self):
        return "<veripy.Interface link=" + self.link.name + ">"


class Link(object):

    class Layer2Protocols:
        Ethernet = link_layers.Ethernet

    def __init__(self, name, ll_protocol=Layer2Protocols.Ethernet, v6_prefix="2012:7665:7269:7079:0000:0000:0000:0000", v6_prefix_size=64, v4_prefix="10.0.0.0", v4_prefix_size=24):
        self.name = name
        self.ll_protocol = ll_protocol
        self.v6_prefix = v6_prefix
        self.v6_prefix_size = v6_prefix_size
        self.v4_prefix = v4_prefix
        self.v4_prefix_size = v4_prefix_size
        self.__bound_interfaces = []

        self.reset()

    def accept(self, packet_or_frame, previous_hop=None):
        self.__forwarded.append(packet_or_frame)
        
        for interface in self.__bound_interfaces:
            if not interface == previous_hop:
                interface.accept(packet_or_frame)

    def bind(self, interface):
        self.__bound_interfaces.append(interface)

    def bound_interfaces(self):
        return self.__bound_interfaces[:]

    def flush_taps(self):
        for iface in self.__bound_interfaces:
            if isinstance(iface, Tap):
                iface.flush()

    def forwarded(self):
        return self.__forwarded[:]

    def reset(self):
        self.__forwarded = []

    def unbind(self, interface):
        self.__bound_interfaces.remove(interface)

    def __str__(self):
        return "<veripy.Link name=" + self.name + "\n             protocol=" + str(self.ll_protocol) + \
                "\n             prefix=" + self.v6_prefix + "\n             prefix_size=" + str(self.v6_prefix_size)   + ">"

class Tap(Interface):

    def __init__(self, link, iface, target_iface=None):
        super(Tap, self).__init__(link=link)
        self.iface = iface
        self.target_iface = target_iface

        self.iface.on_receive(self.receive)

    def accept(self, frame):
        self.iface.send(self.link.ll_protocol.encapsulate(frame, self.iface.ll_addr(), self.target_iface.ll_addr()))

    def flush(self):
        self.iface.flush_sniffer()

    def on_send(self, callback):
        raise Exception("callbacks are not supported on taps")

    def on_receive(self, callback):
        raise Exception("callbacks are not supported on taps")

    def receive(self, frame):
        self.link.accept(frame, self)

    def unbind(self):
        self.link.unbind(self)

    def __str__(self):
        return "<veripy.Tap  link=" + str(self.link.name) + "\n                iface=" + str(self.iface) + \
                "\n                address=" + str(self.iface.ll_addr()) + "\n                target=" + str(self.target_iface) + ">"


class TargetInterface(object):

    def __init__(self, ips=None, ll_protocol=None, link_addr=None):
        self.ips = IPAddressCollection(ips or [])
        self.__ll_addr = link_addr
        self.ll_protocol = ll_protocol

    def global_ip(self, offset=0, type='v6'):
        return self.ips.global_ip(offset=offset, type=type)

    def has_ip(self, ip):
        return str(ip) in self.ips

    def ip(self, offset=0, scope=IPAddressCollection.GLOBAL, type='v6'):
        return self.ips.ip(offset=offset, scope=scope, type=type)

    def link_local_ip(self, offset=0, type='v6'):
        return self.ips.link_local_ip(offset=offset, type=type)
    
    def ll_addr(self):
        return self.__ll_addr

    def __str__(self):
        s = "<veripy.Target address=" + str(self.__ll_addr)

        for ip in self.ip(offset='*', scope='*'):
            s += "\n                  ip=" + str(ip)

        s += ">"

        return s

    
class TestNetwork(object):
    
    def __init__(self, configuration):
        self.__config = configuration
        
        self.__links = [    Link('A',       v4_prefix=self.__config.link1.v4_prefix,
                                            v4_prefix_size=self.__config.link1.v4_prefix_size,
                                            v6_prefix=self.__config.link1.v6_prefix,
                                            v6_prefix_size=self.__config.link1.v6_prefix_size),
                            Link('B',       v4_prefix=self.__config.link2.v4_prefix,
                                            v4_prefix_size=self.__config.link2.v4_prefix_size,
                                            v6_prefix=self.__config.link2.v6_prefix,
                                            v6_prefix_size=self.__config.link2.v6_prefix_size),
                            Link('C',       v4_prefix=self.__config.link3.v4_prefix,
                                            v4_prefix_size=self.__config.link3.v4_prefix_size,
                                            v6_prefix=self.__config.link3.v6_prefix,
                                            v6_prefix_size=self.__config.link3.v6_prefix_size) ]
        self.__nodes = [    TestNode('TN1', ips0=self.__config.tn1.if0_ips,
                                            link0=self.link(2),
                                            ll_addr0=self.__config.tn1.if0_address),
                            TestNode('TN2', ips0=self.__config.tn2.if0_ips,
                                            link0=self.link(1),
                                            ll_addr0=self.__config.tn2.if0_address),
                            TestNode('TN3', ips0=self.__config.tn3.if0_ips,
                                            link0=self.link(1),
                                            ll_addr0=self.__config.tn3.if0_address),
                            TestNode('TN4', ips0=self.__config.tn4.if0_ips,
                                            link0=self.link(3),
                                            ll_addr0=self.__config.tn4.if0_address) ]
        self.__routers = [  TestRouter('TR1', self.link(1),
                                            self.link(2),
                                            self.__config.tr1.if0_address,
                                            self.__config.tr1.if1_address,
                                            self.__config.tr1.if0_ips,
                                            self.__config.tr1.if1_ips,
                                            [self.__config.link1.v6_cidr(), self.__config.link1.v4_cidr()],
                                            [self.__config.link2.v6_cidr(), self.__config.link2.v4_cidr()]),
                            TestRouter('TR2', self.link(1),
                                            self.link(2),
                                            self.__config.tr2.if0_address,
                                            self.__config.tr2.if1_address,
                                            self.__config.tr2.if0_ips,
                                            self.__config.tr2.if1_ips),
                            TestRouter('TR3', self.link(1),
                                            self.link(2),
                                            self.__config.tr3.if0_address,
                                            self.__config.tr3.if1_address,
                                            self.__config.tr3.if0_ips,
                                            self.__config.tr3.if1_ips) ]
        self.__taps = [     Tap(self.link(2),
                                NetworkInterface.get_instance(self.__config.tp1.dev, self.__config.tp1.ll_addr),
                                TargetInterface(self.__config.uut1.ips, self.link(2).ll_protocol, self.__config.uut1.ll_addr)),
                            Tap(self.link(3),
                                NetworkInterface.get_instance(self.__config.tp2.dev, self.__config.tp2.ll_addr),
                                TargetInterface(self.__config.uut2.ips, self.link(3).ll_protocol, self.__config.uut2.ll_addr)) ]

    def disable_nd(self):
        for n in self.nodes(): n.disable_nd()
        for r in self.routers(): r.disable_nd()

    def enable_nd(self):
        for n in self.nodes(): n.enable_nd()
        for r in self.routers(): r.enable_nd()

    def disable_ra(self):
        for r in self.routers(): r.disable_ra()

    def enable_ra(self):
        for r in self.routers(): r.enable_ra()
    
    def link(self, id):
        return self.__links[id-1]

    def links(self):
        return self.__links[:]

    def node(self, id):
        return self.__nodes[id-1]

    def nodes(self):
        return self.__nodes[:]

    def reset(self):
        for link in self.links(): link.reset()
        for node in self.nodes(): node.reset()
        for router in self.routers(): router.reset()

    def router(self, id):
        return self.__routers[id-1]

    def routers(self):
        return self.__routers[:]

    def tap(self, id):
        return self.__taps[id-1]

    def taps(self):
        return self.__taps[:]

    def target(self, id):
        return self.__taps[id-1].target_iface

    def targets(self):
        return map(lambda t: t.target_iface, self.__taps)

    def __str__(self):
        s = "veripy Test Network\n\n"

        s += "Links:\n"
        for link in self.links():
            lines = str(link).split("\n")
            
            s += " - " + lines[0] + "\n"
            for line in lines[1:]:
                s += "   " + line + "\n"

        s += "Nodes:\n"
        for node in self.nodes():
            s += " - " + str(node) + "\n"

        s += "Routers:\n"
        for router in self.routers():
            s += " - " + str(router) + "\n"

        s += "Taps:\n"
        for tap in self.taps():
            s += " - " + str(tap) + "\n"

        return s


class TestNode(object):

    def __init__(self, name, link0, ll_addr0=None, ips0=None):
        self.name = name
        self.__if = []

        self.__perform_nd = True

        self.add_iface(Interface(link=link0, link_addr=ll_addr0, ips=ips0))
        self.if0 = self.iface(0)

    def add_iface(self, iface):
        self.__if.append(iface)

        iface.on_receive(self.respond_to_arp)
        iface.on_receive(self.respond_to_neighbour_solicitation)

    def clear_received(self):
        for iface in self.__if:
            iface.clear_received()

    def disable_nd(self):
        self.__perform_nd = False

    def enable_nd(self):
        self.__perform_nd = True

    def iface(self, id):
        return self.__if[id]

    def ifaces(self):
        return self.__if[:]

    def is_performing_nd(self):
        return self.__perform_nd

    def global_ip(self, iface=0, offset=0, type='v6'):
        return self.__if[iface].global_ip(offset=offset, type=type)

    def ip(self, iface=0, offset=0, scope=IPAddressCollection.GLOBAL, type='v6'):
        return self.__if[iface].ip(offset=offset, scope=scope, type=type)

    def link_local_ip(self, iface=0, offset=0, type='v6'):
        return self.__if[iface].link_local_ip(offset=offset, type=type)

    def received(self, iface=0, src=None, dst=None, lbda=None, seq=None, type=None, raw=False, timeout=5):
        packets = []
        timer = 0

        while len(packets) == 0 and timer < timeout:
            packets = self.iface(iface).received(src=src, dst=dst == None and self.ip(iface=iface, offset='*', scope='*', type='*') or dst, lbda=lbda, seq=None, type=type, raw=raw)

            sleep(0.5)
            timer += 0.5
            
        return packets

    def reset(self):
        for iface in self.__if: iface.reset()

    def respond_to_arp(self, packet, iface):
        if not self.is_performing_nd(): return

        try:
            if packet.haslayer(ARP):
                arp_rq = packet.getlayer(ARP)
                # only respond to ARP requests (op-code is who-is?) destined for
                # an IP address belonging to this interface
                if arp_rq.op == 0x0001 and iface.has_ip(arp_rq.pdst):
                    iface.send(ARP(op=0x0002, hwsrc=iface.ll_addr, psrc=arp_rq.pdst, hwdst=arp_rq.hwsrc, pdst=arp_rq.psrc))
        except AttributeError:
            pass

    def respond_to_neighbour_solicitation(self, packet, iface):
        if not self.is_performing_nd(): return

        try:
            if packet.haslayer(ICMPv6ND_NS):
                src = IPv6Address(packet.getlayer(IPv6).src)
                dst = IPv6Address(packet.getlayer(IPv6).dst)
                tgt = IPv6Address(packet.getlayer(ICMPv6ND_NS).tgt)

                if iface.has_ip(tgt) and (iface.has_ip(dst) or str(dst).startswith("ff02:0000:0000:0000:0000:0001:ff")):
                    iface.send(IPv6(src=str(tgt), dst=str(src))/ICMPv6ND_NA(tgt=str(tgt), R=False, S=True, O=True)/ICMPv6NDOptDstLLAddr(lladdr=iface.ll_addr))
        except AttributeError:
            pass
    
    def send(self, packet_or_frame, iface=0):
        self.__if[iface].send(packet_or_frame)

    def __str__(self):
        s = "<veripy.Node name=" + self.name + ""

        for i, iface in enumerate(self.__if):
            s += "\n                if" + str(i) + "=" + str(iface)

            for ip in self.ip(iface=i, scope='*', offset='*'):
                s += "\n                ip=" + str(ip)

        s += ">"

        return s


class TestRouter(TestNode):
    
    def __init__(self, name, link0, link1, ll_addr0=None, ll_addr1=None, ips0=None, ips1=None, forwards_to_0=None, forwards_to_1=None):
        super(TestRouter, self).__init__(name, link0, ll_addr0=ll_addr0, ips0=ips0)

        self.add_iface(Interface(link=link1, link_addr=ll_addr1, ips=ips1))
        self.if1 = self.iface(1)

        if not (self.if0 == None or self.if1 == None): self.if0.on_receive(self.__forward_to_if1)
        if not (self.if0 == None or self.if1 == None): self.if1.on_receive(self.__forward_to_if0)

        self.__forwards_to_0 = []
        self.__forwards_to_1 = []

        self.__perform_ra = True
        
        if forwards_to_0 != None:
            for n in forwards_to_0:
                self.__forwards_to_0.append(Network(n))
        if forwards_to_1 != None:
            for n in forwards_to_1:
                self.__forwards_to_1.append(Network(n))

    def add_iface(self, iface):
        super(TestRouter, self).add_iface(iface)

        iface.on_receive(self.respond_to_router_solicitation)

    def disable_ra(self):
        self.__perform_ra = False

    def enable_ra(self):
        self.__perform_ra = True

    def is_performing_ra(self):
        return self.__perform_ra

    def respond_to_neighbour_solicitation(self, packet, iface):
        if not self.is_performing_nd(): return
        
        try:
            if packet.haslayer(ICMPv6ND_NS):
                src = IPv6Address(packet.getlayer(IPv6).src)
                dst = IPv6Address(packet.getlayer(IPv6).dst)
                tgt = IPv6Address(packet.getlayer(ICMPv6ND_NS).tgt)

                if iface.has_ip(tgt) and (iface.has_ip(dst) or str(dst).startswith("ff02:0000:0000:0000:0000:0001:ff")):
                    iface.send(IPv6(src=str(tgt), dst=str(src))/ICMPv6ND_NA(tgt=str(tgt), R=True, S=True, O=True)/ICMPv6NDOptDstLLAddr(lladdr=iface.ll_addr))
        except AttributeError:
            pass

    def respond_to_router_solicitation(self, packet, iface):
        if not self.is_performing_ra(): return
    
        try:
            if packet.haslayer(ICMPv6ND_RS):
                src = IPv6Address(packet.getlayer(IPv6).src)

                self.send_ra()
        except AttributeError:
            pass

    def send_ra(self):
        for i, iface in enumerate(self.ifaces()):
            ll_info = ICMPv6NDOptSrcLLAddr(lladdr=iface.ll_addr)
            link_mtu_info = ICMPv6NDOptMTU(mtu=iface.ll_protocol.mtu)
            prefix_info = ICMPv6NDOptPrefixInfo(prefixlen=iface.global_ip().prefix_size, prefix=iface.global_ip().network())

            iface.send(IPv6(src=str(iface.link_local_ip()), dst="ff02::1")/ICMPv6ND_RA(prf=self.name == 'TR1' and 1 or 0)/ll_info/link_mtu_info/prefix_info)

    def __forward_to_if0(self, packet_or_frame, iface):
        if any(map(lambda n: (packet_or_frame.haslayer(IP) or packet_or_frame.haslayer(IPv6)) and str(IPAddress.identify(packet_or_frame.dst)) in n, self.__forwards_to_0)):
            self.__forward_from_to(1, 0, packet_or_frame)

    def __forward_to_if1(self, packet_or_frame, iface):
        if any(map(lambda n: (packet_or_frame.haslayer(IP) or packet_or_frame.haslayer(IPv6)) and str(IPAddress.identify(packet_or_frame.dst)) in n, self.__forwards_to_1)):
            self.__forward_from_to(0, 1, packet_or_frame)

    def __forward_from_to(self, from_iface, to_iface, packet_or_frame):
        try:
            if packet_or_frame.haslayer(IPv6):
                v6_address = IPv6Address(packet_or_frame.getlayer(IPv6).dst)
                
                if packet_or_frame.getlayer(IPv6).hlim <= 0:
                    # do not forward if the maximum hops has passed
                    pass
                elif v6_address.scope() == 'link-local':
                    # do not forward any link-local traffic
                    pass
                elif self.iface(from_iface).has_ip(v6_address):
                    # do not forward any traffic destined for this interface
                    pass
                elif packet_or_frame.haslayer(ICMPv6ND_NS) or packet_or_frame.haslayer(ICMPv6ND_NA):
                    # do not forward neighbour solicitations or advertisements
                    pass
                elif packet_or_frame.haslayer(ICMPv6ND_RS) or packet_or_frame.haslayer(ICMPv6ND_RA):
                    # do not forward router solicitations or advertisements
                    pass
                else:
                    # decrement the hop limit
                    packet_or_frame.getlayer(IPv6).hlim -= 1
                    # forward the packet
                    self.iface(to_iface).send(packet_or_frame)
            elif packet_or_frame.haslayer(IP):
                # do not forward if the maximum hops has passed
                if packet_or_frame.getlayer(IP).ttl <= 0:
                    return
                else:
                    # decrement the TTL
                    packet_or_frame.getlayer(IP).ttl -= 1
                    # forward the packet
                    self.iface(to_iface).send(packet_or_frame)
            else:
                # we appear to have been sent something that is not an IP
                # packet, we'll forward it
                self.iface(to_iface).send(packet_or_frame)
        except AttributeError:
            # we appear to have been sent something that is not a scapy packet
            # at all, we'll forward it anyway
            self.iface(to_iface).send(packet_or_frame)


class RealInterface(object):

    def __init__(self, interface):
        self.__interface = interface

    def sniff(self, **keywords):
        
        tap = None
        for iface in self.__interface.link.bound_interfaces():
            if isinstance(iface, Tap):
                tap = iface
                
        return tap.iface.sniff(**keywords)
