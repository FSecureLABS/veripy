import re
from libs.ipcalc import Network
from veripy.util import IPv4Format, IPv6Format


class IPAddress(object):

    def __init__(self, ip):
        self.ip = ip

    @classmethod
    def identify(cls, ip):
        if isinstance(ip, IPAddress):
            return ip
        elif IPv4Address.is_valid(ip):
            return IPv4Address(ip)
        elif IPv6Address.is_valid(ip):
            return IPv6Address(ip)
        else:
            return None

    def netmask(self):
        return str(Network("%s/%s" % (self.ip, self.prefix_size)).netmask())

    def network(self):
        return str(Network("%s/%s" % (self.ip, self.prefix_size)).network())

    def __cmp__(self, other):
        if self < other:
            return -1
        elif self > other:
            return 1
        else:
            return 0

    def __eq__(self, other):
        ip = IPAddress.identify(other)

        return not ip == None and ip.ip == self.ip

    def __ge__(self, other):
        n1 = Network(self)
        n2 = Network(other)

        return int(n1) >= int(n2)
    
    def __gt__(self, other):
        n1 = Network(self)
        n2 = Network(other)

        return int(n1) > int(n2)

    def __le__(self, other):
        n1 = Network(self)
        n2 = Network(other)

        return int(n1) <= int(n2)

    def __lt__(self, other):
        n1 = Network(self)
        n2 = Network(other)

        return int(n1) < int(n2)

    def __ne__(self, other):
        ip = IPAddress.identify(other)

        return ip == None or ip.ip != self.ip
    
    def __str__(self):
        return self.ip[:]

class IPv4Address(IPAddress):

    def __init__(self, ip):
        super(IPv4Address, self).__init__(ip)

        self.prefix_size = 24

    @classmethod
    def is_valid(cls, ip):
        try:
            return not re.match(IPv4Format, ip) == None
        except TypeError:
            return False

    def canonical_form(self):
        return self.ip[:]

    def short_form(self):
        return self.ip[:]

    def version(self):
        return 4

class IPv6Address(IPAddress):

    Scopes = ['interface-local', 'link-local', 'subnet-local', 'admin-local', 'site-local', 'organisation-local', 'global']

    def __init__(self, ip):
        super(IPv6Address, self).__init__(ip)

        self.prefix_size = 64

        self.__canonicalise()
        
    @classmethod
    def is_valid(cls, ip):
        try:
            return not re.match(IPv6Format, ip) == None
        except TypeError:
            return False

    def canonical_form(self):
        return self.ip[:]

    def is_loopback(self):
        return self.ip == "0000:0000:0000:0000:0000:0000:0000:0001"

    def is_multicast(self):
        return self.ip.startswith("ff")

    def is_tunnel(self):
        return self.ip.startswith("2002")

    def is_undefined(self):
        return self.ip == "0000:0000:0000:0000:0000:0000:0000:0000"

    def is_v4_mapped(self):
        return self.ip.startswith("0000:0000:0000:0000:0000:ffff:")
    
    def scope(self, index=False):
        if self.is_multicast():
            if self.ip.startswith("ff1"):
                return index and 1 or IPv6Address.Scopes[0]
            elif self.ip.startswith("ff2"):
                return index and 2 or IPv6Address.Scopes[1]
            elif self.ip.startswith("ff3"):
                return index and 3 or IPv6Address.Scopes[2]
            elif self.ip.startswith("ff4"):
                return index and 4 or IPv6Address.Scopes[3]
            elif self.ip.startswith("ff5"):
                return index and 5 or IPv6Address.Scopes[4]
            elif self.ip.startswith("ff8"):
                return index and 8 or IPv6Address.Scopes[5]
            elif self.ip.startswith("ffe"):
                return index and 15 or IPv6Address.Scopes[6]
            else:
                return None
        else:
            if self.is_undefined():
                return None
            elif self.is_loopback():
                return index and 1 or IPv6Address.Scopes[0]
            elif self.ip.startswith("fe80"):
                return index and 2 or IPv6Address.Scopes[1]
            elif self.ip.startswith("fc00"):
                return index and 6 or IPv6Address.Scopes[6]
            elif self.ip.startswith("fec0"):
                return index and 4 or IPv6Address.Scopes[4]
            else:
                return index and 15 or IPv6Address.Scopes[6]
    
    def short_form(self):
        blocks = map(lambda b: b.lstrip("0"), self.ip.split(":"))

        return re.sub("::+", "::", reduce(lambda x,y: x + ":" + y, blocks))

    def solicited_node(self):
        return "ff02:0:0:0:0:1:ff" + self.ip[-7:]
        
    def version(self):
        return 6

    def __canonicalise(self):
        v4 = re.search("([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)$", self.ip)

        if not v4 == None:
            self.ip = self.ip[0:self.ip.rindex(":")] + ":" + \
                        hex(int(v4.group(1)))[2:].zfill(2) + \
                        hex(int(v4.group(2)))[2:].zfill(2) + ":" + \
                        hex(int(v4.group(3)))[2:].zfill(2) + \
                        hex(int(v4.group(4)))[2:].zfill(2)
        
        blocks = map(lambda b: b != "" and b.zfill(4) or None, self.ip.split(":"))
        
        if len(blocks) < 8:
            f_blocks = blocks[0:blocks.index(None)]
            b_blocks = blocks[len(blocks)-blocks[::-1].index(None):]
            
            m_blocks = map(lambda x: "0000", range(0, 8 - len(f_blocks) - len(b_blocks)))
            
            blocks = f_blocks + m_blocks + b_blocks

        self.ip = reduce(lambda x,y: x + ":" + y, blocks).lower()
