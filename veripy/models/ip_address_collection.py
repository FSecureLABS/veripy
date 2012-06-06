from veripy.models.ip_address import IPAddress


class IPAddressCollection(object):
    
    INTERFACELOCAL = 1
    LINKLOCAL = 2
    SUBNETLOCAL = 3
    ADMINLOCAL = 4
    SITELOCAL = 5
    ORGANISATIONLOCAL = 8
    GLOBAL = 15


    def __init__(self, ips):
        self.__v4_ips = []
        self.__v4_mapped_ips = []
        self.__v6_ips = []
        self.__v6_tunnel_ips = []

        for ip in ips:
            self.append(ip)

    def append(self, ip):
        if not isinstance(ip, IPAddress):
            ip = IPAddress.identify(ip)

        if not str(ip) in self:
            if ip.version() == 4:
                self.__v4_ips.append(ip)
            elif ip.version() == 6 and not ip.is_tunnel() and not ip.is_v4_mapped():
                self.__v6_ips.append(ip)
            elif ip.version() == 6 and ip.is_tunnel():
                self.__v6_tunnel_ips.append(ip)
            elif ip.version() == 6 and ip.is_v4_mapped():
                self.__v4_mapped_ips.append(ip)

    def global_ip(self, offset=0, type='v6'):
        return self.ip(offset=offset, scope=IPAddressCollection.GLOBAL, type=type)

    def ip(self, offset=0, scope=GLOBAL, type='v6'):
        if type == 'v6':
            if scope != '*':
                ips = filter(lambda ip: ip.scope(index=True) == scope, self.__v6_ips)
            else:
                ips = self.__v6_ips
        elif type == 'v4':
            ips = self.__v4_ips
        elif type == 'v4mapped':
            ips = self.__v4_mapped_ips
        elif type == '6in4':
            ips = self.__v6_tunnel_ips
        elif type == '*':
            if scope != '*':
                ips = filter(lambda ip: ip.scope(index=True) == scope, self.__v6_ips)
            else:
                ips = self.__v6_ips[:]

            ips.extend(self.__v4_ips)
            ips.extend(self.__v6_tunnel_ips)
        else:
            ips = []

        if offset == '*':
            return ips[:]
        else:
            return offset < len(ips) and ips[offset] or None

    def link_local_ip(self, offset=0, type='v6'):
        return self.ip(offset=offset, scope=IPAddressCollection.LINKLOCAL, type=type)

    def __iter__(self):
        for ip in self.__v4_ips:
            yield str(ip)
        for ip in self.__v6_ips:
            yield str(ip)
        for ip in self.__v6_tunnel_ips:
            yield str(ip)
    
    def __len__(self):
        return len(self.__v4_ips) + len(self.__v6_ips) + len(self.__v6_tunnel_ips)
