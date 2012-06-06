from scapy.all import *
from scapy.layers import dhcp6
from time import time


def duid(ll_addr):
    return DUID_LLT(lladdr=ll_addr, timeval=time())

def ias(requested, iface, T1=None, T2=None):
    return map(lambda r: __build_ia(r, iface, T1, T2), requested)

def options(requested):
    return map(__build_option_by_code, requested)

def __build_ia(request, iface, T1=None, T2=None):
    ia = request.__class__(iaid=request.iaid, T1=(T1 == None and request.T1 or T1), T2=(T2 == None and request.T2 or T2))

    ia.ianaopts.append(DHCP6OptIAAddress(addr=str(iface.global_ip()), preflft=300, validlft=300))

    return ia

def __build_option_by_code(code):
    opt = __option_klass_by_code(code)()

    if isinstance(opt, DHCP6OptClientFQDN):
        opt.fqdn = 'testhost.local.'
    elif isinstance(opt, DHCP6OptDNSDomains):
        pass
    elif isinstance(opt, DHCP6OptDNSServers):
        opt.dnsservers.append('2001:500:88:200::10')
    elif isinstance(opt, DHCP6OptSNTPServers):
        opt.sntpservers.append('2001:500:88:200::10')

    return opt

def __option_klass_by_code(code):
    return getattr(dhcp6, dhcp6.dhcp6opts_by_code[code])
