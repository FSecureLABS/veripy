#!/usr/bin/python

# send-ra.py      a tool for spoofing IPv6 Router Advertisements
#
#                 This file is a utility provided with veripy.
#
#                 For more information about veripy, see the project website at
#                 http://veripy.org/

# Copyright (C) 2012 MWR InfoSecurity.
# This file is part of veripy.
#
# veripy is free software: you can redistribute it and/or modify it under the
# terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.
#
# veripy is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# veripy. If not, see <http://www.gnu.org/licenses/>.

# veripy makes use of a number of code libraries. These are the copyright of
# their respective owners.
#
#   Library             URL                                           License
#   ------------------- --------------------------------------------- ---------
#   scapy               http://www.secdev.org/projects/scapy/         GPLv2

from optparse import OptionParser
from scapy.all import *
from sys import argv

parser = OptionParser(usage="usage: %prog [options] PREFIX")

parser.add_option("-i", dest="iface", default="eth0", help="the interface to send the message on, default eth0", metavar="IFACE")
parser.add_option("-l", dest="lladdr", help="the Link Layer address to include, if any", metavar="MAC")
parser.add_option("-m", dest="mtu", default=1500, help="the MTU, defaults to 1500")
parser.add_option("-v", dest="verbose", action="store_true", help="enable verbose mode")
parser.add_option("--dest", dest="destination", default="ff02::1", help="the destination to send the advertisement to", metavar="IP")
parser.add_option("--source", dest="source", default="::", help="the source to send the advertisement from", metavar="IP")
parser.add_option("--prefix-len", dest="prefix_len", default=64, help="the prefix length, defaults to 64", metavar="LENGTH")

(options, args) = parser.parse_args(argv)

if len(args) != 2:
    parser.print_help()
else:
    p = Ether()/IPv6(src=options.source, dst=options.destination)/ICMPv6ND_RA()/ICMPv6NDOptPrefixInfo(prefixlen=int(options.prefix_len), prefix=args[1])

    if not options.mtu == None:
        p = p/ICMPv6NDOptMTU(mtu=int(options.mtu))
    if not options.lladdr == None:
        p = p/ICMPv6NDOptSrcLLAddr(lladdr=options.lladdr)

    if options.verbose:
        p.show()
    
    srp(p, iface=options.iface, timeout=1)

