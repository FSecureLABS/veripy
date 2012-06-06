#!/usr/bin/python

# veripy:         a tool for verifying the compliance of ICT Equipment against
#                 requirements for IPv6 set out in RIPE-501
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
#   Baseline CSS        http://baselinecss.com/                       CC A/SA
#   scapy               http://www.secdev.org/projects/scapy/         GPLv2
#   xyaptu              http://code.activestate.com/recipes/162292/   PSF
#   yaptu               http://code.activestate.com/recipes/52305/    PSF

try:
    import contrib
    import sys
    from veripy import Configuration, Runner
    from veripy.interfaces import CLI

    CLI(configuration=Configuration, runner=Runner).run(sys.argv[1::])
except ImportError, e:
    from os import path

    print "veripy: You do not have veripy, or one of its components in your current Python"
    print "        path. You will need to update your PYTHONPATH environment variable"
    print "        to include the veripy root directory, which may be:"
    print
    print "          " + path.dirname(path.dirname(path.abspath(__file__)))
    print
    print "        The Python interpreter said: " + e.message + "."
