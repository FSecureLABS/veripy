from veripy.models import ComplianceTestSuite
from veripy.models.decorators import must, should

import deprecation_of_rh0

class DeprecationOfRH0Specification(ComplianceTestSuite):
    """
    Deprecation of Type 0 Routing Headers in IPv6

    RFC2460 defines an IPv6 extension header called "Routing Header",
    identified by a Next Header value of 43 in the immediately preceding
    header. A particular Routing Header subtype denoted as "Type 0" is
    also defined.

    This header allows a packet to be constructed such that it will oscillate
    between two RH0-processing hosts or routers many times. Allowing
    a stream of packets from an attacker to be amplified along the path
    between two remote routers, which could be used to cause congestion
    and act as a denial-of-service mechanism.

    @private
    Author:         MWR
    Source:         RFC5095
    """

    TestCase_001 = deprecation_of_rh0.RH0WithSegmentsLeftEqualToZeroToRUTTestCase
    TestCase_002 = deprecation_of_rh0.RH0WithSegmentsLeftEqualToZeroToTN4TestCase
    TestCase_003 = deprecation_of_rh0.RH0WithSegmentsLeftGreaterThanZeroToRUTTestCase
    TestCase_004 = deprecation_of_rh0.RH0WithSegmentsLeftGreaterThanZeroToTN4TestCase

ComplianceTestSuite.register('deprecation-of-rh0', DeprecationOfRH0Specification)
