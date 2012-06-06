from veripy.models import ComplianceTestSuite

import cga_generation

class CryptographicallyGeneratedAddresses(ComplianceTestSuite):
    """
    Cryptographically Generated Addresses (CGA)

    CGA is a method for binding a public signature key to an IPv6 address in
    the Secure Neighbor Discovery (SEND) protocol by generating the interface
    identifier as a cryptographic one-way hash function of a public key and
    auxiliary parameters.

    This is a limited test suite, that verifies the UUT's ability to generate
    an address using CGA.
    
    @private
    Source:         RFC 3972
    Author:         MWR
    """
    
    TestCase_001 = cga_generation.VerifyCGAGenerationTestCase


ComplianceTestSuite.register('cryptographically-generated-addresses', CryptographicallyGeneratedAddresses)
