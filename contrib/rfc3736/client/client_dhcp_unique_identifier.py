from contrib.rfc3736.builder import *
from contrib.rfc3736.constants import *
from contrib.rfc3736.dhcpv6 import DHCPv6Helper
from scapy.all import *
from veripy.assertions import *


class DUIDFormatTestCase(DHCPv6Helper):
    """
    DUID Format
    
    Verify that a client device sends correctly formatted Client ID options.
    
    @private
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 7.1.9)
    """
    
    def run(self):
        q = self.restart_and_wait_for_information_request(self.node(1), self.target(1))

        assertHasLayer(DHCP6OptClientId, q, "expected the DHCPv6 Information Request to have a Client Identifier")

        duid = q[DHCP6OptClientId].duid
        
        if duid.__class__ == DUID_EN:
            assertNotEqual(0, duid.id, "did not expect the DUID ID to be zero")
            assertNotEqual(0, duid.enterprisenum, "did not expect the DUID Enterprise Number to be zero")
        elif duid.__class__ == DUID_LLT:
            assertEqual(str(self.target(1).ll_addr()), duid.lladdr, "expected the DUID Link Layer Address to be %s" % (self.target(1).ll_addr()))
            assertTrue(duid.hwtype in range(1,37) or duid.hwtype == 256, "expected the DUID Hardware Type to be 1-37 or 256")
        elif duid.__class__ == DUID_LL:
            assertEqual(str(self.target(1).ll_addr()), duid.lladdr, "expected the DUID Link Layer Address to be %s" % (self.target(1).ll_addr()))
            assertTrue(duid.hwtype in range(1,37) or duid.hwtype == 256, "expected the DUID Hardware Type to be 1-37 or 256")
            
