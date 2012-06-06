from scapy.all import IPv6ExtHdrFragment
from veripy.assertions.simple import *
from veripy.assertions.support import AssertionCounter, AssertionFailedError


def assertHasLayer(layer, actual, message=''):
    AssertionCounter.incr()

    assertNotNone(actual)

    if not actual.haslayer(layer):
        raise AssertionFailedError(message == '' and 'expected "' + actual.summary() + '" to have layer ' + str(layer.__name__) or message)
    else:
        return True

def assertNotHasLayer(layer, actual, message=''):
    AssertionCounter.incr()

    assertNotNone(actual)

    if actual.haslayer(layer):
        raise AssertionFailedError(message == '' and 'expected "' + actual.summary() + '" not to have layer ' + str(layer.__name__) or message)
    else:
        return True

def assertFragmented(packet, pcap, count=1, size=None, reassemble_to=None):
    assertHasLayer(IPv6ExtHdrFragment, packet, "expected packet to have a IPv6 Fragment Extension header")
    assertEqual(0x00, packet[IPv6ExtHdrFragment].offset, "expected packet to be the first fragment")

    fragments = pcap.filter(lambda p: p.haslayer(IPv6ExtHdrFragment) and p[IPv6ExtHdrFragment].id == packet[IPv6ExtHdrFragment].id)

    assertGreaterThanOrEqualTo(count, len(fragments), "expected to receive at least %d fragments, got %d" % (count, len(fragments)))
    assertEqual(1, len(filter(lambda p: p[IPv6ExtHdrFragment].m == False, fragments)), "expected a single fragment to have the More Fragments flag set to False")
    
    if not size == None:
        for fragment in fragments:
            assertLessThanOrEqualTo(size, len(fragment),"expected all fragments to be no larger than %d octets, got one of %d" % (size, len(fragment)))
    if not reassemble_to == None:
        reassembled_size = len(packet) - len(IPv6ExtHdrFragment())
        for fragment in fragments:
            if fragment[IPv6ExtHdrFragment].offset != 0x00:
                reassembled_size += len(fragment[IPv6ExtHdrFragment].payload)

        assertEqual(reassemble_to, reassembled_size, "expected fragments to reassemble to %d, got %d" % (reassemble_to, reassembled_size))

def assertNotFragmented(packet):
    assertNotHasLayer(IPv6ExtHdrFragment, packet)
    