from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase


class ChooseSameAddressTestCase(ComplianceTestCase):
    """
    IPv6 Default Address Selection - Choose Same Address
    
    Verify that a node selects a source address that is the same as the
    destination address if the packet is being sent to the same interface.
    
    @private
    Source:         RFC 3484 Section 5, Rule 1
    """
    
    def run(self):
        if len(self.target(1).global_ip(offset='*')) < 2:
            fail("Cannot Test. The UUT requires two global IP addresses for this test case to be valid.")
        
        self.ui.tell("Please send an ICMPv6 Echo Request from the UUT to %s." % self.target(1).global_ip(offset=0))
        self.ui.ask("Have you sent the Echo Request?")
        
        self.logger.info("Attempting to find the Echo Request.")
        r1 = self.node(1).received(dst=self.target(1).global_ip(offset=0), type=ICMPv6EchoRequest)

        assertEqual(1, len(r1), "expected to see the ICMPv6 Echo Request sent by the UUT")
            
        self.logger.info("Verifying the source of ICMPv6 Echo Request.")
        assertEqual(self.target(1).global_ip(offset=0), r1[0].getlayer(IPv6).src)

        self.ui.tell("Please send an ICMPv6 Echo Request from the UUT to %s." % self.target(1).global_ip(offset=1))
        self.ui.ask("Have you sent the Echo Request?")

        self.logger.info("Attempting to find the second Echo Request.")
        r1 = self.node(1).received(dst=self.target(1).global_ip(offset=1), type=ICMPv6EchoRequest)

        assertEqual(1, len(r1), "expected to see the ICMPv6 Echo Request sent by the UUT")

        self.logger.info("Verifying the source of ICMPv6 Echo Request.")
        assertEqual(self.target(1).global_ip(offset=1), r1[0].getlayer(IPv6).src)


class ChooseAppropriateScopeTestCase(ComplianceTestCase):
    """
    IPv6 Default Address Selection - Choose Appropriate Scope

    Verify that a node selects a source address with the smallest scope that is
    shared with the destination address.

    @private
    Source:         RFC 3484 Section 5, Rule 2
                    RFC 3484 Page 8 Paragraph 4
    """

    def run(self):
        self.ui.tell("Please send an ICMPv6 Echo Request from the UUT to %s." % self.node(1).link_local_ip())
        self.ui.ask("Have you sent the Echo Request?")
        
        self.logger.info("Attempting to find the Echo Request.")
        r1 = self.node(1).received(dst=self.node(1).link_local_ip(), type=ICMPv6EchoRequest)

        assertEqual(1, len(r1), "expected to see the ICMPv6 Echo Request sent by the UUT")

        self.logger.info("Verifying the source of ICMPv6 Echo Request.")
        assertEqual(self.target(1).link_local_ip(), r1[0].getlayer(IPv6).src)

        self.ui.tell("Please send an ICMPv6 Echo Request from the UUT to %s." % self.node(1).global_ip())
        self.ui.ask("Have you sent the Echo Request?")

        self.logger.info("Attempting to find the second Echo Request.")
        r1 = self.node(1).received(dst=self.node(1).global_ip(), type=ICMPv6EchoRequest)

        assertEqual(1, len(r1), "expected to see the ICMPv6 Echo Request sent by the UUT")

        self.logger.info("Verifying the source of ICMPv6 Echo Request.")
        assertEqual(self.target(1).global_ip(), r1[0].getlayer(IPv6).src)


class PreferHomeAddressTestCase(ComplianceTestCase):
    """
    IPv6 Default Address Selection - Prefer Home Address

    Verify that a node prefers its home address over its care-of address, when
    roaming by MIPv6.

    @private
    Source:         RFC 3484 Section 5, Rule 4
    """
    pass


class PreferOutgoingInterfaceTestCase(ComplianceTestCase):
    """
    IPv6 Default Address Selection - Prefer Outgoing Interface
    
    Verify that a node prefers to use an address assigned to the interface
    which will be used to send to the destination address.
    
    @private
    @should
    Source:         RFC 3484 Section 5, Rule 5
    """

    def run(self):
        self.ui.tell("Please send an ICMPv6 Echo Request from the UUT to %s." % self.node(1).global_ip())
        self.ui.ask("Have you sent the Echo Request?")

        self.logger.info("Attempting to find the Echo Request.")
        r1 = self.node(1).received(type=ICMPv6EchoRequest)

        assertEqual(1, len(r1), "expected to see the ICMPv6 Echo Request sent by the UUT")

        self.logger.info("Verifying the source of ICMPv6 Echo Request.")
        assertEqual(self.target(1).global_ip(), r1[0].getlayer(IPv6).src)

        self.ui.tell("Please send an ICMPv6 Echo Request from the UUT to %s." % self.node(4).global_ip())
        self.ui.ask("Have you sent the Echo Request?")

        self.logger.info("Attempting to find the second Echo Request.")
        r1 = self.node(4).received(type=ICMPv6EchoRequest)

        assertEqual(1, len(r1), "expected to see the ICMPv6 Echo Request sent by the UUT")

        self.logger.info("Verifying the source of ICMPv6 Echo Request.")
        assertEqual(self.target(2).global_ip(), r1[0].getlayer(IPv6).src)


#class PreferMatchingLabelTestCase(SourceAddressSelectionHelper):
#	"""
#	IPv6 Default Address Selection - Prefer Matching Label
#
#	Verify that a node prefers to use an address with a label that matches the
#	destination address's label.
#
#	@private
#	@should
#	Source:           RFC 3484 Section 5, Rule 6
#	"""
#
#	def collect_addresses(self):
#		self.logger.info("Prompting user for two addresses, one with a label which matches the destination IP label, and one which does not.")
#		test_ips = []
#		while True:
#			matching_label_ip = self.ui.read("Please enter an IP address with a label matching the label of %s: [n/a]" % self.iface(self.SUBNET1).ip())
#			if (len(matching_label_ip) > 0 and matching_label_ip in map(str, self.uut(self.SUBNET1).ip("*", "*"))) or len(matching_label_ip) == 0:
#				test_ips.append(matching_label_ip)
#				break
#			self.ui.tell("Address not available for use.")
#		while True:
#			unmatching_label_ip = self.ui.read("Please enter an IP address with a label different to the label of %s: [n/a]" % self.iface(self.SUBNET1).ip())
#			if (len(unmatching_label_ip) > 0 and unmatching_label_ip in map(str, self.uut(self.SUBNET1).ip("*", "*"))) or len(unmatching_label_ip) == 0:
#				test_ips.append(unmatching_label_ip)
#				break
#			self.ui.tell("Address not available for use.")
#		super(PreferMatchingLabelTestCase, self).setup_addresses(test_ips, matching_label_ip)
#
#	def run(self):
#		self.collect_addresses()
#		self.confirm_suitable_addresses_collected()
#		self.receive_request()
#		self.check_packets()


class PreferPublicOverTemporaryAddressesTestCase(ComplianceTestCase):
    """
    IPv6 Default Address Selection - Prefer Public Address over Temporary
    Addresses
    
    Verify that a node prefers to use a public address rather than a temporary
    address, unless the device is configured to prefer temporary addresses over
    public addresses.
    
    @private
    Source:         RFC 3484 Section 5, Rule 7
    """
    pass
#
#	def collect_addresses(self):
#		self.logger.info("Prompting user for information on whether or not public addresses are preferred over temporary addresses.")
#		public_addresses_preferred = self.ui.ask("Are public addresses preferred over temporary addresses?")
#		test_ips = []
#		while True:
#			public_address = self.ui.read("Please enter an IP address with a label matching the label of %s: [n/a]" % self.iface(self.SUBNET1).ip())
#			if (len(public_address) > 0 and public_address in map(str, self.uut(self.SUBNET1).ip("*", "*"))) or len(public_address) == 0:
#				test_ips.append(public_address)
#				break
#			self.ui.tell("Address not available for use.")
#		while True:
#			temporary_address = self.ui.read("Please enter an IP address with a label different to the label of %s: [n/a]" % self.iface(self.SUBNET1).ip())
#			if (len(temporary_address) > 0 and temporary_address in map(str, self.uut(self.SUBNET1).ip("*", "*"))) or len(temporary_address) == 0:
#				test_ips.append(temporary_address)
#				break
#			self.ui.tell("Address not available for use.")
#		super(PreferPublicAddressTestCase, self).setup_addresses(test_ips, public_address if public_addresses_preferred else temporary_address)
#
#	def run(self):
#		self.collect_addresses()
#		self.confirm_suitable_addresses_collected()
#		self.receive_request()
#		self.check_packets()


#class UseLongestMatchingPrefixTestCase(SourceAddressSelectionHelper):
#	"""
#	IPv6 Default Address Selection - Use Longest Matching Prefix
#
#	Verify that a node prefers to use an address that shares the longest matching length
#	prefix in common with the destination address.
#
#	@private
#	@should
#	Source:           RFC 3484 Section 5, Rule 8
#	"""
#
#	def collect_addresses(self):
#		dest_ip = self.iface(self.SUBNET1).ip()
#		ips = self.uut(self.SUBNET1).ip("*", "*")
#		likenesses = {}
#		for ip in map(lambda x: str(x), ips):
#			ip = util.expand_v6(ip)
#			likenesses[ip] = self.likeness(ip, dest_ip)
#		ips = sorted(likenesses.items())
#		test_ips = []
#		longer_matching_ip = None
#		if len(ips) > 1 and ips[0][1] != ips[-1][1]:
#			longer_matching_ip = util.contract_v6(ips[0][0])
#			test_ips.extend([util.contract_v6(ips[0][0]), util.contract_v6(ips[1][0])])
#		super(UseLongestMatchingPrefixTestCase, self).setup_addresses(test_ips, longer_matching_ip)
#
#	def run(self):
#		self.collect_addresses()
#		self.confirm_suitable_addresses_collected()
#		self.receive_request()
#		self.check_packets()
#
#	def likeness(self, ip_a, ip_b):
#		for i in range(len(ip_a)):
#			if util.expand_v6(ip_a[i]) != util.expand_v6(ip_b[i]):
#				return i
#		return len(ip_a)


class SourceAddressMustBeIPv4MappedOnSIITNodeTestCase(ComplianceTestCase):
    """
    IPv6 Default Address Selection - Source Address must be IPv4 mapped if the
    Destination Address is, on a SIIT Node
    
    Verify that a SIIT node only uses an IPv4-translateable address given an
    IPv4-translateable destination.
    
    @private
    Source:         RFC 3484 Page 8 Paragraph 9
    """
    
    def run(self):
        if len(self.node(1).ip(type='v4mapped', offset='*')) == 0:
            fail("Cannot Test. The UUT requires an IPv4-mapped address for this test case to be valid.")
        
        self.ui.tell("Please send an ICMPv6 Echo Request from the UUT to %s." % self.node(1).ip(type='v4mapped'))
        self.ui.ask("Have you sent the Echo Request?")
        
        self.logger.info("Attempting to find the Echo Request.")
        r1 = self.node(1).received(dst=self.node(1).ip(type='v4mapped'), type=ICMPv6EchoRequest)

        assertEqual(1, len(r1), "expected to see the ICMPv6 Echo Request sent by the UUT")

        self.logger.info("Verifying the source of ICMPv6 Echo Request.")
        assertEqual(self.target(1).ip(type='v4mapped'), r1[0].getlayer(IPv6).src)


class SourceAddressMustNotBeIPv4MappedOnSIITNodeTestCase(ComplianceTestCase):
    """
    IPv6 Default Address Selection - Source Address must not be IPv4 mapped if
    the Destination Address is not, on a SIIT Node

    Verify that a SIIT node does not use an IPv4-translateable address given an
    IPv6 destination.

    @private
    Source:         RFC 3484 Page 8 Paragraph 9
    """

    def run(self):
        if len(self.node(1).ip(type='v4mapped', offset='*')) == 0:
            fail("Cannot Test. The UUT requires an IPv4-mapped address for this test case to be valid.")
            
        self.ui.tell("Please send an ICMPv6 Echo Request from the UUT to %s." % self.node(1).ip(type='v6'))
        self.ui.ask("Have you sent the Echo Request?")
        
        self.logger.info("Attempting to find the Echo Request.")
        r1 = self.node(1).received(dst=self.node(1).ip(type='v6'), type=ICMPv6EchoRequest)

        assertEqual(1, len(r1), "expected to see the ICMPv6 Echo Request sent by the UUT")

        self.logger.info("Verifying the source of ICMPv6 Echo Request.")
        assertEqual(self.target(1).ip(type='v6'), r1[0].getlayer(IPv6).src)
        