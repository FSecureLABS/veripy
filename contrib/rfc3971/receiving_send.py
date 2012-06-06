
from scapy.all import *
from send_helper import ValidSendHelper, InvalidSendButCanContinueHelper

class UUTProcessValidSendTestCase(ValidSendHelper):
    """
    SEND

    Verify the UUT can process a valid send message

    @private
    source rfc 3971 5.1, 5.2, 5.3
    """
    def set_up(self):
        super(UUTProcessValidSendTestCase, self).set_up()
        self.packet_to_send = self.construct_valid_sign_ns()

class UUTProcessValidSendReservedFieldSetTestCase(ValidSendHelper):
    """
    SEND

    Verify the UUT can process a valid send message with reserved field set

    @private
    source rfc 3971 5.1, 5.2, 5.3
    """
    def set_up(self):
        super(UUTProcessValidSendReservedFieldSetTestCase, self).set_up()
        ns_pket = ICMPv6ND_NS(tgt=str(self.target(1).link_local_ip()))/ICMPv6NDOptSrcLLAddr(lladdr=self.node(1).iface(0).ll_addr)
        ns_pket = self.add_send_options(ns_pket)
        ns_pket[ICMPv6NDOptCGA].res = 1
        self.packet_to_send = self.sign(self.ipv6_layer/ns_pket, ICMPv6ND_NS)

class UUTReceivesNoCGAOptionTestCase(InvalidSendButCanContinueHelper):
    """
    SEND - Doesn't receive CGA Option

    Verify the UUT will treat an NS without CGA Option as unsecured

    @private
    source rfc 3971 5.1.2
    """
    def set_up(self):
        super(UUTReceivesNoCGAOptionTestCase, self).set_up()
        ns_pket = ICMPv6ND_NS(tgt=str(self.target(1).link_local_ip()))/ICMPv6NDOptSrcLLAddr(lladdr=self.node(1).iface(0).ll_addr)
        ns_pket = ns_pket/ICMPv6NDOptNO(nonce=chr(random.randint(0,255))*6, len=1)/ICMPv6NDOptTS(timestamp=time.time())
        self.packet_to_send = self.sign(self.ipv6_layer/ns_pket, ICMPv6ND_NS)


class UUTReceivesDifferentKeyTestCase(InvalidSendButCanContinueHelper):
    """
    SEND - Receives Key hash different to CGA Option

    Verify the UUT will treat an NS without CGA Option as unsecured

    @private
    source rfc 3971 5.2.2
    """
    def set_up(self):
        super(UUTReceivesDifferentKeyTestCase, self).set_up()
        self.packet_to_send = self.construct_valid_sign_ns()

        # Send a different key hash
        self.packet_to_send[ICMPv6NDOptRSA].hash = "9de5f82e02105jce5f08a94b3640cb90"

class UUTReceivesNoRSAOptionTestCase(InvalidSendButCanContinueHelper):
    """
    SEND - Doesn't Receive RSA Option

    Verify the UUT will treat an NS without RSA Option as unsecured

    @private
    source rfc 3971 5.2.2
    """
    def set_up(self):
        super(UUTReceivesNoRSAOptionTestCase, self).set_up()
        ns_pket = ICMPv6ND_NS(tgt=str(self.target(1).link_local_ip()))/ICMPv6NDOptSrcLLAddr(lladdr=self.node(1).iface(0).ll_addr)
        ns_pket = self.add_send_options(ns_pket)
        self.packet_to_send = self.ipv6_layer/ns_pket

class UUTReceivesNoNonceOptionTestCase(InvalidSendButCanContinueHelper):
    """
    SEND - Doesn't Receive Nonce Option

    Verify the UUT will treat an NS without Nonce Option as unsecured

    @private
    source rfc 3971 5.3.4
    """
    def set_up(self):
        super(UUTReceivesNoNonceOptionTestCase, self).set_up()
        ns_pket = ICMPv6ND_NS(tgt=str(self.target(1).link_local_ip()))/ICMPv6NDOptSrcLLAddr(lladdr=self.node(1).iface(0).ll_addr)
        ns_pket = ns_pket/self.cga_opt/ICMPv6NDOptTS(timestamp=time.time())
        self.packet_to_send = self.sign(self.ipv6_layer/ns_pket, ICMPv6ND_NS)

class UUTReceivesNoTimeStampOptionTestCase(InvalidSendButCanContinueHelper):
    """
    SEND - Doesn't Receive Timestamp Option

    Verify the UUT will treat an NS without Timestamp Option as unsecured

    @private
    source rfc 3971 5.3.4
    """
    def set_up(self):
        super(UUTReceivesNoTimeStampOptionTestCase, self).set_up()
        ns_pket = ICMPv6ND_NS(tgt=str(self.target(1).link_local_ip()))/ICMPv6NDOptSrcLLAddr(lladdr=self.node(1).iface(0).ll_addr)
        ns_pket = ns_pket/self.cga_opt/ICMPv6NDOptNO(nonce=chr(random.randint(0,255))*6, len=1)
        self.packet_to_send = self.sign(self.ipv6_layer/ns_pket, ICMPv6ND_NS)

class UUTReceivesRSAOptionNotLastTestCase(InvalidSendButCanContinueHelper):
    """
    SEND - Receives RSA option as not the last option

    Verify the UUT will treat an NS with RSA option in the middle as unsecured

    @private
    source rfc 3971 5.2.2
    """
    def set_up(self):
        super(UUTReceivesRSAOptionNotLastTestCase, self).set_up()
        nd_ns = ICMPv6ND_NS(tgt=str(self.target(1).link_local_ip()))/ICMPv6NDOptSrcLLAddr(lladdr=self.node(1).iface(0).ll_addr)
        ns_pket = nd_ns/self.cga_opt/ICMPv6NDOptNO(nonce=chr(random.randint(0,255))*6, len=1)/ICMPv6NDOptTS(timestamp=time.time())
        sig = self.sign(self.ipv6_layer/ns_pket, ICMPv6ND_NS)[ICMPv6NDOptRSA]
        # Insert signature in middle
        self.packet_to_send = self.ipv6_layer/ns_pket/sig/self.cga_opt/ICMPv6NDOptNO(nonce=chr(random.randint(0,255))*6, len=1)/ICMPv6NDOptTS(timestamp=time.time())

