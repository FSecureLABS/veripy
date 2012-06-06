from scapy import sendrecv
from scapy.layers import inet, inet6
from scapy.plist import PacketList
from veripy.networking.arch import OSInterfaceAdapter
from veripy.networking.sniffer import Sniffer


class Base(object):
    """
    network.interfaces.Base is the root of the network interfaces
    architecture, and used to share common functionality across various link
    layers and OS-specific implementations.
    
    Network Interfaces are singleton, and should be retrieved through the
    Base#get_instance() class method, specifying the physical interface to
    bind to.
    
    OS-specific Concerns
    --------------------
    Each specific interface is further extended by a small piece of OS-
    specific functionality that deines how it interfaces with the physical
    port.
    """
    
    __instances = {}
    
    @classmethod
    def get_instance(cls, interface, ll_addr):
        """
        Get a Base network interface for the specified physical interface,
        maintaining a singleton of each.
        
        Expected Attributes:
         interface  the physical interface on which to send/receive
                    packets
        """

        if interface in cls.__instances.keys():
            return cls.__instances[interface]
        else:
            i = cls(interface, ll_addr)
            cls.__instances[interface] = i
            return i
    
    @classmethod
    def get_physical_interfaces(cls):
        return OSInterfaceAdapter.get_physical_interfaces()
    
    def __init__(self, interface, ll_addr):
        """
        Prepares a new NetworkInterface, ready to send packets to a
        particular physical interface.
        
        Expected Attributes:
         interface  the physical interface on which to send/receive
                    packets
        """
        self.__interface = interface
        self.__ll_addr = ll_addr
        self.__sniffer = Sniffer(self)

        self.__on_receive_callbacks = []
    
    def accept(self, frame_or_frames):
        frames = not isinstance(frame_or_frames, PacketList) and [frame_or_frames] or frame_or_frames
        
        for frame in frames:
            for callback in self.__on_receive_callbacks:
                callback(frame)

    def interface(self):
        return self.__interface
    
    def ll_addr(self):
        return self.__ll_addr

    def pcap(self):
        return self.__sniffer.pcap()
    
    def on_receive(self, callback):
        self.__on_receive_callbacks.append(callback)

    def send(self, frame, timeout=1):
        """
        Sends Layer 2 frame on the network interface. The optional timeout
        specifies how long to wait for an answer. The packet is sent on
        the wire as-is, with no modification by veripy or in the OS.

        If an answer to the packet is detected, send() will return True,
        the answer will be available through the pcap() data.

        Expected Attributes:
             frame  a Layer 2 frame to send on the network interface

        Optional Attributes:
           timeout  the amount of time to wait for the packet to be
                    answered before declaring it as unanswered,
                    in seconds

        Returns:    True if the packet was answered, or False
        """
        # send out the layer 2 frame on the network interface, collecting
        # answered and unanswered packets
        answered, unanswered = self.srp(frame, timeout)
        # return True, if the packet was answered
        return len(answered) > 0
    
    def srp(self, frame, timeout=1):
        """
        *** WARNING ***   This method exists primarily to assist unit
                          testing of the IIERCT framework. Under
                          normal operation the send() method should be
                          invoked, rather than directly calling srp().
        
        Wraps the srp() command from scapy.sendrecv, adding arguments to
        specify the interface to use, and any filters to be applied when
        packets are received.
        
        Expected Attributes:
             frame  a Layer 2 frame to send on the network interface
        
        Optional Attributes:
           timeout  the amount of time to wait for the frame to be
                    answered before declaring it as unanswered,
                    in seconds
        
        Returns:    [PacketList, PacketList], the answered and unanswered
                    packets
        """
        return sendrecv.srp(frame, iface=self.__interface, timeout=timeout, verbose=0)
    
    def flush_sniffer(self):
        return self.__sniffer.flush()
    
    def flush_sniffer_asynchronously(self):
        return self.__sniffer.flush_asynchronously()
    
    def flushing_sniffer(self):
        return self.__sniffer.flushing()
    
    def resume_sniffing(self):
        """
        Tell the sniffer associated with this NetworkInterface to resume sniffing for network traffic on
        the NetworkInterface's physical interface.
        """
        if self.__sniffer.is_defunct():
            self.__sniffer = Sniffer(self)
            
        if not self.__sniffer.isAlive():
            self.__sniffer.start()
        else:
            self.__sniffer.resume()

    def pause_sniffing(self):
        """
        Tell the sniffer associated with this NetworkInterface to stop sniffing for network traffic on
        the NetworkInterface's physical interface.
        """
        self.__sniffer.pause()
    
    def paused(self):
        """
        Determine whether or not teh sniffer is paused for the Network Interface.
        """
        return self.__sniffer.paused()
    
    def reset_sniffing(self):
        """
        Tell the sniffer associated with this NetworkInterface to empty its log of packets that it has
        sniffed so far.
        """
        self.__sniffer.reset()
    
    def sniffing(self):
        """
        Determine whether or not the sniffer is active for the Network Interface.
        """
        return self.__sniffer.sniffing()
    
    def stop_flushing_sniffer_asynchronously(self):
        """
        Forceably stop the asynchronous flushing of a sniffer. This helps to prevent a bug
        where multiple subnets share the same physical NetworkInterface.
        """
        return self.__sniffer.stop_flushing_asynchronously()
    
    def stop_sniffing(self):
        """
        Tell the sniffer associated with this NetworkInterface to stop sniffing altogether.
        """
        self.__sniffer.stop()

    def __str__(self):
        return self.__interface

    def sniff(self, **keywords):
        return sendrecv.sniff(iface=self.__interface, **keywords)
    