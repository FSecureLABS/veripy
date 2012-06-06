from scapy.all import PacketList
from veripy.models import IPAddressCollection


class MockInterface(object):
    
    def __init__(self, interface, ll_addr):
        self.__interface = interface
        self.__ll_addr = ll_addr
        self.__on_receive_callbacks = []

        self.sent = []
        self.sniffer = MockSniffer(self)

    def accept(self, frames):
        for frame in frames:
            for callback in self.__on_receive_callbacks:
                callback(frame)

    def interface(self):
        return self.__interface

    def on_receive(self, callback):
        self.__on_receive_callbacks.append(callback)

    def ll_addr(self):
        return self.__ll_addr
    
    def pcap(self):
        return self.sniffer.pcap()

    def send(self, frame, timeout=1):
        self.sent.append(frame)

    def srp(self, frame, timeout):
        pass

    def flush_sniffer(self):
        pass

    def flush_sniffer_asynchronously(self):
        pass

    def flushing_sniffer(self):
        pass

    def resume_sniffing(self):
        pass

    def pause_sniffing(self):
        pass

    def paused_sniffing(self):
        pass

    def reset_sniffing(self):
        pass

    def sniffing(self):
        pass

    def stop_flushing_sniffer_asynchronously(self):
        pass

    def stop_sniffing(self):
        pass


class MockSniffer(object):
    
    class State:
        Initialising, Running, Stopped, Paused = range(4)

    def __init__(self, interface, timeout=1):
        self.__interface = interface
        self.__pcap = []
        self.__state = MockSniffer.State.Initialising
        self.__timeout = timeout

        self._flush = False
        self._flush_asynchronously = False
        self._flushing = False

    def flush(self):
        self._flush = True

    def flush_asynchronously(self):
        self._flush_asynchronously = True

    def flushing(self):
        self._flushing = True

        return False

    def pause(self):
        pass

    def paused(self):
	pass

    def pcap(self):
        combined_pcap = PacketList()

        for pcap in self.__pcap:
            for packet in pcap:
                combined_pcap.append(packet)

        return combined_pcap

    def reset(self):
	pass

    def resume(self):
        pass

    def sniffing(self):
	return True

    def stop(self):
	pass

    def stop_flushing_asynchronously(self):
        pass
