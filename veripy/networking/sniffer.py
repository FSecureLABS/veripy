from scapy.all import PacketList, sniff
from threading import Thread
from time import sleep, time


class Sniffer(Thread):
    """
    Sniffer provides a general-purpose packet sniffer, that binds to a
    particular network interface and captures all traffic that passes through
    it.
    
    A sniffer is asynchronous from the application that invokes it, and can
    be controlled through a simple interface:
    
    Example:
    
      s = Sniffer('eth0')
      s.start()
      sleep(10)
      s.flush()
      s.stop()
      
      print "Caught %d packets." % (len(s.pcap()))
    
    The intercepted packets are available through the #pcap() method, or by
    subscribing to the on_receive callback, which will push packets as they
    are received.
    """

    class State:
        Initialising, Running, Stopped, Paused = range(4)
    
    def __init__(self, interface, timeout=5):
        """

        Expected Attributes:
             interface  specifies the physical interface to which the
                        sniffer should be bound

        Optional Attributes:
               timeout  specifies the amount of time for which packets
                        are captured before the main event loop is
                        allowed to execute
        """
        self.__defunct = False
        self.__interface = interface
        self.__pcap = []
        self.__reset = False
        self.__sniffing = False
        self.__state = Sniffer.State.Initialising
        self.__timeout = timeout

        Thread.__init__(self)
        self.__feedback = Feedback(self)

        self.__ctr = 0
        self.__flush_ctr = -1

    def flush(self):
        """
        
        Returns:    True, if the sniffer was flushed, or False if it
                    is not running.
        """
        if self.__state != Sniffer.State.Running:
            return False

        ctr = self.__ctr
        while(self.__ctr == ctr): sleep(0.5)

        return True
    
    def flush_asynchronously(self):
        """
        
        Returns:    True, if flushing has started, or False if it is
                    already in progress.
        """
        if self.__flush_ctr == -1:
            self.__flush_ctr = self.__ctr
            
            return True
        else:
            return False
    
    def flushing(self):
        """
        
        Returns:    True, if the sniffer is being flushed asynchronously,
                    or False.
        """
        if self.__flush_ctr != self.__ctr:
            self.__flush_ctr = -1
            
            return False
        else:
            return True

    def interface(self):
        return self.__interface

    def is_defunct(self):
        return self.__defunct
    
    def pause(self):
        """
        Signal to the thread that it should pause but not stop.
        """
        if self.__state == Sniffer.State.Running:
            self.__state = Sniffer.State.Paused

            while not self.paused(): pass

    def paused(self):
        """
        Returns:    True, if the Sniffer is in the Paused state.
        """
        return self.__state == Sniffer.State.Paused and self.__sniffing == False
    
    def pcap(self):
        """
        Get the sniffed network packets.
        
        Returns:    PacketList containing timestamped packets in the order
                    they were received.
        """
        return self.__pcap[:]
    
    def reset(self):
        """
        Reset the log of packets collected so far.
        """
        if self.sniffing():
            self.__reset = True

            self.flush()
        else:
            self.__pcap = []
    
    def resume(self):
        """
        Signal to the thread that it should resume running.
        """
        if self.__state == Sniffer.State.Paused:
            self.__state = Sniffer.State.Running

            while not self.sniffing(): pass

    def run(self):
        """
        *** WARNING ***     This is used by Python's multithreading as
	                    the main event loop during operation. It is
	                    unlikely that this method should be called
	                    directly.

        Performs the actual sniffing, whilst the sniffer is running. In each
        iteration, the sniffer checks its state and (if applicable)
        invokes the scapy #sniff() method to capture packets.

        If the sniffer is paused, it enters a spin lock, waiting on it to be
        resumed.
        """
        self.__state = Sniffer.State.Running

        while self.__state != Sniffer.State.Stopped:
            try:
                self.__sniffing = False
                if self.__state != Sniffer.State.Paused:
                    self.__sniffing = True

                    s = self.sniff(iface=self.__interface.interface(), timeout=self.__timeout)
                    
                    if self.__reset:
                        self.__pcap = []
                        self.__reset = False
            except Exception, e:
                print e
                print "Unable to sniff on interface %s, pausing sniffer." % self.__interface
                self.pause()

            self.__ctr += 1

    def sniff(self, iface, timeout):
        return sniff(iface=iface, prn=lambda p: self.__pcap.extend(p), timeout=timeout)

    def sniffing(self):
        """
        Returns:    True, if the Sniffer is in the Running state and actively
                    sniffing.
        """
        return self.__state == Sniffer.State.Running and self.__sniffing == True

    def start(self):
        super(Sniffer, self).start()
        
        self.__feedback.start()
        
    def state(self):
        return self.__state

    def stop(self):
        """
        Signal to the thread that it should stop, and tell it to join
        back with the main thread.

        It is not possible to stop() a sniffer before it has started
        running, else there would be a race condition the simple construct:

          s = Sniffer('eth0')
          s.stop()

        Which could cause the sniffer to run indefinately.
        """
        while self.__state == Sniffer.State.Initialising: pass

        self.__state = Sniffer.State.Stopped
        self.__feedback.stop()

        self.join()
        
        self.__defunct = True
    
    def stop_flushing_asynchronously(self):
        self.__flush_ctr = -1


class Feedback(Thread):

    def __init__(self, sniffer):
        Thread.__init__(self)

        self.__ctr = 0
        self.__sniffer = sniffer
        
    def run(self):
        while self.__sniffer.state() != Sniffer.State.Stopped:
            # grab a recent copy of the pcap data
            pcap = self.__sniffer.pcap()
            
            # send any new packets back through the tap, by asking the
            # attached Interface to accept them
            for p in pcap[self.__ctr:]:
                self.__sniffer.interface().accept(p)

                # update the counter, so we know the last index at which packets
                # were retrieved
                self.__ctr += 1

    def stop(self):
        self.join()
    