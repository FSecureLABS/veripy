
from sys import platform
if (not platform.startswith("linux")): raise(Exception("Interface not supported by OS."))

from veripy.networking.interface_adapter import InterfaceAdapter
from scapy.arch.linux import get_if_list, get_if, SIOCGIFFLAGS, IFF_UP
import struct


class NixInterfaceAdapter(InterfaceAdapter):
	"""
	A NetworkInterface is an class used to implement OS-specific network interface functionality required to communicate with a node.
	"""
	
	@classmethod
	def get_physical_interfaces(cls):
		"""
		Used to retrieve a list of active physical network interfaces, such as eth0, wlan1 etc.

		Returns:        an array of strings such as 'eth0', 'wlan0'
		"""
		interfaces = get_if_list()
		active_interfaces = []
		for i in interfaces:
			if (struct.unpack("16xH14x",get_if(i,SIOCGIFFLAGS))[0] & IFF_UP) and i <> "lo":
				active_interfaces.append(i)
		return active_interfaces
