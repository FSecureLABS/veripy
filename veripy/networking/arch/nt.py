
from sys import platform
if (not platform.startswith("win32")): raise(Exception("Interface not supported by OS."))

from veripy.networking.interface_adapter import InterfaceAdapter
from scapy.arch.windows import get_if_list

class NtInterfaceAdapter(InterfaceAdapter):
	"""
	A NetworkInterface is an class used to implement OS-specific network interface functionality required to communicate with a node.
	"""


	@classmethod
	def get_physical_interfaces(cls):
		"""
		Used to retrieve a list of physical network interfaces, such as eth0, wlan1 etc.
		Note that the NT version of this does not select only active physical interfaces,
		since the pypcap library on Windows does not expose the necessary API to be able to
		tell if any interface other than the default interface is active.

		Returns:        an array of strings such as 'eth0', 'wlan0'
		"""
		return get_if_list()
