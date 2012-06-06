
from sys import platform

if platform.startswith('linux'):
	from veripy.networking.arch.nix import NixInterfaceAdapter as OSInterfaceAdapter
elif platform.startswith('win32'):
	from veripy.networking.arch.nt import NtInterfaceAdapter as OSInterfaceAdapter
else:
	raise(Exception("OS not supported."))

__all__ = ['OSInterfaceAdapter']
