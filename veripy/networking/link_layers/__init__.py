
__all__ = [ 'Ethernet' ]

from veripy.networking.link_layers.abstract import LinkLayer
from veripy.networking.link_layers.ethernet import Ethernet

LinkLayer.register(Ethernet)
