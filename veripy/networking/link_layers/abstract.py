

class LinkLayer(object):

    frame = None
    
    max_mtu = None
    min_mtu = None
    mtu = None
    
    __link_layers = {}
    
    @classmethod
    def get(self, name):
#        try:
	return self.__link_layers[name]()
#	except KeyError, e:
#		raise UndefinedLinkLayerError(e.message)

    @classmethod
    def register(self, link_layer):
        self.__link_layers[link_layer().name()] = link_layer
    
    def name(self):
        raise Exception('Name should be implemented by a LinkLayer.')

    def validate(self, pos, argument):
        return getattr(self, self.expected_arguments[pos]['validator'])(argument)
