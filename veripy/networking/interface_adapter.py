
class InterfaceAdapter(object):

	@classmethod
	def get_physical_interfaces(cls):
		raise Exception("get_physical_interfaces: must be implemented by an OS-specific adapter")
