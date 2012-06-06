from veripy.interfaces.abstract import Callbacks


class MockCallbacks(Callbacks):

    def __init__(self, interface):
        super(self.__class__, self).__init__(interface)

        self.inputs = []
        self.outputs = []

        self.test_network = None

    def read(self, prompt=None):
        if len(self.inputs) == 0:
            raise Exception('Expected another input to be available.')

        self.outputs.append(prompt)
        self.inputs.reverse()
        v = self.inputs.pop()
        self.inputs.reverse()

        return v

    def tell(self, message):
        self.outputs.append(message)

    def wait(self, seconds):
        if self.test_network != None:
            for tap in self.test_network.taps():
                if hasattr(tap.target_iface, "next_delivery"):
                    for p in tap.target_iface.next_delivery(seconds):
                        tap._MockTap__receiving = True
                        tap.receive(p)
                        tap._MockTap__receiving = False

    def write(self, prompt):
        self.outputs.append(prompt)


class MockInterface(object):

    def callbacks(self):
        return MockCallbacks(self)
