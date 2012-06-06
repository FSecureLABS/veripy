
class Interface(object):
    pass


class Callbacks(object):

    def __init__(self, interface):
        self.__interface = interface
        self.__truth_store = {}

    def ask(self, prompt, truth_store=False):
        if truth_store and prompt in self.__truth_store:
            return self.__truth_store[prompt]

        while True:
            i = self.read(prompt + " [yn] ").lower()

            if i == "y":
                if truth_store: self.__truth_store[prompt] = True
                return True
            elif i == "n":
                if truth_store: self.__truth_store[prompt] = False
                return False

    def read_with_truth_store(self, prompt=None):
        if prompt in self.__truth_store:
            return self.__truth_store[prompt]

        self.__truth_store[prompt] = self.read(prompt)

        return self.__truth_store[prompt]

    def clear_truth_store(self):
        self.__truth_store = {}    
