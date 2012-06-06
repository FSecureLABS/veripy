from os import makedirs, path
from shutil import copyfile
from veripy.exceptions import *


class Base(object):

    __formatters = {}

    def __init__(self, report, ui=None):
        self.report = report
        self.ui = ui

    @classmethod
    def all(cls):
        return cls.__formatters.keys()

    @classmethod
    def clear(cls):
        cls.__formatters = {}

    @classmethod
    def get(cls, id):
        if id in cls.__formatters:
            return cls.__formatters[id]
        else:
            raise UndefinedFormatterError(id)

    @classmethod
    def register(cls, id, klass):
        if not id in cls.__formatters:
            cls.__formatters[id] = klass
        else:
            raise DuplicateFormatterError(id)

    def copy_file(self, source, destination):
        copyfile(source, destination)

    def create_directory(self, directory):
        if not path.exists(directory):
            makedirs(directory)

    def format(self, path):
        raise InvalidFormatterError("'format' must be defined by a concrete formatter")

    def type(self):
        raise InvalidFormatterError("'format' must be defined by a concrete formatter")

    def write_file(self, path, data):
        try:
            f = open(path, 'w')
            f.write(data)
            f.close()

            if self.ui != None:
                ui.tell("Written " + path + ".")
        except IOError, e:
            if self.ui != None:
                if ui.ask("Could not save output to " + path + ". Would you like to specify a different path?"):
                    self.write_file(self.ui.read(), data)
                else:
                    self.ui.tell("Skipping " + path + ".")
            else:
                raise e
