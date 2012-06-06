from os import listdir, path
from sys import modules

__all__ = []

ContribBase = path.dirname(__file__)

for f in listdir(path.abspath(ContribBase)):
    if path.isdir(path.join(ContribBase, f)):
        setattr(modules[__name__], f, __import__(f, globals(), locals(), ['*'], -1))
        
        __all__.append(f)
