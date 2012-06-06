
__all__ = [ 'Formatter',
            'CSVFormatter',
            'HTMLFormatter',
            'TextFormatter',
            'XMLFormatter' ]

from abstract import Base as Formatter
from csv import CSVFormatter
from html import HTMLFormatter
from text import TextFormatter
from xml import XMLFormatter

Formatter.register('C', CSVFormatter)
Formatter.register('H', HTMLFormatter)
Formatter.register('T', TextFormatter)
Formatter.register('X', XMLFormatter)
