
class AssertionCounter(object):

    __ctr = 0

    @classmethod
    def incr(cls):
        cls.__ctr += 1

    @classmethod
    def reset(cls):
        cls.__ctr = 0

    @classmethod
    def value(cls):
        return cls.__ctr

    
class AssertionFailedError(Exception):
    pass
    