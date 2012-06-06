
def must(cls):
    cls.optional = False

    return cls

def should(cls):
    cls.optional = True

    return cls
