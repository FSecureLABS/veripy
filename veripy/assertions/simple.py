from veripy.assertions.support import AssertionCounter, AssertionFailedError


def assertEqual(expected, actual, message=''):
    AssertionCounter.incr()

    if expected != actual:
        raise AssertionFailedError(message == '' and 'expected ' + str(expected) + ' got ' + str(actual) or message)
    else:
	return True

def assertNotEqual(expected, actual, message=''):
    AssertionCounter.incr()
    
    if expected == actual:
        raise AssertionFailedError(message == '' and 'expected not ' + str(expected) + ' got ' + str(actual) or message)
    else:
        return True

def assertGreaterThan(expected, actual, message=''):
    AssertionCounter.incr()
    
    if expected >= actual:
        raise AssertionFailedError(message == '' and 'expected ' + str(actual) + ' to be greater than ' + str(expected) or message)
    else:
        return True

def assertGreaterThanOrEqualTo(expected, actual, message=''):
    AssertionCounter.incr()

    if expected > actual:
        raise AssertionFailedError(message == '' and 'expected ' + str(actual) + ' to be greater than or equal to ' + str(expected) or message)
    else:
        return True

def assertLessThan(expected, actual, message=''):
    AssertionCounter.incr()
    
    if expected <= actual:
        raise AssertionFailedError(message == '' and 'expected ' + str(actual) + ' to be less than ' + str(expected) or message)
    else:
        return True

def assertLessThanOrEqualTo(expected, actual, message=''):
    AssertionCounter.incr()
    
    if expected < actual:
        raise AssertionFailedError(message == '' and 'expected ' + str(actual) + ' to be less than or equal to ' + str(expected) or message)
    else:
        return True

def assertNone(actual, message=''):
    AssertionCounter.incr()
    
    if not actual == None:
        raise AssertionFailedError(message == '' and 'expected ' + str(actual) + ' to be None' or message)
    else:
        return True

def assertNotNone(actual, message=''):
    AssertionCounter.incr()

    if not actual != None:
        raise AssertionFailedError(message == '' and 'expected ' + str(actual) + ' to not be None' or message)
    else:
        return True

def assertTrue(actual, message=''):
    AssertionCounter.incr()
    
    if actual != True:
        raise AssertionFailedError(message == '' and 'expected ' + str(actual) + ' to be True' or message)
    else:
        return True

def assertFalse(actual, message=''):
    AssertionCounter.incr()

    if actual != False:
        raise AssertionFailedError(message == '' and 'expected ' + str(actual) + ' to be False' or message)
    else:
        return True

def fail(message=''):
    AssertionCounter.incr()

    raise AssertionFailedError(message)
