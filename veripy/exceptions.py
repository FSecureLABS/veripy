
class VeripyError(Exception):
    pass

# Configuration errors
class InvalidConfigurationError(VeripyError):
    pass

# Formatter errors
class DuplicateFormatterError(VeripyError):

    def __init__(self, identifier):
        self.identifier = identifier

class InvalidFormatterError(VeripyError): pass

class UndefinedFormatterError(VeripyError):

    def __init__(self, identifier):
        self.identifier = identifier

# TestSuite errors
class TestSuiteError(VeripyError):

    def __init__(self, test_suite):
        self.test_suite = test_suite

class TestSuiteIdentifierError(VeripyError):

    def __init__(self, identifier):
        self.identifier = identifier

class DuplicateComplianceTestSuite(TestSuiteError):

    def __str__(self):
        return "%s is already registered under a different handle" % self.test_suite

class DuplicateComplianceTestSuiteIdentifier(TestSuiteIdentifierError):

    def __str__(self):
        return "the handle for '%s' is already assigned to another ComplianceTestSuite" % self.test_suite

class InvalidComplianceTestSuiteError(TestSuiteError):

    def __str__(self):
        return "%s is not a valid veripy ComplianceTestSuite" % self.test_suite

class UnknownComplianceTestSuiteError(TestSuiteIdentifierError):

    def __str__(self):
        return "no known test suite for %s" % self.identifier
    