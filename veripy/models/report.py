from veripy.models import Outcome


class NetworkDump(object):
    pass


class Report(object):

    def __init__(self, klass, title, vendor, device, notes):
        self.klass = klass
        self.title = title
        self.vendor = vendor
        self.device = device
        self.notes = notes
        
        self.reset()

    def append(self, suite, case, outcome):
        if len(self.__results) == 0 or self.__results[-1].test_suite != suite:
            self.__results.append(TestSuiteResults(suite))

        self.__results[-1].append(case, outcome)
    
    def is_compliant(self):
        return all(s.is_compliant() for s in self.__results)
    
    def reset(self):
        self.__results = []
    
    def results(self):
        return self.__results[:]
    
    def results_for_test_suite(self, test_suite):
        """
        Returns the results for a particular test suite
        """
        try:
            return self.__results[test_suite.title].results()
        except KeyError:
            return []
    
    def __str__(self):
        return "<iierct.models.Report \"" + self.title + "\">"


class Result(object):

    def __init__(self, case, outcome):
        self.test_case = case
        self.outcome = outcome

    def is_compliant(self):
        return self.outcome.result == Outcome.Results.PASS
        

class TestSuiteResults(object):

    def __init__(self, test_suite):
        self.test_suite = test_suite
        self.__results = []

    def append(self, case, outcome):
        self.__results.append(Result(case, outcome))

    def is_compliant(self):
        return all(c.is_compliant() or c.test_case.is_optional() for c in self.__results)

    def results(self):
        return self.__results[:]
