import unittest
from veripy.models import ComplianceTestCase, Outcome, Report, Result, TestSuiteResults
from veripy.models.decorators import *


class ReportTestCase(unittest.TestCase):

    def setUp(self):
        self.c1 = must(CompulsaryTestCase)
        self.c2 = should(OptionalTestCase)
        self.c3 = must(OtherTestCase)

    def test_it_should_be_compliant_if_all_test_suites_are_compliant(self):
        r1 = Report("host", "Test Report", "MWR", "Test Case", "N/A")
        
        r1.append(1, self.c1, Outcome(Outcome.Results.PASS))
        r1.append(1, self.c2, Outcome(Outcome.Results.PASS))
        r1.append(2, self.c3, Outcome(Outcome.Results.PASS))

        self.assertTrue(r1.is_compliant())

    def test_it_should_not_be_compliant_if_a_test_suite_is_not_compliant(self):
        r1 = Report("host", "Test Report", "MWR", "Test Case", "N/A")

        r1.append(1, self.c1, Outcome(Outcome.Results.FAIL))
        r1.append(1, self.c2, Outcome(Outcome.Results.PASS))
        r1.append(2, self.c3, Outcome(Outcome.Results.PASS))

        self.assertFalse(r1.is_compliant())


class ResultTestCase(unittest.TestCase):

    def setUp(self):
        self.c1 = must(CompulsaryTestCase)
        self.c2 = should(OptionalTestCase)
        

    def test_it_should_be_compliant_if_the_outcome_is_compliant(self):
        r1 = Result(self.c1, Outcome(Outcome.Results.PASS))

        self.assertTrue(r1.is_compliant())

    def test_it_should_not_be_compliant_if_the_outcome_is_non_compliant(self):
        r1 = Result(self.c1, Outcome(Outcome.Results.FAIL))

        self.assertFalse(r1.is_compliant())

    def test_it_should_not_be_compliant_if_the_outcome_is_error(self):
        r1 = Result(self.c1, Outcome(Outcome.Results.ERROR))

        self.assertFalse(r1.is_compliant())

    def test_it_should_not_be_compliant_if_the_outcome_is_unimplemented(self):
        r1 = Result(self.c1, Outcome(Outcome.Results.UNIMPLEMENTED))

        self.assertFalse(r1.is_compliant())


class TestSuiteResultTestCase(unittest.TestCase):

    def setUp(self):
        self.c1 = must(CompulsaryTestCase)
        self.c2 = should(OptionalTestCase)


    def test_it_should_be_compliant_if_all_test_cases_are_compliant(self):
        tr = TestSuiteResults(None)

        tr.append(self.c1, Outcome(Outcome.Results.PASS))
        tr.append(self.c2, Outcome(Outcome.Results.PASS))

        self.assertTrue(tr.is_compliant())

    def test_it_should_not_be_compliant_if_a_test_case_is_not_compliant(self):
        tr = TestSuiteResults(None)

        tr.append(self.c1, Outcome(Outcome.Results.FAIL))
        tr.append(self.c2, Outcome(Outcome.Results.PASS))

        self.assertFalse(tr.is_compliant())

    def test_it_should_be_compliant_if_a_non_compliant_test_case_is_optional(self):
        tr = TestSuiteResults(None)

        tr.append(self.c1, Outcome(Outcome.Results.PASS))
        tr.append(self.c2, Outcome(Outcome.Results.FAIL))

        self.assertTrue(tr.is_compliant())

###

class CompulsaryTestCase(ComplianceTestCase): pass
class OptionalTestCase(ComplianceTestCase): pass
class OtherTestCase(ComplianceTestCase): pass
