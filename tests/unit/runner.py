import unittest
from tests.mocks.cli import MockInterface
from tests.mocks.configuration import sampleOptions, MockConfiguration
from veripy import Runner
from veripy.models import ComplianceTestCase, ComplianceTestSuite, Report, TestNetwork


class RunnerTestCase(unittest.TestCase):

    class TestSuiteA(ComplianceTestSuite):
        class TestCase1(ComplianceTestCase): pass
        class TestCase2(ComplianceTestCase): pass
        class TestCase3(ComplianceTestCase): pass

    class TestSuiteB(ComplianceTestSuite):
        class TestCase1(ComplianceTestCase): pass
        class TestCase2(ComplianceTestCase): pass
        

    def test_it_should_initialise_from_a_configuration(self):
        options, args = sampleOptions("--configuration tests/mocks/veripy.cfg host")

        c = MockConfiguration(args, options, MockInterface())
        c.mock_test_plan = [RunnerTestCase.TestSuiteA, RunnerTestCase.TestSuiteB]

        r = c.build_runner()

        self.assertTrue(isinstance(r.report, Report))
        self.assertEqual(2, len(r.test_plan))
        self.assertTrue(isinstance(r.test_network, TestNetwork))

    def test_it_should_count_the_test_cases_to_be_run(self):
        options, args = sampleOptions("--configuration tests/mocks/veripy.cfg host")
        
        c = MockConfiguration(args, options, MockInterface())
        c.mock_test_plan = [RunnerTestCase.TestSuiteA, RunnerTestCase.TestSuiteB]

        r = c.build_runner()

        self.assertEqual(5, len(r.test_cases()))

    def test_it_should_run_the_test_cases_in_the_order_provided(self):
        options, args = sampleOptions("--configuration tests/mocks/veripy.cfg host")

        c = MockConfiguration(args, options, MockInterface())
        c.mock_test_plan = [RunnerTestCase.TestSuiteA, RunnerTestCase.TestSuiteB]

        r = c.build_runner()

        self.assertEqual(RunnerTestCase.TestSuiteA.TestCase1, r.test_cases()[0])
        self.assertEqual(RunnerTestCase.TestSuiteA.TestCase2, r.test_cases()[1])
        self.assertEqual(RunnerTestCase.TestSuiteA.TestCase3, r.test_cases()[2])
        self.assertEqual(RunnerTestCase.TestSuiteB.TestCase1, r.test_cases()[3])
        self.assertEqual(RunnerTestCase.TestSuiteB.TestCase2, r.test_cases()[4])

    def test_it_should_step_through_the_test_cases_in_order(self):
        options, args = sampleOptions("--configuration tests/mocks/veripy.cfg host")

        c = MockConfiguration(args, options, MockInterface())
        c.mock_test_plan = [RunnerTestCase.TestSuiteA, RunnerTestCase.TestSuiteB]

        r = c.build_runner()
        s = [   [None, None],
                [RunnerTestCase.TestSuiteA, RunnerTestCase.TestSuiteA.TestCase1],
                [RunnerTestCase.TestSuiteA, RunnerTestCase.TestSuiteA.TestCase2],
                [RunnerTestCase.TestSuiteA, RunnerTestCase.TestSuiteA.TestCase3],
                [RunnerTestCase.TestSuiteB, RunnerTestCase.TestSuiteB.TestCase1],
                [RunnerTestCase.TestSuiteB, RunnerTestCase.TestSuiteB.TestCase2] ]

        for step in s:
            self.assertEqual(step[0], r.current_test_suite())
            self.assertEqual(step[1], r.current_test_case())

            print "+ next_case()"
            r.next_case()

    def test_it_should_not_run_test_cases_that_do_not_match_the_case_rx(self):
        options, args = sampleOptions("--configuration tests/mocks/veripy.cfg --case TestCase1 host")

        c = MockConfiguration(args, options, MockInterface())
        c.mock_test_plan = [RunnerTestCase.TestSuiteA, RunnerTestCase.TestSuiteB]

        r = c.build_runner()

        r.next_case()
        self.assertEqual(RunnerTestCase.TestSuiteA.TestCase1, r.current_test_case())

        r.next_case()
        self.assertEqual(RunnerTestCase.TestSuiteB.TestCase1, r.current_test_case())
        