import unittest
from veripy.exceptions import *
from veripy.models import ComplianceTestCase, ComplianceTestSuite


class ComplianceTestSuiteTestCase(unittest.TestCase):

    def setUp(self):
        ComplianceTestSuite.clear()
        

    class MyTestSuite(ComplianceTestSuite):
        """
        Example Test Suite

        This test suite has a title, a description and some private
        comments.

        @private
        This is implemented badly!
        """

        class TestCase1(ComplianceTestCase):
            pass

        class TestCase2(ComplianceTestCase):
            pass

    class AnotherTestSuite(ComplianceTestSuite):
        """
        Test Suite - With no Description
        """

        class TestCase1(ComplianceTestCase):
            pass

        class TestCase2(ComplianceTestCase):
            pass

        class RandomOtherClass(object):
            pass

    class AnotherTestSuiteWithHelper(ComplianceTestSuite):

        class SuiteHelper(ComplianceTestCase):
            pass

        class TestCase1(SuiteHelper):
            pass

        class TestCase2(SuiteHelper):
            pass

    class BlankTestSuite1(ComplianceTestSuite):
        """
        """
        pass

    class BlankTestSuite2(ComplianceTestSuite):
        pass
    

    def test_it_should_extract_the_title_from_the_pydoc_comment(self):
        self.assertEqual("Example Test Suite", ComplianceTestSuiteTestCase.MyTestSuite.title())

    def test_it_should_extract_the_description_from_the_pydoc_comment(self):
        self.assertEqual("This test suite has a title, a description and some private comments.", ComplianceTestSuiteTestCase.MyTestSuite.description())

    def test_it_should_extract_the_title_if_a_description_is_missing(self):
        self.assertEqual("Test Suite - With no Description", ComplianceTestSuiteTestCase.AnotherTestSuite.title())

    def test_it_should_extract_a_blank_description_if_it_is_missing(self):
        self.assertEqual("", ComplianceTestSuiteTestCase.AnotherTestSuite.description())

    def test_it_should_default_the_title_if_the_pydoc_is_blank(self):
        self.assertEqual("BlankTestSuite1", ComplianceTestSuiteTestCase.BlankTestSuite1.title())

    def test_it_should_return_a_blank_description_if_the_pydoc_is_blank(self):
        self.assertEqual("", ComplianceTestSuiteTestCase.BlankTestSuite1.description())

    def test_it_should_default_the_title_if_the_pydoc_is_missing(self):
        self.assertEqual("BlankTestSuite2", ComplianceTestSuiteTestCase.BlankTestSuite2.title())

    def test_it_should_return_a_blank_description_if_the_pydoc_is_missing(self):
        self.assertEqual("", ComplianceTestSuiteTestCase.BlankTestSuite2.description())

    def test_it_should_return_a_list_of_enclosed_test_cases(self):
        c = ComplianceTestSuiteTestCase.MyTestSuite.test_cases()

        self.assertEqual(2, len(c))
        self.assertEqual("TestCase1", c[0].title())
        self.assertEqual("TestCase2", c[1].title())

    def test_it_should_not_return_non_test_cases_as_test_cases(self):
        c = ComplianceTestSuiteTestCase.AnotherTestSuite.test_cases()

        self.assertEqual(2, len(c))
        self.assertEqual("TestCase1", c[0].title())
        self.assertEqual("TestCase2", c[1].title())

    def test_it_should_not_return_helpers_as_test_cases(self):
        c = ComplianceTestSuiteTestCase.AnotherTestSuiteWithHelper.test_cases()

        self.assertEqual(2, len(c))
        self.assertEqual("TestCase1", c[0].title())
        self.assertEqual("TestCase2", c[1].title())

    def test_it_should_iterate_through_enclosed_test_cases(self):
        s = ComplianceTestSuiteTestCase.MyTestSuite()
        c = []

        for case in s:
            c.append(case)

        self.assertEqual(2, len(c))
        self.assertEqual("TestCase1", c[0].title())
        self.assertEqual("TestCase2", c[1].title())

    def test_it_should_register_a_test_suite(self):
        ComplianceTestSuite.register('my-test-suite', ComplianceTestSuiteTestCase.MyTestSuite)

        self.assertEqual(1, len(ComplianceTestSuite.all()))
        self.assertEqual('my-test-suite', ComplianceTestSuite.all()[0])

    def test_it_should_not_register_an_invalid_test_suite(self):
        try:
            ComplianceTestSuite.register('my-test-suite', 'a')

            self.fail("allowed an invalid ComplianceTestSuite to be registered")
        except InvalidComplianceTestSuiteError, e:
            self.assertEqual('a', e.test_suite)

    def test_it_should_not_register_two_test_suites_with_the_same_identifier(self):
        ComplianceTestSuite.register('my-test-suite', ComplianceTestSuiteTestCase.MyTestSuite)

        try:
            ComplianceTestSuite.register('my-test-suite', ComplianceTestSuiteTestCase.AnotherTestSuite)

            self.fail("allowed two ComplianceTestSuites to be registered with the same id")
        except DuplicateComplianceTestSuiteIdentifier, e:
            self.assertEqual('my-test-suite', e.identifier)

    def test_it_should_not_register_the_same_test_suite_with_two_identifiers(self):
        ComplianceTestSuite.register('my-test-suite', ComplianceTestSuiteTestCase.MyTestSuite)

        try:
            ComplianceTestSuite.register('another-test-suite', ComplianceTestSuiteTestCase.MyTestSuite)

            self.fail("allowed two identifiers to be assigned to a ComplianceTestSuite")
        except DuplicateComplianceTestSuite, e:
            self.assertEqual(ComplianceTestSuiteTestCase.MyTestSuite, e.test_suite)

    def test_it_should_get_a_test_suite(self):
        ComplianceTestSuite.register('my-test-suite', ComplianceTestSuiteTestCase.MyTestSuite)

        self.assertEqual(ComplianceTestSuiteTestCase.MyTestSuite, ComplianceTestSuite.get('my-test-suite'))

    def test_it_should_raise_if_try_to_get_a_non_existent_test_suite(self):
        ComplianceTestSuite.register('my-test-suite', ComplianceTestSuiteTestCase.MyTestSuite)

        try:
            ComplianceTestSuite.get('aaa')

            self.fail("expected an UnknownComplianceTestSuite error")
        except UnknownComplianceTestSuiteError, e:
            self.assertEqual('aaa', e.identifier)
            