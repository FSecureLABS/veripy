import logging
import unittest
from tests.mocks.test_network import MockInterface, MockTap, MockTargetInterface, TestNetworkConfiguration
from veripy.assertions import *
from veripy.models import ComplianceTestCase, Outcome, TestNetwork
from veripy.models.decorators import must, should


class ComplianceTestCaseTestCase(unittest.TestCase):

    def setUp(self):
        self.test_network = TestNetwork(TestNetworkConfiguration())

        self.test_network._TestNetwork__taps[0].unbind()

        self.t1 = self.test_network._TestNetwork__taps[0] = MockTap(self.test_network.link(2),
                                                                MockInterface('if0', 'be:ef:ca:fe:09:01'),
                                                                MockTargetInterface(ips=["2001:800:88:200::50", "fe80::50"], ll_protocol='Ethernet', link_addr='be:ef:ba:be:09:01'))
        self.t2 = self.test_network._TestNetwork__taps[1] = MockTap(self.test_network.link(3),
                                                                MockInterface('if1', 'be:ef:ca:fe:09:02'),
                                                                MockTargetInterface(ips=["2001:900:88:200::50", "fe80::51"], ll_protocol='Ethernet', link_addr='be:ef:ba:be:09:02'))

    class MyTestCase(ComplianceTestCase):
        """
        Example Test Case

        This test case has a title, a description and some private
        comments.

        @private
        This is implemented badly!
        """
        pass

    class AnotherTestCase(ComplianceTestCase):
        """
        Test Case - With no Description
        """
        pass

    class BlankTestCase1(ComplianceTestCase):
        """
        """
        pass

    class BlankTestCase2(ComplianceTestCase):
        pass

    @should
    class OptionalTestCase(ComplianceTestCase):
        pass

    @must
    class MandatoryTestCase(ComplianceTestCase):
        pass

    class InstrumentedTestCase(ComplianceTestCase):

        def __init__(self, test_network, ui):
            super(ComplianceTestCaseTestCase.InstrumentedTestCase, self).__init__(test_network, ui)
            
            self.sequence = []

        def run(self):
            self.sequence.append("run")

        def set_up(self):
            self.sequence.append("set_up")

        def tear_down(self):
            self.sequence.append("tear_down")
    

    def test_it_should_extract_the_title_from_the_pydoc_comment(self):
        self.assertEqual("Example Test Case", ComplianceTestCaseTestCase.MyTestCase.title())

    def test_it_should_extract_the_description_from_the_pydoc_comment(self):
        self.assertEqual("This test case has a title, a description and some private comments.", ComplianceTestCaseTestCase.MyTestCase.description())

    def test_it_should_extract_the_title_if_a_description_is_missing(self):
        self.assertEqual("Test Case - With no Description", ComplianceTestCaseTestCase.AnotherTestCase.title())

    def test_it_should_extract_a_blank_description_if_it_is_missing(self):
        self.assertEqual("", ComplianceTestCaseTestCase.AnotherTestCase.description())

    def test_it_should_default_the_title_if_the_pydoc_is_blank(self):
        self.assertEqual("BlankTestCase1", ComplianceTestCaseTestCase.BlankTestCase1.title())

    def test_it_should_return_a_blank_description_if_the_pydoc_is_blank(self):
        self.assertEqual("", ComplianceTestCaseTestCase.BlankTestCase1.description())

    def test_it_should_default_the_title_if_the_pydoc_is_missing(self):
        self.assertEqual("BlankTestCase2", ComplianceTestCaseTestCase.BlankTestCase2.title())

    def test_it_should_return_a_blank_description_if_the_pydoc_is_missing(self):
        self.assertEqual("", ComplianceTestCaseTestCase.BlankTestCase2.description())

    def test_it_should_not_be_optional_by_default(self):
        self.assertFalse(ComplianceTestCaseTestCase.MyTestCase.is_optional())

    def test_it_should_use_a_decorator_to_indicate_an_optional_case(self):
        self.assertTrue(ComplianceTestCaseTestCase.OptionalTestCase.is_optional())

    def test_it_should_use_a_decoration_to_reinforce_a_mandatory_case(self):
        self.assertFalse(ComplianceTestCaseTestCase.MandatoryTestCase.is_optional())

    def test_it_should_make_a_logger_available(self):
        c = ComplianceTestCaseTestCase.MyTestCase(self.test_network, None)

        self.assertTrue(hasattr(c, 'logger'))
        self.assertTrue(isinstance(c.logger, logging.Logger))

    def test_it_should_use_a_per_case_logger(self):
        c = ComplianceTestCaseTestCase.MyTestCase(self.test_network, None)

        self.assertTrue(hasattr(c, 'logger'))
        self.assertEqual(".veripy.compliance_tests.MyTestCaseLogger", c.logger.name)

    def test_it_should_make_the_logger_output_available(self):
        c = ComplianceTestCaseTestCase.MyTestCase(self.test_network, None)

        self.assertEqual("", c.log_file())

        c.logger.info("This is a log message.")

        self.assertTrue(c.log_file() != "")

    def test_it_should_return_a_result_from_run_case(self):
        t = ComplianceTestCaseTestCase.MyTestCase(self.test_network, None)

        o = t.run_case()

        self.assertTrue(isinstance(o, Outcome))

    def test_it_should_return_a_pass_result_if_the_test_case_passed(self):
        class PassingTestCase(ComplianceTestCase):
            def run(self):
                assertTrue(True)

        self.assertEqual(Outcome.Results.PASS, PassingTestCase(self.test_network, None).run_case().result)

    def test_it_should_return_a_fail_result_if_the_test_case_did_not_pass(self):
        class FailingTestCase(ComplianceTestCase):
            def run(self):
                fail("failure message")

        o = FailingTestCase(self.test_network, None).run_case()

        self.assertEqual(Outcome.Results.FAIL, o.result)
        self.assertEqual("failure message", o.message)

    def test_it_should_return_a_error_result_if_the_test_case_caused_an_exception(self):
        class PassingTestCase(ComplianceTestCase):
            def run(self):
                raise Exception("unexpected error")

        o = PassingTestCase(self.test_network, None).run_case()

        self.assertEqual(Outcome.Results.ERROR, o.result)
        self.assertEqual("unexpected error", o.message)

    def test_it_should_return_an_unimplemented_result_if_the_test_case_had_no_body(self):
        class UnimplementedTestCase(ComplianceTestCase):
            pass

        self.assertEqual(Outcome.Results.UNIMPLEMENTED, UnimplementedTestCase(self.test_network, None).run_case().result)

    def test_it_should_return_an_unimplemented_result_if_the_test_case_had_no_assertions(self):
        class UnimplementedTestCase(ComplianceTestCase):
            def run(self):
                pass

        self.assertEqual(Outcome.Results.UNIMPLEMENTED, UnimplementedTestCase(self.test_network, None).run_case().result)

    def test_it_should_execute_the_setup_procedure_before_running_a_test_case(self):
        t = ComplianceTestCaseTestCase.InstrumentedTestCase(self.test_network, None)

        t.run_case()

        self.assertEqual("set_up", t.sequence[0])
        self.assertEqual("run", t.sequence[1])

    def test_it_should_execute_the_teardown_procedure_after_running_a_test_case(self):
        t = ComplianceTestCaseTestCase.InstrumentedTestCase(self.test_network, None)

        t.run_case()

        self.assertEqual("run", t.sequence[1])
        self.assertEqual("tear_down", t.sequence[2])
        