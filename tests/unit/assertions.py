from scapy.all import *
import unittest
from veripy import assertions


class AssertionsTestCase(unittest.TestCase):

    def test_it_should_assert_equal_for_equal_arguments(self):
        self.assertEqual(True, assertions.assertEqual(1, 1), "did not identify equal arguments")

    def test_it_should_assert_equal_for_non_equal_arguments(self):
        try:
            assertions.assertEqual(2, 1)

            self.fail("did not identify that arguments were not equal")
        except assertions.AssertionFailedError:
            pass

    def test_it_should_use_a_default_message_on_a_failed_equal_assertion(self):
        try:
            assertions.assertEqual(2, 1)

            self.fail("did not identify that arguments were not equal")
        except assertions.AssertionFailedError, e:
            self.assertEqual('expected 2 got 1', e.message)

    def test_it_should_use_a_custom_message_on_a_failed_equal_assertion(self):
        try:
            assertions.assertEqual(2, 1, 'something is wrong')

            self.fail("did not identify that arguments were not equal")
        except assertions.AssertionFailedError, e:
            self.assertEqual('something is wrong', e.message)

    def test_it_should_assert_not_equal_for_non_equal_arguments(self):
        self.assertEqual(True, assertions.assertNotEqual(1, 2), "did not identify non-equal arguments")

    def test_it_should_assert_not_equal_for_equal_arguments(self):
        try:
            assertions.assertNotEqual(1, 1)

            self.fail("did not identify that arguments were equal")
        except assertions.AssertionFailedError:
            pass

    def test_it_should_use_a_default_message_on_a_failed_not_equal_assertion(self):
        try:
            assertions.assertNotEqual(1, 1)

            self.fail("did not identify that arguments were equal")
        except assertions.AssertionFailedError, e:
            self.assertEqual('expected not 1 got 1', e.message)

    def test_it_should_use_a_custom_message_on_a_failed_not_equal_assertion(self):
        try:
            assertions.assertNotEqual(1, 1, 'something is wrong')

            self.fail("did not identify that arguments were equal")
        except assertions.AssertionFailedError, e:
            self.assertEqual('something is wrong', e.message)

    def test_it_should_assert_greater_than_for_valid_arguments(self):
        self.assertEqual(True, assertions.assertGreaterThan(1, 2), "did not identify that 2 > 1")

    def test_it_should_assert_greater_than_for_equal_arguments(self):
        try:
            assertions.assertGreaterThan(1, 1)

            self.fail("did not identify that 2 == 1")
        except assertions.AssertionFailedError, e:
            self.assertEqual('expected 1 to be greater than 1', e.message)

    def test_it_should_assert_greater_than_for_invalid_arguments(self):
        try:
            assertions.assertGreaterThan(2, 1)

            self.fail("did not identify that 2 > 1")
        except assertions.AssertionFailedError, e:
            self.assertEqual('expected 1 to be greater than 2', e.message)

    def test_it_should_assert_less_than_for_valid_arguments(self):
        self.assertEqual(True, assertions.assertLessThan(2, 1), "did not identify that 1 < 2")

    def test_it_should_assert_less_than_for_equal_arguments(self):
        try:
            assertions.assertLessThan(1, 1)

            self.fail("did not identify that 1 == 1")
        except assertions.AssertionFailedError, e:
            self.assertEqual('expected 1 to be less than 1', e.message)

    def test_it_should_assert_less_than_for_invalid_arguments(self):
        try:
            assertions.assertLessThan(1, 2)

            self.fail("did not identify that 2 > 1")
        except assertions.AssertionFailedError, e:
            self.assertEqual('expected 2 to be less than 1', e.message)

    def test_it_should_assert_greater_than_or_equal_to_for_valid_arguments(self):
        self.assertEqual(True, assertions.assertGreaterThan(1, 2), "did not identify that 2 >= 1")

    def test_it_should_assert_greater_than_for_equal_arguments(self):
        self.assertEqual(True, assertions.assertGreaterThanOrEqualTo(1, 1), "did not identify that 1 >= 1")

    def test_it_should_assert_greater_than_or_equal_to_for_invalid_arguments(self):
        try:
            assertions.assertGreaterThanOrEqualTo(2, 1)

            self.fail("did not identify that 2 > 1")
        except assertions.AssertionFailedError, e:
            self.assertEqual('expected 1 to be greater than or equal to 2', e.message)

    def test_it_should_assert_less_than_or_equal_to_for_valid_arguments(self):
        self.assertEqual(True, assertions.assertLessThanOrEqualTo(2, 1), "did not identify that 1 <= 2")

    def test_it_should_assert_less_than_or_equal_to_for_equal_arguments(self):
        self.assertEqual(True, assertions.assertLessThanOrEqualTo(2, 1), "did not identify that 1 <= 2")

    def test_it_should_assert_less_than_or_equal_to_for_invalid_arguments(self):
        try:
            assertions.assertLessThanOrEqualTo(1, 2)

            self.fail("did not identify that 2 > 1")
        except assertions.AssertionFailedError, e:
            self.assertEqual('expected 2 to be less than or equal to 1', e.message)

    def test_it_should_assert_none(self):
        try:
            assertions.assertNone(None)
        except assertions.AssertionFailedError, e:
            self.fail("did not identify that None was None")

    def test_it_should_assert_none_for_invalid_arguments(self):
        try:
            assertions.assertNone(True)

            self.fail("did not identify that True was not None")
        except assertions.AssertionFailedError, e:
            self.assertEqual('True was expected to be None', e.message)

    def test_it_should_assert_not_none(self):
        try:
            assertions.assertNotNone(True)
        except assertions.AssertionFailedError, e:
            self.fail("did not identify that True was not None")

    def test_it_should_assert_not_none_for_invalid_arguments(self):
        try:
            assertions.assertNotNone(None)

            self.fail("did not identify that None was not not None")
        except assertions.AssertionFailedError, e:
            self.assertEqual('None was not expected to be None', e.message)

    def test_it_should_assert_true(self):
        try:
            assertions.assertTrue(True)
        except assertions.AssertionFailedError, e:
            self.fail("did not identify that True was True")

    def test_it_should_assert_true_for_invalid_arguments(self):
        try:
            assertions.assertTrue(False)

            self.fail("did not identify that False was not True")
        except assertions.AssertionFailedError, e:
            self.assertEqual('False was expected to be True', e.message)

    def test_it_should_assert_false(self):
        try:
            assertions.assertFalse(False)
        except assertions.AssertionFailedError, e:
            self.fail("did not identify that False was False")

    def test_it_should_assert_false_for_invalid_arguments(self):
        try:
            assertions.assertFalse(True)

            self.fail("did not identify that True was was False")
        except assertions.AssertionFailedError, e:
            self.assertEqual('True was expected to be False', e.message)

    def test_it_should_assert_failure(self):
        try:
            assertions.fail("this is the message")

            self.fail("did not assert failure")
        except assertions.AssertionFailedError, e:
            self.assertEqual('this is the message', e.message)

    def test_it_should_assert_true_for_valid_arguments(self):
        self.assertEqual(True, assertions.assertTrue(True), 'did not identify that True is True')

    def test_it_should_assert_true_for_invalid_arguments(self):
        try:
            assertions.assertTrue(False)

            self.fail("did not identify that False is not True")
        except assertions.AssertionFailedError, e:
            self.assertEqual('expected False to be True', e.message)

    def test_it_should_assert_false_for_valid_arguments(self):
        self.assertEqual(True, assertions.assertFalse(False), 'did not identify that False is False')

    def test_it_should_assert_false_for_invalid_arguments(self):
        try:
            assertions.assertFalse(True)

            self.fail("did not identify that True is not False")
        except assertions.AssertionFailedError, e:
            self.assertEqual('expected True to be False', e.message)

    def test_it_should_assert_none_for_valid_arguments(self):
        self.assertEqual(True, assertions.assertNone(None), 'did not identify that None is None')

    def test_it_should_assert_none_for_invalid_arguments(self):
        try:
            assertions.assertNone(True)

            self.fail("did not identify that True is not None")
        except assertions.AssertionFailedError, e:
            self.assertEqual('expected True to be None', e.message)

    def test_it_should_assert_not_none_for_valid_arguments(self):
        self.assertEqual(True, assertions.assertNotNone(True), 'did not identify that True is not None')

    def test_it_should_assert_not_none_for_invalid_arguments(self):
        try:
            assertions.assertNotNone(None)

            self.fail("did not identify that None is None")
        except assertions.AssertionFailedError, e:
            self.assertEqual('expected None to not be None', e.message)

    def test_it_should_assert_has_layer_for_valid_arguments(self):
        self.assertEqual(True, assertions.assertHasLayer(ICMPv6EchoRequest, IPv6()/ICMPv6EchoRequest()), 'did not identify that IPv6()/ICMPv6EchoRequest packet has ICMPv6EchoRequest layer')

    def test_it_should_assert_has_layer_for_invalid_arguments(self):
        try:
            assertions.assertHasLayer(ICMPv6EchoRequest, IPv6()/ICMPv6ParamProblem())

            self.fail('did not identify that "::1 > ::1 (58) / ICMPv6ParamProblem" does not have layer ICMPv6EchoRequest')
        except assertions.AssertionFailedError, e:
            self.assertEqual('expected "::1 > ::1 (58) / ICMPv6ParamProblem" to have layer ICMPv6EchoRequest', e.message)

    def test_it_should_assert_not_has_layer_for_valid_arguments(self):
        self.assertEqual(True, assertions.assertNotHasLayer(ICMPv6ParamProblem, IPv6()/ICMPv6EchoRequest()), 'did not identify that IPv6()/ICMPv6EchoRequest packet does not have ICMPv6ParamProblem layer')

    def test_it_should_assert_not_has_layer_for_invalid_arguments(self):
        try:
            assertions.assertNotHasLayer(ICMPv6ParamProblem, IPv6()/ICMPv6ParamProblem())

            self.fail('"::1 > ::1 (58) / ICMPv6ParamProblem" has layer ICMPv6ParamProblem')
        except assertions.AssertionFailedError, e:
            self.assertEqual('expected "::1 > ::1 (58) / ICMPv6ParamProblem" not to have layer ICMPv6ParamProblem', e.message)

if __name__ == '__main__':
  unittest.main()
