import unittest
from tests.mocks.cli import MockInterface
from tests.mocks.configuration import sampleOptions
from veripy import Configuration, Runner
from veripy.configuration import TestNetworkConfiguration
from veripy.exceptions import *
from veripy.models import ComplianceTestSuite, IPAddress, Report, TestNetwork


class ConfigurationTestCase(unittest.TestCase):

    def setUp(self):
        ComplianceTestSuite.clear()
        ComplianceTestSuite.register('ipv6-basic-specification', ConfigurationTestCase.TestSuiteA)
        ComplianceTestSuite.register('ipv6-default-address-selection', ConfigurationTestCase.TestSuiteB)
        ComplianceTestSuite.register('icmpv6', ConfigurationTestCase.TestSuiteC)
        ComplianceTestSuite.register('neighbour-discovery', ConfigurationTestCase.TestSuiteD)
        ComplianceTestSuite.register('pmtu-discovery', ConfigurationTestCase.TestSuiteE)
        ComplianceTestSuite.register('ipv6-router-alert-option', ConfigurationTestCase.TestSuiteF)

    def tearDown(self):
        ComplianceTestSuite.clear()


    class TestSuiteA(ComplianceTestSuite): pass
    class TestSuiteB(ComplianceTestSuite): pass
    class TestSuiteC(ComplianceTestSuite): pass
    class TestSuiteD(ComplianceTestSuite): pass
    class TestSuiteE(ComplianceTestSuite): pass
    class TestSuiteF(ComplianceTestSuite): pass


    def test_it_should_build_a_configuration(self):
        options, args = sampleOptions("host")
        
        self.assertTrue(isinstance(Configuration(args, options), Configuration))

    def test_it_should_read_configuration_from_the_specified_file(self):
        options, args = sampleOptions("--configuration tests/mocks/veripy.cfg host")

        c = Configuration(args, options)
        
        self.assertTrue(isinstance(c, Configuration))
        self.assertTrue(c.has_section('test-section'))
        self.assertEqual(1, len(c.keys('test-section')))
        self.assertTrue(c.has_option('test-section', 'key'))
        self.assertEqual('value', c.get('test-section', 'key'))

    def test_it_should_read_an_ordered_list_of_all_known_test_suites(self):
        options, args = sampleOptions("--configuration tests/mocks/veripy.cfg host")

        c = Configuration(args, options)
        s = c.test_suites()

        self.assertEqual(6, len(s))
        self.assertEqual('ipv6-basic-specification', s[0])
        self.assertEqual('ipv6-default-address-selection', s[1])
        self.assertEqual('icmpv6', s[2])
        self.assertEqual('neighbour-discovery', s[3])

    def test_it_should_read_an_ordered_list_of_all_known_devices(self):
        options, args = sampleOptions("--configuration tests/mocks/veripy.cfg host")

        c = Configuration(args, options)
        k = c.device_klasses()

        self.assertEqual(10, len(k))
        self.assertEqual('host', k[0])
        self.assertEqual('switch-consumer', k[1])
        self.assertEqual('switch-enterprise', k[2])
        self.assertEqual('router', k[3])

    def test_it_should_build_a_report(self):
        options, args = sampleOptions("--configuration tests/mocks/veripy.cfg host")

        c = Configuration(args, options)
        r = c.build_report()

        self.assertTrue(isinstance(r, Report))

    def test_it_should_pass_configuration_into_the_build_report(self):
        options, args = sampleOptions("--configuration tests/mocks/veripy.cfg --title Report --vendor veripy --device Desktop --notes Lorem. host")

        c = Configuration(args, options)
        r = c.build_report()

        self.assertEqual("host", r.klass)
        self.assertEqual("Report", r.title)
        self.assertEqual("veripy", r.vendor)
        self.assertEqual("Desktop", r.device)
        self.assertEqual("Lorem.", r.notes)

    def test_it_should_build_a_runner(self):
        options, args = sampleOptions("--configuration tests/mocks/veripy.cfg host")

        c = Configuration(args, options, MockInterface())
        r = c.build_runner()

        self.assertTrue(isinstance(r, Runner))

    def test_it_should_give_the_runner_a_pointer_back_to_the_configuration(self):
        options, args = sampleOptions("--configuration tests/mocks/veripy.cfg host")

        c = Configuration(args, options, MockInterface())
        r = c.build_runner()

        self.assertEqual(c, r._Runner__config)

    def test_it_should_build_a_test_network(self):
        options, args = sampleOptions("--configuration tests/mocks/veripy.cfg host")

        c = Configuration(args, options)
        n = c.build_test_network()

        self.assertTrue(isinstance(n, TestNetwork))

    def test_it_should_pass_configuration_into_the_test_network(self):
        options, args = sampleOptions("--configuration tests/mocks/veripy.cfg host")

        c = Configuration(args, options)
        n = c.build_test_network()

        self.assertTrue(isinstance(c.test_network(), TestNetworkConfiguration))

    def test_it_should_identify_a_subset_of_test_suites_to_run_1_of_2(self):
        options, args = sampleOptions("--configuration tests/mocks/veripy.cfg host")

        c = Configuration(args, options)
        s = c.test_plan()

        self.assertEqual(6, len(s))
        self.assertEqual(ConfigurationTestCase.TestSuiteA, s[0])
        self.assertEqual(ConfigurationTestCase.TestSuiteB, s[1])
        self.assertEqual(ConfigurationTestCase.TestSuiteC, s[2])
        self.assertEqual(ConfigurationTestCase.TestSuiteD, s[3])

    def test_it_should_identify_a_subset_of_test_suites_to_run_2_of_2(self):
        options, args = sampleOptions("--configuration tests/mocks/veripy.cfg switch-enterprise")

        c = Configuration(args, options)
        s = c.test_plan()

        self.assertEqual(3, len(s))
        self.assertEqual(ConfigurationTestCase.TestSuiteA, s[0])
        self.assertEqual(ConfigurationTestCase.TestSuiteB, s[1])
        self.assertEqual(ConfigurationTestCase.TestSuiteC, s[2])

    def test_it_should_identify_a_subset_of_test_suites_to_run_with_optional_protocols(self):
        options, args = sampleOptions("--configuration tests/mocks/veripy.cfg -p switch-is-a-router switch-enterprise")

        c = Configuration(args, options)
        s = c.test_plan()

        self.assertEqual(4, len(s))
        self.assertEqual(ConfigurationTestCase.TestSuiteA, s[0])
        self.assertEqual(ConfigurationTestCase.TestSuiteB, s[1])
        self.assertEqual(ConfigurationTestCase.TestSuiteC, s[2])
        self.assertEqual(ConfigurationTestCase.TestSuiteF, s[3])

    def test_it_should_identify_a_subset_of_test_suites_to_run_without_optionals(self):
        options, args = sampleOptions("--configuration tests/mocks/veripy.cfg --skip-optional host")

        c = Configuration(args, options)
        s = c.test_plan()

        self.assertEqual(5, len(s))

    def test_it_should_raise_if_no_device_is_specified(self):
        options, args = sampleOptions("--configuration tests/mocks/veripy.cfg")

        try:
            Configuration(args, options)
            
            self.fail("expected an InvalidConfigurationError to be thrown")
        except InvalidConfigurationError, e:
            self.assertEqual("no device class specified", e.message)

    def test_it_should_raise_if_an_unknown_device_is_specified(self):
        options, args = sampleOptions("--configuration tests/mocks/veripy.cfg dog")

        try:
            Configuration(args, options)

            self.fail("expected an InvalidConfigurationError to be thrown")
        except InvalidConfigurationError, e:
            self.assertEqual("'dog' is not a known type of device", e.message)

    def test_it_should_raise_if_an_unknown_protocol_is_specified(self):
        options, args = sampleOptions("--configuration tests/mocks/veripy.cfg -p RAID host")

        try:
            Configuration(args, options)

            self.fail("expected an InvalidConfigurationError to be thrown")
        except InvalidConfigurationError, e:
            self.assertEqual("unknown protocol 'RAID' specified", e.message)

    def test_it_should_identify_an_output_formatter(self):
        options, args = sampleOptions("--configuratio tests/mocks/veripy.cfg -fX out.xml host")

        c = Configuration(args, options)

        self.assertEqual(1, len(c.formatters))
        self.assertTrue("X" in c.formatters.keys())
        self.assertEqual("XMLFormatter", c.formatters['X'][0].__name__)
        self.assertEqual("out.xml", c.formatters['X'][1])

    def test_it_should_identify_multiple_output_formatters(self):
        options, args = sampleOptions("--configuratio tests/mocks/veripy.cfg -fX out.xml -fH out.html host")

        c = Configuration(args, options)

        self.assertEqual(2, len(c.formatters))
        self.assertTrue("X" in c.formatters.keys())
        self.assertEqual("XMLFormatter", c.formatters['X'][0].__name__)
        self.assertEqual("out.xml", c.formatters['X'][1])
        self.assertTrue("H" in c.formatters.keys())
        self.assertEqual("HTMLFormatter", c.formatters['H'][0].__name__)
        self.assertEqual("out.html", c.formatters['H'][1])

    def test_it_should_configure_the_prefix_of_link_a(self):
        options, args = sampleOptions("--configuration tests/mocks/veripy.cfg host")

        c = Configuration(args, options)

        self.assertEqual("2012:7665:7269:7079:0000:0000:0000:0000", c.test_network().link1.prefix)

    def test_it_should_configure_the_prefix_size_of_link_a(self):
        options, args = sampleOptions("--configuration tests/mocks/veripy.cfg host")

        c = Configuration(args, options)

        self.assertEqual(64, c.test_network().link1.prefix_size)

    def test_it_should_configure_the_prefix_of_link_b(self):
        options, args = sampleOptions("--configuration tests/mocks/veripy.cfg host")

        c = Configuration(args, options)

        self.assertEqual("2012:6970:7636:0000:0000:0000:0000:0000", c.test_network().link2.prefix)

    def test_it_should_configure_the_prefix_size_of_link_b(self):
        options, args = sampleOptions("--configuration tests/mocks/veripy.cfg host")

        c = Configuration(args, options)

        self.assertEqual(64, c.test_network().link2.prefix_size)

    def test_it_should_configure_the_prefix_of_link_c(self):
        options, args = sampleOptions("--configuration tests/mocks/veripy.cfg host")

        c = Configuration(args, options)

        self.assertEqual("2012:6d77:7269:0000:0000:0000:0000:0000", c.test_network().link3.prefix)

    def test_it_should_configure_the_prefix_size_of_link_c(self):
        options, args = sampleOptions("--configuration tests/mocks/veripy.cfg host")

        c = Configuration(args, options)

        self.assertEqual(64, c.test_network().link3.prefix_size)

    def test_it_should_get_the_global_ip_of_tn1(self):
        options, args = sampleOptions("--configuration tests/mocks/veripy.cfg host")

        c = Configuration(args, options)

        self.assertEqual(3, len(c.test_network().tn1.if0_ips))
        self.assertTrue(IPAddress.identify("2012:6970:7636:ef::0102") in c.test_network().tn1.if0_ips)

    def test_it_should_get_the_global_ip_of_tn2(self):
        options, args = sampleOptions("--configuration tests/mocks/veripy.cfg host")

        c = Configuration(args, options)

        self.assertEqual(2, len(c.test_network().tn2.if0_ips))
        self.assertTrue(IPAddress.identify("2012:7665:7269:7079::ef:0103") in c.test_network().tn2.if0_ips)

    def test_it_should_get_the_global_ip_of_tn3(self):
        options, args = sampleOptions("--configuration tests/mocks/veripy.cfg host")

        c = Configuration(args, options)

        self.assertEqual(2, len(c.test_network().tn3.if0_ips))
        self.assertTrue(IPAddress.identify("2012:7665:7269:7079::ef:0104") in c.test_network().tn3.if0_ips)

    def test_it_should_get_the_global_ip_of_tn4(self):
        options, args = sampleOptions("--configuration tests/mocks/veripy.cfg host")

        c = Configuration(args, options)

        self.assertEqual(2, len(c.test_network().tn4.if0_ips))
        self.assertTrue(IPAddress.identify("2012:6d77:7269::ef:0105") in c.test_network().tn4.if0_ips)

    def test_it_should_get_the_link_local_ip_of_tn1(self):
        options, args = sampleOptions("--configuration tests/mocks/veripy.cfg host")

        c = Configuration(args, options)

        self.assertEqual(3, len(c.test_network().tn1.if0_ips))
        self.assertTrue(IPAddress.identify("fe80::7a2b:cbff:feef:0102") in c.test_network().tn1.if0_ips)
        self.assertTrue(IPAddress.identify("fe80::7a2b:cbff:feca:ad05") in c.test_network().tn1.if0_ips)

    def test_it_should_get_the_link_local_ip_of_tn2(self):
        options, args = sampleOptions("--configuration tests/mocks/veripy.cfg host")

        c = Configuration(args, options)

        self.assertEqual(2, len(c.test_network().tn2.if0_ips))
        self.assertTrue(IPAddress.identify("fe80::7a2b:cbff:feef:0103") in c.test_network().tn2.if0_ips)

    def test_it_should_get_the_link_local_ip_of_tn3(self):
        options, args = sampleOptions("--configuration tests/mocks/veripy.cfg host")

        c = Configuration(args, options)

        self.assertEqual(2, len(c.test_network().tn3.if0_ips))
        self.assertTrue(IPAddress.identify("fe80::7a2b:cbff:feef:0104") in c.test_network().tn3.if0_ips)

    def test_it_should_get_the_link_local_ip_of_tn4(self):
        options, args = sampleOptions("--configuration tests/mocks/veripy.cfg host")

        c = Configuration(args, options)

        self.assertEqual(2, len(c.test_network().tn4.if0_ips))
        self.assertTrue(IPAddress.identify("fe80::7a2b:cbff:feef:0105") in c.test_network().tn4.if0_ips)

    def test_it_should_get_the_global_ip_of_tr1if0(self):
        options, args = sampleOptions("--configuration tests/mocks/veripy.cfg host")

        c = Configuration(args, options)

        self.assertEqual(2, len(c.test_network().tr1.if0_ips))
        self.assertTrue(IPAddress.identify("2012:7665:7269:7079::fe:0101") in c.test_network().tr1.if0_ips)
        self.assertTrue(IPAddress.identify("fe80::7a2b:cbff:fefe:0101") in c.test_network().tr1.if0_ips)

    def test_it_should_get_the_global_ip_of_tr2if0(self):
        options, args = sampleOptions("--configuration tests/mocks/veripy.cfg host")

        c = Configuration(args, options)

        self.assertEqual(2, len(c.test_network().tr1.if0_ips))
        self.assertTrue(IPAddress.identify("2012:7665:7269:7079::fe:102") in c.test_network().tr2.if0_ips)
        self.assertTrue(IPAddress.identify("fe80::7a2b:cbff:fefe:102") in c.test_network().tr2.if0_ips)

    def test_it_should_get_the_global_ip_of_tr3if0(self):
        options, args = sampleOptions("--configuration tests/mocks/veripy.cfg host")

        c = Configuration(args, options)

        self.assertEqual(2, len(c.test_network().tr1.if0_ips))
        self.assertTrue(IPAddress.identify("2012:7665:7269:7079::fe:103") in c.test_network().tr3.if0_ips)
        self.assertTrue(IPAddress.identify("fe80::7a2b:cbff:fefe:103") in c.test_network().tr3.if0_ips)

    def test_it_should_get_the_global_ip_of_tr1if1(self):
        options, args = sampleOptions("--configuration tests/mocks/veripy.cfg host")

        c = Configuration(args, options)

        self.assertEqual(2, len(c.test_network().tr1.if1_ips))
        self.assertTrue(IPAddress.identify("2012:7665:7269:7079::fe:0102") in c.test_network().tr1.if1_ips)
        self.assertTrue(IPAddress.identify("fe80::7a2b:cbff:fefe:0102") in c.test_network().tr1.if1_ips)

    def test_it_should_get_the_global_ip_of_tr2if1(self):
        options, args = sampleOptions("--configuration tests/mocks/veripy.cfg host")

        c = Configuration(args, options)

        self.assertEqual(2, len(c.test_network().tr1.if0_ips))
        self.assertTrue(IPAddress.identify("2012:6970:7636::fe:103") in c.test_network().tr2.if1_ips)
        self.assertTrue(IPAddress.identify("fe80::7a2b:cbff:fefe:103") in c.test_network().tr2.if1_ips)

    def test_it_should_get_the_global_ip_of_tr3if1(self):
        options, args = sampleOptions("--configuration tests/mocks/veripy.cfg host")

        c = Configuration(args, options)

        self.assertEqual(2, len(c.test_network().tr1.if0_ips))
        self.assertTrue(IPAddress.identify("2012:6970:7636::fe:104") in c.test_network().tr3.if1_ips)
        self.assertTrue(IPAddress.identify("fe80::7a2b:cbff:fefe:104") in c.test_network().tr3.if1_ips)

    def test_it_should_get_the_physical_device_for_tap1(self):
        options, args = sampleOptions("--configuration tests/mocks/veripy.cfg host")

        c = Configuration(args, options)

        self.assertEqual('vmnet8', c.test_network().tp1.dev)

    def test_it_should_get_the_link_layer_address_of_tap1(self):
        options, args = sampleOptions("--configuration tests/mocks/veripy.cfg host")

        c = Configuration(args, options)

        self.assertEqual('00:50:56:c0:00:08', c.test_network().tp1.ll_addr)

    def test_it_should_get_the_physical_device_for_tap2(self):
        options, args = sampleOptions("--configuration tests/mocks/veripy.cfg host")

        c = Configuration(args, options)

        self.assertEqual('vmnet8', c.test_network().tp2.dev)

    def test_it_should_get_the_link_layer_address_of_tap2(self):
        options, args = sampleOptions("--configuration tests/mocks/veripy.cfg host")

        c = Configuration(args, options)

        self.assertEqual('00:50:56:c0:00:08', c.test_network().tp2.ll_addr)

    def test_it_should_configure_a_test_suite_pattern(self):
        options, args = sampleOptions(["--suite", "My Test Suite", "host"])

        c = Configuration(args, options)

        self.assertEqual('My Test Suite', c.suite_rx)

    def test_it_should_configure_a_test_case_pattern(self):
        options, args = sampleOptions(["--case", "My Test Case", "host"])

        c = Configuration(args, options)

        self.assertEqual('My Test Case', c.case_rx)

    def test_it_should_not_run_test_suites_that_do_not_match_the_suite_pattern(self):
        options, args = sampleOptions("--configuration tests/mocks/veripy.cfg --suite TestSuiteA host")

        c = Configuration(args, options)
        s = c.test_plan()

        self.assertEqual(1, len(s))
        self.assertEqual(ConfigurationTestCase.TestSuiteA, s[0])
        