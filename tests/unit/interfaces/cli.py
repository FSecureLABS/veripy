from tests.mocks.configuration import MockConfiguration
from tests.mocks.runner import MockRunner
import unittest
from veripy.interfaces.cli import Interface, Callbacks


class CliTestCase(unittest.TestCase):

    def test_it_should_pass_an_option_specifying_the_configuration_file(self):
        i = Interface(configuration=MockConfiguration, runner=MockRunner)
        i.run(["-c", "tests/mocks/veripy.cfg", "host"])
        
        self.assertEqual('tests/mocks/veripy.cfg', i.configuration._Configuration__options.ensure_value('configuration', ''))
    
    def test_it_should_pass_an_option_specifying_whether_to_run_option_tests(self):
        i = Interface(configuration=MockConfiguration, runner=MockRunner)
        i.run(["--skip-optional", "host"])
        
        self.assertTrue(i.configuration._Configuration__options.ensure_value('skip_optional', None))
    
    def test_it_should_pass_a_protocol_requirement(self):
        i = Interface(configuration=MockConfiguration, runner=MockRunner)
        i.run(["-p", "bgp4", "router"])
        
        self.assertEqual(1, len(i.configuration._Configuration__options.ensure_value('protocols', [])))
        self.assertTrue('bgp4' in i.configuration._Configuration__options.ensure_value('protocols', []))
    
    def test_it_should_pass_multiple_protocol_requirements(self):
        i = Interface(configuration=MockConfiguration, runner=MockRunner)
        i.run(["-p", "6pe", "-p", "mpls", "router"])
        
        self.assertEqual(2, len(i.configuration._Configuration__options.ensure_value('protocols', [])))
        self.assertTrue('6pe' in i.configuration._Configuration__options.ensure_value('protocols', []))
        self.assertTrue('mpls' in i.configuration._Configuration__options.ensure_value('protocols', []))
    
    def test_it_should_copy_the_vendor_specified(self):
        i = Interface(configuration=MockConfiguration, runner=MockRunner)
        i.run(["--vendor", "MWR", "host"])
        
        self.assertEqual('MWR', i.configuration._Configuration__options.ensure_value('vendor', ''))
    
    def test_it_should_copy_the_device_specified(self):
        i = Interface(configuration=MockConfiguration, runner=MockRunner)
        i.run(["--device", "Desktop PC", "host"])

        self.assertEqual('Desktop PC', i.configuration._Configuration__options.ensure_value('device', ''))
    
    def test_it_should_copy_the_report_title_specified(self):
        i = Interface(configuration=MockConfiguration, runner=MockRunner)
        i.run(["--title", "My Report", "host"])
        
        self.assertEqual('My Report', i.configuration._Configuration__options.ensure_value('title', ''))
    
    def test_it_should_recover_gracefully_if_a_nonsense_option_is_specified(self):
        i = Interface(configuration=MockConfiguration, runner=MockRunner)
        
        try:
            i.run(["--junk", "host"])
        except Exception, e:
            self.fail("allowed an exception to propogate where an invalid option had been provided: " + e.message)
    
    def test_it_should_pass_positional_arguments(self):
        i = Interface(configuration=MockConfiguration, runner=MockRunner)
        i.run(["host"])
        
        self.assertEqual('host', i.configuration.klass,)
    
    def test_it_should_pass_a_set_of_ui_callbacks(self):
        i = Interface(configuration=MockConfiguration, runner=MockRunner)
	i.run(["host"])
        
        self.assertEqual(i, i.configuration.ui)
    
    def test_it_should_pass_the_simulate_option(self):
        i = Interface(configuration=MockConfiguration, runner = MockRunner)
        i.run(["-s", "host"])
        
        self.assertTrue(i.configuration._Configuration__options.ensure_value('simulate', None))

    def test_it_should_pass_a_selected_output_format(self):
        i = Interface(configuration=MockConfiguration, runner=MockRunner)
        i.run(["-fX", "/home/user/test-runs/device.xml", "host"])

        f = dict(i.configuration._Configuration__options.ensure_value('formats', []))
        
        self.assertEqual(False, 'C' in f.keys())
        self.assertEqual(False, 'H' in f.keys())
        self.assertEqual(True, 'X' in f.keys())
    
    def test_it_should_pass_a_multiple_output_formats(self):
        i = Interface(configuration=MockConfiguration, runner=MockRunner)
        i.run(["-fX", "/home/user/test-runs/device.xml", "-fH", "/home/user/test-runs/device.html", "-fC", "/home/user/test-runs/device.csv", "host"])
        
        f = dict(i.configuration._Configuration__options.ensure_value('formats', []))
        
        self.assertEqual(True, 'C' in f.keys())
        self.assertEqual(True, 'H' in f.keys())
        self.assertEqual(True, 'X' in f.keys())
    
    def test_it_should_pass_the_formatter_output_path(self):
        i = Interface(configuration=MockConfiguration, runner=MockRunner)
        i.run(["-fX", "/home/user/test-runs/device.xml", "host"])
        
        f = dict(i.configuration._Configuration__options.ensure_value('formats', []))

        self.assertEqual('/home/user/test-runs/device.xml', f['X'])
    
    def test_it_should_pass_the_path_for_multiple_formatters(self):
        i = Interface(configuration=MockConfiguration, runner=MockRunner)
        i.run(["-fX", "/home/user/test-runs/device.xml", "-fH", "/home/user/test-runs/device.html", "-fC", "/home/user/test-runs/device.csv", "host"])
        
        f = dict(i.configuration._Configuration__options.ensure_value('formats', []))
        
        self.assertEqual('/home/user/test-runs/device.csv', f['C'])
        self.assertEqual('/home/user/test-runs/device.html', f['H'])
        self.assertEqual('/home/user/test-runs/device.xml', f['X'])

    def test_it_should_receive_the_target_ips_ifx(self):
        i = Interface(configuration=MockConfiguration, runner=MockRunner)
        i.run(["-t", "1", "2012:6970:7636:0:20c:29ff:fef4:b890", "fe80::20c:29ff:fef4:b890", "00:0c:29:f4:b8:90", "host"])

        t = i.configuration._Configuration__options.targets

        self.assertTrue(t.has_key(1))
        self.assertEqual(3, len(t[1]))
        self.assertEqual("2012:6970:7636:0:20c:29ff:fef4:b890", t[1][0])
        self.assertEqual("fe80::20c:29ff:fef4:b890", t[1][1])

    def test_it_should_receive_the_target_link_layer_address_ifx(self):
        i = Interface(configuration=MockConfiguration, runner=MockRunner)
        i.run(["-t", "1", "2012:6970:7636:0:20c:29ff:fef4:b890", "fe80::20c:29ff:fef4:b890", "00:0c:29:f4:b8:90", "host"])

        t = i.configuration._Configuration__options.targets

        self.assertTrue(t.has_key(1))
        self.assertEqual(3, len(t[1]))
        self.assertEqual("00:0c:29:f4:b8:90", t[1][2])

    def test_it_should_receive_the_target_ips_ify(self):
        i = Interface(configuration=MockConfiguration, runner=MockRunner)
        i.run(["-t", "2", "2012:6970:7636:0:20c:29ff:fef4:b890", "fe80::20c:29ff:fef4:b890", "00:0c:29:f4:b8:90", "host"])

        t = i.configuration._Configuration__options.targets

        self.assertTrue(t.has_key(2))
        self.assertEqual(3, len(t[2]))
        self.assertEqual("2012:6970:7636:0:20c:29ff:fef4:b890", t[2][0])
        self.assertEqual("fe80::20c:29ff:fef4:b890", t[2][1])

    def test_it_should_receive_the_target_link_layer_address_ify(self):
        i = Interface(configuration=MockConfiguration, runner=MockRunner)
        i.run(["-t", "2", "2012:6970:7636:0:20c:29ff:fef4:b890", "fe80::20c:29ff:fef4:b890", "00:0c:29:f4:b8:90", "host"])

        t = i.configuration._Configuration__options.targets

        self.assertTrue(t.has_key(2))
        self.assertEqual(3, len(t[2]))
        self.assertEqual("00:0c:29:f4:b8:90", t[2][2])

    def test_it_should_allow_a_test_suite_pattern_to_be_specified(self):
        i = Interface(configuration=MockConfiguration, runner=MockRunner)
        i.run(["--suite", "ICMPv6", "host"])

        self.assertEqual("ICMPv6", i.configuration._Configuration__options.suite_rx)

    def test_it_should_allow_a_test_case_pattern_to_be_specified(self):
        i = Interface(configuration=MockConfiguration, runner=MockRunner)
        i.run(["--case", "ICMPv6", "host"])

        self.assertEqual("ICMPv6", i.configuration._Configuration__options.case_rx)
        