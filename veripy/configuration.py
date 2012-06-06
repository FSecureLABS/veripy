from ConfigParser import ConfigParser
from libs.ipcalc import Network
from veripy.exceptions import *
from veripy.formatters import Formatter
from veripy.models import ComplianceTestSuite, IPAddress, IPAddressCollection, Report, TestNetwork
from veripy.networking import Base
from veripy.runner import Runner


class Configuration(object):

    def __init__(self, args, options, ui=None):
        self.__pre_validate_args(args)
        self.__pre_validate_options(options)
        self.__load_configuration()
        self.__validate_args(args)

        self.klass = args[0]
        # veripy session configuration
        self.formatters = self.__get_formatters(options.ensure_value('formats', []))
        self.protocols = options.ensure_value('protocols', [])
        # limits configuration
        self.case_rx = options.ensure_value('case_rx', None)
        self.skip_optional = options.ensure_value('skip_optional', False)
        self.suite_rx = options.ensure_value('suite_rx', None)
        # report configuration
        self.title = options.ensure_value('title', 'veripy Test Report')
        self.vendor = options.ensure_value('vendor', 'N/A')
        self.device = options.ensure_value('device', 'N/A')
        self.notes = options.ensure_value('notes', 'N/A')
        # ui configuration
        self.ui = ui
        # test network configuration
        self.__test_network_config = TestNetworkConfiguration(self)
        # target network configuration
        for i in options.targets.keys():
            getattr(self.__test_network_config, 'uut' + str(i)).ips = IPAddressCollection(options.targets[i][0:-1])
            getattr(self.__test_network_config, 'uut' + str(i)).ll_addr = options.targets[i][-1]

        # run validations
        self.__validate_options(options)
        # actually build the test network
        self.__test_network = TestNetwork(self.test_network())

    def build_report(self):
        return Report(self.klass, self.title, self.vendor, self.device, self.notes)

    def build_runner(self, klass=None):
        if klass == None:
            return Runner(self)
        else:
            return klass(self)

    def build_test_network(self):
        return self.__test_network

    def device_klasses(self):
        return map(lambda x: self.get('devices', str(x)), sorted(map(lambda x: int(x), self.keys('devices'))))

    def get(self, section, key):
        return self.__config.get(section, key)

    def has_option(self, section, key):
        return self.__config.has_option(section, key)

    def has_section(self, section):
        return self.__config.has_section(section)

    def keys(self, section):
        return self.__config.options(section)

    def protocols_for(self, klass):
        return self.has_section('device-' + klass) and map(lambda p: p.strip(), self.get('device-' + klass, 'protocols').split(",")) or []

    def test_network(self):
        return self.__test_network_config
    
    def test_plan(self):
        suites = []

        for suite in self.test_suites():
            if self.__enable_test_suite(suite):
                suites.append(suite)

        return map(lambda s: ComplianceTestSuite.get(s), suites)

    def test_suites(self):
        return map(lambda x: self.get('test-suites', str(x)), sorted(map(lambda x: int(x), self.keys('test-suites'))))

    def __enable_test_suite(self, suite):
        if self.has_option("ts-" + suite, self.klass):
            if self.suite_rx != None:
                if ComplianceTestSuite.get(suite).title().lower().find(self.suite_rx.lower()) == -1:
                    return False
                
            for configuration in map(lambda c: c.strip(), self.get("ts-" + suite, self.klass).split("|")):
                options = map(lambda s: s.strip(), configuration.split(","))

                mandatory = options[0] == "mandatory"
                protocols = options[1::]

                if (mandatory or not self.skip_optional) and (not False in map(lambda p: p in self.protocols, protocols)):
                    return True
            
        return False

    def __get_formatters(self, formats):
        formatters = {}
        
        for f in formats:
            formatters[f[0]] = [Formatter.get(f[0]), f[1]]

        return formatters

    def __load_configuration(self):
        self.__config = ConfigParser()
        self.__config.read(self.__options.ensure_value('configuration', 'veripy.cfg'))

    def __pre_validate_args(self, args):
        if len(args) != 1:
            raise InvalidConfigurationError("no device class specified")

    def __pre_validate_options(self, options):
        self.__options = options

    def __validate_args(self, args):
        if not args[0] in self.device_klasses():
            raise InvalidConfigurationError("'%s' is not a known type of device" % args[0])

    def __validate_options(self, options):
        unknown_protocols = filter(lambda p: not p in self.protocols_for(self.klass), options.ensure_value('protocols', []))
        if len(unknown_protocols) > 0:
            raise InvalidConfigurationError("unknown protocol '%s' specified" % unknown_protocols[0])


class TestNetworkConfiguration(object):

    def __init__(self, config):
        self.__config = config
        
        self.link_layer = config.get('test-network', 'link-layer')

        for link in self.__config.get('test-network', 'links').split(","):
            setattr(self, 'link' + link.strip(), TestNetworkConfiguration.Link(self.__config, link.strip()))
        for node in self.__config.get('test-network', 'nodes').split(","):
            setattr(self, node.strip(), TestNetworkConfiguration.Node(self.__config, node.strip()))
        for router in self.__config.get('test-network', 'routers').split(","):
            setattr(self, router.strip(), TestNetworkConfiguration.Node(self.__config, router.strip()))
        for tap in self.__config.get('test-network', 'taps').split(","):
            setattr(self, tap.strip(), TestNetworkConfiguration.Tap(self.__config, tap.strip()))
            setattr(self, tap.strip().replace("tp", "uut"), TestNetworkConfiguration.Target())

    class Link(object):

        def __init__(self, config, link):
            self.__config = config

            n4 = Network(self.__config.get('test-network', 'link-' + link + '-v4'))
            n6 = Network(self.__config.get('test-network', 'link-' + link + '-v6'))

            self.v4_prefix = str(n4.network())
            self.v4_prefix_size = n4.subnet()
            
            self.prefix = self.v6_prefix = str(n6.network())
            self.prefix_size = self.v6_prefix_size = n6.subnet()

        def v4_cidr(self):
            return "%s/%s" % (self.v4_prefix, self.v4_prefix_size)

        def v6_cidr(self):
            return "%s/%s" % (self.v6_prefix, self.v6_prefix_size)
    
    class Node(object):

        def __init__(self, config, node):
            self.__config = config

            for iface in range(0, int(self.__config.get('test-network', node + '-ifaces'))):
                setattr(self, 'if' + str(iface) + '_address', self.__config.get('test-network', node + '-if' + str(iface) + '-address'))
                setattr(self, 'if' + str(iface) + '_ips', self.__extract_ips(self.__config.get('test-network', node + '-if' + str(iface) + '-ips')))
        
        def __extract_ips(self, ip_str):
            return map(lambda ip: IPAddress.identify(ip.strip()), ip_str.split(","))


    class Tap(object):

        def __init__(self, config, tap):
            self.__config = config

            self.dev = self.__config.get('test-network', tap + '-dev')
            self.ll_addr = self.__config.get('test-network', tap + '-address')

    class Target(object):

        def __init__(self):
            self.ips = None
            self.ll_addr = None
            