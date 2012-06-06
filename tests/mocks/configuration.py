from optparse import OptionParser, OptionGroup
from tests.mocks.test_network import MockInterface, MockTap, MockTargetInterface
from veripy import Configuration
from veripy.models import TestNetwork


def sampleOptions(params):
    parser = OptionParser()
    parser.add_option("-c", "--configuration")
    parser.add_option("-f", action="append", dest="formats", nargs=2)
    parser.add_option("-p", action="append", dest="protocols")
    parser.add_option("-o", "--skip-optional", action="store_true", dest="skip_optional")
    parser.add_option("-t", "--target", action="callback", callback=parse_target, default={}, dest="targets")

    limit = OptionGroup(parser, "Limit Options")
    limit.add_option("--case", dest="case_rx")
    limit.add_option("--suite", dest="suite_rx")
    parser.add_option_group(limit)

    report = OptionGroup(parser, "Report Options")
    report.add_option("--title")
    report.add_option("--vendor")
    report.add_option("--device")
    report.add_option("--notes")
    parser.add_option_group(report)

    return parser.parse_args(isinstance(params, str) and params.split(" ") or params)


class MockConfiguration(Configuration):

    def __init__(self, args, options, ui):
        super(MockConfiguration, self).__init__(args, options, ui)
        
        self.mock_test_plan = []

    def build_test_network(self):
        tn = TestNetwork(self.test_network())

        tn._TestNetwork__taps[0].unbind()
        tn._TestNetwork__taps[0] = MockTap(tn.link(2),
                                            MockInterface('if0', 'be:ef:ca:fe:09:01'),
                                            MockTargetInterface(ips=["2001:800:88:200::50", "fe80::50"], ll_protocol='Ethernet', link_addr='be:ef:ba:be:09:01'))
        tn._TestNetwork__taps[1].unbind()
        tn._TestNetwork__taps[1] = MockTap(tn.link(3),
                                            MockInterface('if1', 'be:ef:ca:fe:09:02'),
                                            MockTargetInterface(ips=["2001:900:88:200::50", "fe80::51"], ll_protocol='Ethernet', link_addr='be:ef:ba:be:09:02'))

        return tn
    
    def test_plan(self):
        return self.mock_test_plan


def parse_target(option, opt_str, value, parser):
    """
    Parses a target definition from the commandline, accepting the link
    layer definition, any number of IP addresses and any arguments required
    for the link layer specification.
    """
    value = []
    # the first element of a target definition should be the target_id, as an
    # integer
    value.append(int(parser.rargs[0]))
    # then, a series of IP addresses, followed by any specifications required
    # by the link layer itself
    for i, arg in enumerate(parser.rargs[1:]):
        if not (arg.startswith("-") or i == len(parser.rargs) - 2):
            value.append(arg)
        else:
            break
    # remove all the arguments that we have consumed from the buffer
    del parser.rargs[:len(value)]
    # check that we haven't already seen a definition for this target
    if value[0] in getattr(parser.values, option.dest):
        raise InvalidOptionsError('already got definition for target ' + repr(value[1]))
    # finally, save the subnet definition into the options dictionary.
    getattr(parser.values, option.dest)[value[0]] = value[1:]

    