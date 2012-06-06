from logging import getLogger, FileHandler, Formatter, INFO, StreamHandler
from optparse import OptionGroup, OptionParser
from sys import stdout
from time import sleep
from veripy.interfaces.abstract import Callbacks as AbstractCallbacks
from veripy.interfaces.abstract import Interface as AbstractInterface


class Interface(AbstractInterface):

    __usage = """
Usage: %prog [option] DEVICE

veripy:

  veripy is a tool for verifing the compliance of ICT Equipment against
  requirements for IPv6 set out in RIPE-501.

  For more information about veripy, see the website at http://veripy.org/, or
  follow us on Twitter @veripyv6.

Examples:

  host                  run a veripy test session against a host
  -c my.cfg host        run a veripy test session, with a custom configuration
                        file
  -o host               run a veripy test session, skipping any optional
                        requirements
  -p bgp4 router        run a veripy test session against a router, enabling
                        additional tests for the BGP4 protocol

Arguments:
  DEVICE                the type of device being tested, as defined in RIPE-501
    """.strip()

    def __init__(self, configuration=None, runner=None):
        self.__callbacks = Callbacks(self)

        self.__prepare_logging()

        self.__configuration_klass = configuration
        self.__runner_klass = runner
        self.__parser = VeripyOptionsParser(usage=self.__class__.__usage)
        
        self.__parser.add_option("-c", dest="configuration", help="specify the veripy configuration file to use", metavar="veripy-config.cfg")
        self.__parser.add_option("-f", action="append", dest="formats", help="specify an output format (F) to PATH", metavar="F PATH", nargs=2)
        self.__parser.add_option("-p", action="append", dest="protocols", help="specify a requirement for a particular optional protocol", metavar="PROTOCOL")
        self.__parser.add_option("-s", "--simulate", action="store_true", help="only simulate the test sequence, without actually running them")
        self.__parser.add_option("-t", "--target", action="callback", callback=parse_target, default={}, dest="targets", help="provide configuration of the interfaces of the UUT", metavar="OPTIONS")

        limit_options = OptionGroup(self.__parser, "Running Fewer Test Suites")
        limit_options.add_option("--case", dest="case_rx", help="only run Test Cases whose names match PATTERN", metavar="PATTERN")
        limit_options.add_option("--skip-optional", action="store_true", dest="skip_optional", help="disable tests for optional requirements")
        limit_options.add_option("--suite", dest="suite_rx", help="only run Test Suites whose names match PATTERN", metavar="PATTERN")
        self.__parser.add_option_group(limit_options)

        report_options = OptionGroup(self.__parser, "Report Options")
        report_options.add_option("--title")
        report_options.add_option("--vendor")
        report_options.add_option("--device")
        report_options.add_option("--notes")
        self.__parser.add_option_group(report_options)

    def callbacks(self):
        return self.__callbacks

    def run(self, argv=[]):
        (options, args) = self.__parser.parse_args(argv)

        self.configuration = self.__configuration_klass(args, options, self)
        self.runner = self.configuration.build_runner(self.__runner_klass)

        self.runner.run()

    def __prepare_logging(self):
        self.__logger = getLogger(".veripy")
        self.__logger.setLevel(INFO)
        
        file_h = FileHandler('log/veripy.log')
        file_h.setFormatter(Formatter('%(asctime)s %(levelname)s %(message)s'))
        self.__logger.addHandler(file_h)

        stream_h = StreamHandler(stdout)
        stream_h.setFormatter(Formatter('%(asctime)s %(levelname)s %(message)s'))
        self.__logger.addHandler(stream_h)


class Callbacks(AbstractCallbacks):

    def __init__(self, interface):
        super(self.__class__, self).__init__(interface)
            
    def read(self, prompt=None):
        return raw_input(prompt == None and " > " or prompt)

    def tell(self, message):
        self.write(message)

    def wait(self, seconds):
        stdout.write("%-80s" % ("| Waiting for %d seconds..." % (seconds)))

        for i in range(0, seconds):
            stdout.write("\r%-80s" % ("%s Waiting for %d seconds..." % (['|', '/', '-', '\\', '|', '/', '-', '\\'][(i*2)%8], seconds - i)))
            stdout.flush()
            sleep(0.5)
            stdout.write("\r%-80s" % ("%s Waiting for %d seconds..." % (['|', '/', '-', '\\', '|', '/', '-', '\\'][(i*2+1)%8], seconds - i)))
            stdout.flush()
            sleep(0.5)

        stdout.write("\r%-80s\r" % "")
        stdout.flush()

    def write(self, prompt):
        print prompt


class VeripyOptionsParser(OptionParser):

    def error(self, msg):
        pass

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
    