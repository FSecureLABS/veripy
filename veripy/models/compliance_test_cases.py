from logging import getLogger, Formatter, Handler
from traceback import format_exc
from veripy.assertions import AssertionCounter, AssertionFailedError


class ComplianceTestCase(object):

    disabled_nd = False
    disabled_ra = False
    optional = False
    restart_uut = False
    sequence = 0

    def __init__(self, test_network, ui):
        self.__prepare_logging()

        self.__test_network = test_network
        self.ui = ui

        if self.__class__.disabled_nd:
            self.disable_nd()
        if self.__class__.disabled_ra:
            self.disable_ra()
            
    @classmethod
    def title(cls):
        sections = cls.__extract_pydoc()

        if len(sections[0]) > 0:
            return reduce(lambda x, y: x + ' ' + y, sections[0]).strip()
        else:
            return cls.__name__

    @classmethod
    def description(cls):
        sections = cls.__extract_pydoc()

        if len(sections[1]) > 0:
            return reduce(lambda x, y: x + ' ' + y, sections[1]).strip()
        else:
            return ""

    @classmethod
    def is_optional(cls):
        return cls.optional

    def disable_nd(self):
        self.__test_network.disable_nd()

    def enable_nd(self):
        self.__test_network.enable_nd()

    def disable_ra(self):
        self.__test_network.disable_ra()

    def enable_ra(self):
        self.__test_network.enable_ra()

    def link(self, id):
        return self.__test_network.link(id)

    def links(self):
        return self.__test_network.links()
    
    def log_file(self):
        return self.__logging_handler.log_file

    def next_seq(self):
        ComplianceTestCase.sequence += 1

        return self.seq()

    def node(self, id):
        return self.__test_network.node(id)

    def nodes(self):
        return self.__test_network.nodes()

    def router(self, id):
        return self.__test_network.router(id)

    def routers(self):
        return self.__test_network.routers()
    
    def run(self):
        pass

    def run_case(self):
        o = Outcome(True)

        self.__set_up_framework(o)
        try:
            self.set_up()
            self.send_on_set_up()
            self.run()
        except AssertionFailedError, e:
            o.result = Outcome.Results.FAIL
            o.message = e.message
            o.backtrace = format_exc()
        except Exception, e:
            self.logger.error(str(e))
            
            o.result = Outcome.Results.ERROR
            o.message = e.message
            o.backtrace = format_exc()
        except KeyboardInterrupt, e:
            self.logger.error("Caught SIGINT. This test case will be skipped.")

            o.result = Outcome.Results.ERROR
            o.message = "Skipped, with SIGINT."
        try:
            self.tear_down()
        except Exception, e:
            self.logger.error(e.message)

            o.result = Outcome.Results.ERROR
            o.message = e.message
            o.backtrace = format_exc()
        self.__tear_down_framework(o)

        return o

    def seq(self):
        return ComplianceTestCase.sequence
    
    def set_up(self):
        pass

    def send_on_set_up(self):
        pass

    def tap(self, id):
        return self.__test_network.tap(id)

    def taps(self):
        return self.__test_network.taps()
    
    def target(self, id):
        return self.__test_network.target(id)

    def targets(self):
        return self.__test_network.targets()

    def tear_down(self):
        pass

    @classmethod
    def __extract_pydoc(cls):
        pydoc = cls.__doc__ != None and cls.__doc__.strip() or ""

        assigning, sections = 0, [[], []]

        if pydoc != None:
            for l in map(lambda i: i.strip(), pydoc.split("\n")):
                if l == '@private': break
                if l == '' and assigning < len(sections) - 1: assigning += 1
                sections[assigning].append(l)

        return sections

    def __prepare_logging(self):
        self.logger = getLogger(".veripy.compliance_tests." + self.__class__.__name__ + "Logger")

        self.__logging_handler = InMemoryHandler()
        self.__logging_handler.setFormatter(Formatter('%(asctime)s %(levelname)s %(message)s'))
        self.logger.addHandler(self.__logging_handler)
    
    def __set_up_framework(self, o):
        AssertionCounter.reset()

        if self.__class__.restart_uut:
            self.ui.tell("You need to restart the network interfaces on the UUT before this test case can proceed.")
            self.ui.read("Please press enter once the UUT interfaces are ready.")

        for node in self.nodes():
            node.clear_received()
        for router in self.routers():
            router.clear_received()
            if not self.__class__.disabled_ra:
                router.send_ra()
        for tap in self.taps():
            tap.iface.resume_sniffing()

    def __tear_down_framework(self, o):
        if o.result == Outcome.Results.PASS and AssertionCounter.value() == 0:
            o.result = Outcome.Results.UNIMPLEMENTED

        for tap in self.taps():
            tap.iface.stop_sniffing()

            o.network_dumps.append([tap.link.name, tap.iface.pcap()])

        o.log = self.log_file()

        self.enable_nd()

    def __str__(self):
        pass


class InMemoryHandler(Handler):

    def __init__(self):
        Handler.__init__(self)
        
        self.log_file = ""
    
    def emit(self, record):
        self.log_file += "\n" + self.format(record)


class Outcome(object):

    class Results:
        PASS, FAIL, ERROR, UNIMPLEMENTED = [True, False, -1, -2]
        
    def __init__(self, result):
        self.result = result
        
        self.backtrace = ""
        self.message = ""
        self.network_dumps = []
        self.log = ""

    def is_error(self):
        return self.result == Outcome.Results.ERROR

    def is_fail(self):
        return self.result == Outcome.Results.FAIL

    def is_pass(self):
        return self.result == Outcome.Results.PASS

    def is_unimplemented(self):
        return self.result == Outcome.Results.UNIMPLEMENTED

    def result_string(self):
        if self.result == Outcome.Results.PASS:
            return "Pass"
        elif self.result == Outcome.Results.FAIL:
            return "Fail"
        elif self.result == Outcome.Results.ERROR:
            return "Error"
        elif self.result == Outcome.Results.UNIMPLEMENTED:
            return "Unimplemented"
        else:
            return "None"
        