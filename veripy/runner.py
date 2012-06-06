
class Runner(object):

    def __init__(self, configuration):
        self.__config = configuration
        self.__stop = False

        self.reset()

    def clean_up(self):
        pass

    def current_test_case(self):
        if self.current_test_suite() and self.__case_index >= 0 and self.__case_index < len(self.current_test_suite().test_cases(self.__config.case_rx)):
            return self.current_test_suite().test_cases(self.__config.case_rx)[self.__case_index]
        else:
            return None
    
    def current_test_suite(self):
        if self.__suite_index >= 0 and self.__suite_index < len(self.test_plan):
            return self.test_plan[self.__suite_index]
        else:
            return None

    def next_case(self):
        try:
            if self.__suite_index == -1:
                self.__suite_index += 1
                self.__case_index += 1
            elif self.__case_index <= len(self.current_test_suite().test_cases(self.__config.case_rx)) - 2:
                self.__case_index += 1
            else:
                self.__suite_index += 1
                self.__case_index = 0

            if not self.current_test_case() == None:
                attempts = 1
                result = None

                while(True):
                    # pop a message through the UI that we are entering the new
                    # test case
                    self.ui.tell("%s %s/%s" % (attempts == 1 and "Running" or "Retrying", self.current_test_suite().title(), self.current_test_case().title()))
                    # run the actual test case
                    self.__active_case = True
                    result = self.current_test_case()(self.test_network, self.ui).run_case()
                    self.__active_case = False
                    # if the case failed, and we have done less than three attempts
                    # then offer to retry
                    if not result.is_fail() or attempts >= 3:
                        break
                    elif result.is_fail():
                        attempts += 1
                        
                        self.ui.tell("The test case result was %s. Trying again..." % (result.result_string()))
                # if it took more than one attempt, add a note to the message
                if attempts > 1:
                    result.message += " (attempt %d)" % (attempts)
                # add the result to the report
                self.report.append(self.current_test_suite(), self.current_test_case(), result)

                return True
        except KeyboardInterrupt, e:
            self.stop()

    def produce_reports(self):
        for f in self.__config.formatters.values():
            f[0](self.report).format(f[1])
    
    def reset(self):
        self.report = self.__config.build_report()
        self.test_plan = self.__config.test_plan()
        self.test_network = self.__config.build_test_network()
        self.ui = self.__config.ui.callbacks()

        self.__active_case = False
        self.__suite_index = -1
        self.__case_index = -1

    def run(self):
        self.reset()

        while (self.__stop == False and self.next_case()): pass
        
        self.produce_reports()
        self.clean_up()

    def stop(self):
        self.__stop = True

    def test_cases(self):
        c = []

        for suite in self.test_plan:
            c.extend(suite.test_cases(self.__config.case_rx))

        return c
    