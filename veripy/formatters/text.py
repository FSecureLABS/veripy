from abstract import Base
from textwrap import wrap
from time import strftime


class TextFormatter(Base):

    BaselineWidth = 80

    def format(self, p):
        report = "%-50s  Produced at %16s\n" % (self.report.title, strftime("%Y-%m-%d %H:%M"))
        report += "%-50s  ----------------------------\n" % self.__underline(self.report.title)
        report += "%18s  %-30s\n" % ("profile", self.report.klass)
        report += "%18s  %-30s"   % ("vendor", self.report.vendor)
        report += "  %-28s\n"     % ("Session Result".center(28))
        report += "%18s  %-30s"   % ("device", self.report.device)
        report += "  %-28s\n"     % ((self.report.is_compliant() and "Compliant" or "Not Compliant").center(28))
        report += "%18s  %-30s\n" % ("notes", self.report.notes)

        for idx, suite_result in enumerate(self.report.results()):
            report += "\n"
            report += "%3d. %-46s  %1s  %-24s\n" % (idx+1, suite_result.test_suite.title(), "", (suite_result.is_compliant() and "Compliant" or "Not Compliant"))
            report += "     %-46s\n" % (self.__underline(suite_result.test_suite.title()))

            for jdx, case_result in enumerate(suite_result.results()):
                title = wrap(case_result.test_case.title(), 41)
                message = case_result.outcome.message != None and wrap(case_result.outcome.message, 24) or []
                
                for kdx in range(0, max(len(title), len(message) + 1)):
                    if kdx == 0:
                        report += "     %3s. %-41s  %1s  %-24s\n" % (jdx+1, title[kdx], case_result.test_case.is_optional() and "*" or "", case_result.outcome.result_string())
                    else:
                        report += "          %-41s     %-24s\n" % (kdx < len(title) and title[kdx] or "", kdx <= len(message) and message[kdx-1] or "")

        self.write_file(p, report)

    def type(self):
        return "text"

    def __underline(self, str):
        return reduce(lambda x,y: x+y, map(lambda x: "-", str))
    