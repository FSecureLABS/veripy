from abstract import Base


class CSVFormatter(Base):

    Separator = ","
    TextDelimeter = "\""


    def format(self, p):
        lines = [self.__format_line(["suite", "case", "optional", "compliance", "message"])]

        for suite in self.report.results():
            for result in suite.results():
                lines.append(self.__format_line([suite.test_suite.title(), result.test_case.title(), result.test_case.is_optional(), result.outcome.result_string(), result.outcome.message]))
        
        self.write_file(p, "\n".join(lines))

    def type(self):
        return "csv"

    def __format_line(self, columns):
        return self.Separator[:].join(map(lambda c: self.TextDelimeter + str(c) + self.TextDelimeter, columns))
        