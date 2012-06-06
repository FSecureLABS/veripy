from inspect import isclass
from veripy.exceptions import *
from veripy.models.compliance_test_cases import ComplianceTestCase


class ComplianceTestSuite(object):

    __suites = {}

    @classmethod
    def all(cls):
        return cls.__suites.keys()
    
    @classmethod
    def clear(cls):
        cls.__suites = {}

    @classmethod
    def get(cls, id):
        try:
            return cls.__suites[id]
        except KeyError:
            raise UnknownComplianceTestSuiteError(id)
    
    @classmethod
    def register(cls, id, suite):
        if isclass(suite) and issubclass(suite, ComplianceTestSuite):
            if id in cls.__suites.keys():
                raise DuplicateComplianceTestSuiteIdentifier(id)
            elif suite in cls.__suites.values():
                raise DuplicateComplianceTestSuite(suite)
            else:
                cls.__suites[id] = suite
        else:
            raise InvalidComplianceTestSuiteError(suite)

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
    def test_cases(cls, case_rx=None):
        return filter(lambda c: isclass(c) and issubclass(c, ComplianceTestCase) and "TestCase" in c.__name__ and (case_rx == None or c.title().lower().find(case_rx.lower()) >= 0), map(lambda c: getattr(cls, c), dir(cls)))

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
    
    def __iter__(self):
        for case in self.__class__.test_cases():
            yield case
