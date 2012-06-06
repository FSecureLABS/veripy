
all:			help

help:
	@echo "veripy Makefile"
	@echo "---------------"
	@echo ""
	@echo "This Makefile is intended to support a developer working on the veripy tool. It"
	@echo "provides a number of utility functions for running test cases and managing the."
	@echo "source code."
	@echo ""
	@echo "Commands:"
	@echo "                 clean  remove all generated files"
	@echo "               release  build a release package, from the last tagged version"
	@echo ""
	@echo "                  test  run all test cases"
	@echo "            unit-tests  run all unit test cases"
	@echo "     integration-tests  run all integration test cases"
	@echo "           suite-tests  run all compliance suite test cases"
	@echo ""
	@echo "                  help  display this usage information"

clean:
	find . -name "*.pyc" -exec rm '{}' ';'
	rm -rf tmp/*

test:			unit-tests integration-tests suite-tests
unit-tests:
	-nosetests tests/unit/*.py tests/unit/*/*.py
integration-tests:
	-nosetests tests/integration/*.py
suite-tests:
	-nosetests contrib/*/tests/*.py 2>&1

release:
	-./scripts/package.sh