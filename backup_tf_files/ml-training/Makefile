REPORTS_DIR ?= ../reports
OUTPUT_DIR ?= output

.PHONY: install train train-single compare clean help

install:
	pip install -r requirements.txt

## Train on all JSON reports in reports/ directory
train:
	@test -d "$(REPORTS_DIR)" || (echo "ERROR: Reports dir not found: $(REPORTS_DIR)"; exit 1)
	python flow.py --reports-dir $(REPORTS_DIR) --output-dir $(OUTPUT_DIR)

## Train on a single policy version JSON
train-single:
	@test -n "$(REPORT)" || (echo "ERROR: REPORT required. Example: make train-single REPORT=../reports/test_custom_v3.json"; exit 1)
	python flow.py --report-file $(REPORT) --output-dir $(OUTPUT_DIR)

## Compare multiple policy versions
compare:
	@test -n "$(FILES)" || (echo "ERROR: FILES required. Example: make compare FILES='../reports/v1.json ../reports/v2.json ../reports/v3.json'"; exit 1)
	python flow.py --compare $(FILES) --output-dir $(OUTPUT_DIR)

clean:
	rm -rf output/* __pycache__ .prefect

help:
	@echo "WAF ML Training Pipeline"
	@echo "========================"
	@echo ""
	@echo "  make install                          Install dependencies"
	@echo "  make train                            Train on all reports in reports/"
	@echo "  make train-single REPORT=path.json    Train on a single report"
	@echo "  make compare FILES='v1.json v2.json'  Compare policy versions"
	@echo "  make clean                            Clean output"
	@echo ""
	@echo "Workflow:"
	@echo "  1. cd .. && make test-json MODULE=test_custom_v3"
	@echo "  2. cd ml-training && make train-single REPORT=../reports/test_custom_v3.json"
	@echo "  3. cat output/quality_test_custom_v3.json"
	@echo ""
	@echo "Compare versions:"
	@echo "  make compare FILES='../reports/v1.json ../reports/v2.json ../reports/v3.json'"
