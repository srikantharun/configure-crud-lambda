REPORTS_DIR ?= ../reports
OUTPUT_DIR ?= output

CF_LOG_GROUP ?= aws-waf-logs-baseline13
CF_REGION ?= us-east-1
ALB_LOG_GROUP ?= aws-waf-logs-wpb-jenkins
ALB_REGION ?= eu-west-1

# Default run date (override with: make comparison RUN_DATE=20260521)
RUN_DATE ?= 20260521

# Self-contained virtualenv - no `source ... activate` needed
VENV := mltest
PY   := $(VENV)/bin/python3
PIP  := $(VENV)/bin/pip

.PHONY: install validate validate-sample build-xlsx comparison clean help

## Create the mltest venv (if needed) and install requirements into it
install:
	@test -d $(VENV) || python3 -m venv $(VENV)
	$(PIP) install --quiet --upgrade pip
	$(PIP) install --quiet -r requirements.txt
	@echo "venv ready at $(VENV)/ - other targets will use it automatically"

## Run pytest tests and collect WAF evidence into JSON
validate:
	@test -x $(PY) || (echo "ERROR: run 'make install' first"; exit 1)
	@test -n "$(REPORT)" || (echo "ERROR: REPORT required (path to test_*.json)"; exit 1)
	$(PY) validate.py --report-file $(REPORT) \
		--cf-log-group $(CF_LOG_GROUP) --cf-region $(CF_REGION) \
		--alb-log-group $(ALB_LOG_GROUP) --alb-region $(ALB_REGION) \
		--output-dir $(OUTPUT_DIR)

## Validate failures + 20 random passes
validate-sample:
	@test -x $(PY) || (echo "ERROR: run 'make install' first"; exit 1)
	@test -n "$(REPORT)" || (echo "ERROR: REPORT required"; exit 1)
	$(PY) validate.py --report-file $(REPORT) \
		--cf-log-group $(CF_LOG_GROUP) --cf-region $(CF_REGION) \
		--alb-log-group $(ALB_LOG_GROUP) --alb-region $(ALB_REGION) \
		--output-dir $(OUTPUT_DIR) --sample 20

## Convert validate.py JSONs in runs/<date>_run/ to per-(policy, placement) XLSXs in runs/
build-xlsx:
	@test -x $(PY) || (echo "ERROR: run 'make install' first"; exit 1)
	$(PY) build_xlsx.py --date $(RUN_DATE)

## Manager-facing pivot - one workbook across 1.1 / 1.3 / 1.3b with formulas
comparison:
	@test -x $(PY) || (echo "ERROR: run 'make install' first"; exit 1)
	$(PY) build_comparison.py --date $(RUN_DATE)

clean:
	rm -rf $(OUTPUT_DIR)/* __pycache__

help:
	@echo "WAF baseline analytics"
	@echo "======================"
	@echo ""
	@echo "Setup"
	@echo "  make install                       Create $(VENV)/ venv + install deps"
	@echo ""
	@echo "Test execution"
	@echo "  make validate REPORT=path.json     Run tests, collect CF+ALB WAF evidence"
	@echo "  make validate-sample REPORT=...    Same, but only failures + 20 random passes"
	@echo ""
	@echo "Reporting (run after dropping JSONs in runs/<date>_run/)"
	@echo "  make build-xlsx RUN_DATE=YYYYMMDD  Per-(policy, placement) XLSXs"
	@echo "  make comparison RUN_DATE=YYYYMMDD  Manager-facing pivot workbook with formulas"
	@echo ""
	@echo "Typical workflow:"
	@echo "  1. make install"
	@echo "  2. Drop validate_baseline_*.json files in runs/<date>_run/"
	@echo "  3. make comparison RUN_DATE=YYYYMMDD"
	@echo "  4. Open runs/comparison_1.1_vs_1.3_vs_1.3b_FORMULAS_FIXED_YYYYMMDD.xlsx"
	@echo ""
	@echo "  make clean                         Remove output files"
