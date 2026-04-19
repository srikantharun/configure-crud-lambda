ENVIRONMENT ?= poc
TERRAFORM_BINARY ?= terraform

# WAF Testing Configuration
WAF_ENDPOINT	 ?= https://juice-shop-alb-1282716061.eu-west-1.elb.amazonaws.com
WAF_LOG_GROUP	 ?= aws-waf-logs-baseline13
AWS_REGION	 ?= eu-west-1
AWS_ACCOUNT_ID	 ?= 976629938830

.DEFAULT_GOAL=help
.PHONY: help
help: ##list available commands
	@echo "----------------------------------"
	@awk -F ':|##' '/^[^\t].+?:.*?##/ {\
	printf "\033[36m%-30s\033[0m %s\n", $$1, $$NF \
	}' $(MAKEFILE_LIST)

.PHONY: init
init: clean ##terraform init
	${TERRAFORM_BINARY} init -reconfigure -backend-config backend_config/${ENVIRONMENT}.tfvars

.PHONY: plan
plan: ##terraform plan
	${TERRAFORM_BINARY} plan -var-file env_vars/${ENVIRONMENT}.tfvars -out=${ENVIRONMENT}.tfplan -no-color

.PHONY: apply
apply: ##terraform apply
	${TERRAFORM_BINARY} apply "${ENVIRONMENT}.tfplan" -no-color

.PHONY: clean
clean: ##delete .terraform direcotry
	rm -rf .terraform

.PHONY: lint
lint: ##Run terraform fmt
	${TERRAFORM_BINARY} fmt -recursive .

# =============================================================================
# WAF Testing
# =============================================================================
.PHONY: test test-install test-clean test-validate test-report test-coverage help

test-install:
	pip install pytest pyyaml pydantic pytest-html pytest-cov

test-clean:
	rm -rf reports/* .pytest_cache tests/.pytest_cache tests/waf/.pytest_cache .coverage htmlcov
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true

test-validate:
	@test -n "$(MODULE)" || (echo "ERROR: MODULE required"; exit 1)
	python -c "import yaml; from pathlib import Path; print('Validating $(MODULE)...')"

test:
	@test -n "$(MODULE)" || (echo "ERROR: MODULE required"; exit 1)
	pytest tests/waf/ -v -s --tb=short --waf-endpoint=$(WAF_ENDPOINT) --waf-log-group=$(WAF_LOG_GROUP) --aws-region=$(AWS_REGION) --account-id=$(AWS_ACCOUNT_ID) --waf-module=$(MODULE)

test-report:
	@test -n "$(MODULE)" || (echo "ERROR: MODULE required"; exit 1)
	@mkdir -p reports
	pytest tests/waf/ -v --waf-endpoint=$(WAF_ENDPOINT) --waf-log-group=$(WAF_LOG_GROUP) --aws-region=$(AWS_REGION) --account-id=$(AWS_ACCOUNT_ID) --waf-module=$(MODULE) --html=reports/$(MODULE).html --junitxml=reports/$(MODULE)_junit.xml

test-coverage:
	@test -n "$(MODULE)" || (echo "ERROR: MODULE required"; exit 1)
	@mkdir -p reports
	pytest tests/waf/ -v --waf-endpoint=$(WAF_ENDPOINT) --waf-log-group=$(WAF_LOG_GROUP) --aws-region=$(AWS_REGION) --account-id=$(AWS_ACCOUNT_ID) --waf-module=$(MODULE) --cov=tests/waf --cov-report=xml:reports/coverage.xml --junitxml=reports/$(MODULE)_junit.xml

help:
	@echo "Terraform:"
	@echo "  make init		Initialize terraform"
	@echo "  make plan		Create terraform plan"
	@echo "  make apply		Apply terraform plan"
	@echo ""
	@echo "WAF Testing:"
	@echo "make test-install	  Install dependencies"
	@echo "make test-clean		  Clean artifacts"
	@echo "make test MODULE=xxx	  Run tests"
	@echo "make test-report MODULE=xxx  Generate report"
