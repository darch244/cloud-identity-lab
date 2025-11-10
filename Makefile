PYTHON       ?= python3
VENV         = .venv
PIP          = $(VENV)/bin/pip
PYTHON_BIN   = $(VENV)/bin/python
PYTEST       = $(VENV)/bin/pytest
RUFF         = $(VENV)/bin/ruff
MYPY         = $(VENV)/bin/mypy

.PHONY: setup lint format format-check typecheck test scan ci all

all: lint test

## Create venv and install pinned requirements
setup:
	$(PYTHON) -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt

## Lint the engine and tests with ruff (zero errors required)
lint:
	$(RUFF) check engine tests

## Auto-format the engine and tests with ruff
format:
	$(RUFF) format engine tests

## Verify formatting without modifying files
format-check:
	$(RUFF) format --check engine tests

## Statically type-check the engine with mypy
typecheck:
	$(MYPY) engine

## Run the unit test suite (offline, mock IAM data)
test:
	$(PYTEST) -q

## Syntax + smoke scan: compile all Python, run the offline mock analyzer,
## and (when terraform is installed) check terraform formatting
scan:
	$(PYTHON_BIN) -m compileall -q engine tests
	$(PYTHON_BIN) -m engine.cli analyze --mock --output markdown >/dev/null
	@command -v terraform >/dev/null 2>&1 && terraform fmt -check -recursive \
		|| echo "terraform not on PATH - skipped terraform fmt check"

## Full gate: syntax/lint/format/type/go-tests
ci: scan lint format-check typecheck test