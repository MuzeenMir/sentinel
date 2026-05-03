VENV := .venv-backend
PYTHON := $(VENV)/bin/python
PIP := $(VENV)/bin/pip

.PHONY: venv deps test-ai-engine test-api-gateway test-shared test-all

venv:
	python3 -m venv $(VENV)

deps: venv
	$(PIP) install --upgrade pip setuptools wheel
	$(PIP) install -r requirements-test.txt -r ai-engine/requirements.txt -r api-gateway/requirements.txt

test-ai-engine: deps
	cd ai-engine && $(PYTHON) -m pytest

test-api-gateway: deps
	cd api-gateway && $(PYTHON) -m pytest

test-shared: deps
	$(PYTHON) -m pytest tests

test-all: test-ai-engine test-api-gateway test-shared

