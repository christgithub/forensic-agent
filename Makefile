.PHONY: start stop status e2e_tests e2e_test_archiver e2e_tests_windows unit_tests help

PYTHON := python3
MAIN := main.py
PID_FILE := .service.pid

help:
	@echo "Available commands:"
	@echo "  make start               - Start the forensic agent service"
	@echo "  make stop                - Stop the forensic agent service"
	@echo "  make status              - Check if the service is running"
	@echo "  make e2e_tests_linux           - Run all end-to-end tests (Linux container)"
	@echo "  make e2e_tests_windows   - Run end-to-end tests (Windows artefacts)"
	@echo "  make unit_tests          - Run all unit tests"
	@echo "  make help                - Show this help message"

start:
	@if [ -f $(PID_FILE) ]; then \
		echo "Service is already running (PID: $$(cat $(PID_FILE)))"; \
	else \
		echo "Starting forensic agent service..."; \
		nohup $(PYTHON) $(MAIN) > service.log 2>&1 & echo $$! > $(PID_FILE); \
		echo "Service started (PID: $$(cat $(PID_FILE)))"; \
	fi

stop:
	@if [ -f $(PID_FILE) ]; then \
		echo "Stopping forensic agent service (PID: $$(cat $(PID_FILE)))..."; \
		kill $$(cat $(PID_FILE)) 2>/dev/null || echo "Process not found"; \
		rm -f $(PID_FILE); \
		echo "Service stopped"; \
	else \
		echo "Service is not running"; \
	fi

status:
	@if [ -f $(PID_FILE) ]; then \
		if ps -p $$(cat $(PID_FILE)) > /dev/null 2>&1; then \
			echo "Service is running (PID: $$(cat $(PID_FILE)))"; \
		else \
			echo "PID file exists but process is not running"; \
			rm -f $(PID_FILE); \
		fi \
	else \
		echo "Service is not running"; \
	fi

e2e_tests_linux:
	@echo "Running end-to-end tests in Docker (Linux)..."
	@docker build -f Dockerfile.test -t forensic-agent-test .
	@docker rm -f forensic-agent-e2e 2>/dev/null || true
	@docker run -d --name forensic-agent-e2e -e PYTHONUNBUFFERED=1 forensic-agent-test \
		sh -c "python E2E/test_e2e.py; tail -f /dev/null"
	@echo "Container 'forensic-agent-e2e' is running. Stream logs with: docker logs -f forensic-agent-e2e"

e2e_tests_windows:
	@echo "Running Windows artefacts end-to-end tests in Docker..."
	@echo "(Uses linux/amd64 image locally. Swap FROM in Dockerfile.test.windows for"
	@echo " python:3.11-windowsservercore-ltsc2022 on a Windows CI runner for a true Windows container.)"
	@docker build -f Dockerfile.test.windows -t forensic-agent-test-windows .
	@docker rm -f forensic-agent-e2e-windows 2>/dev/null || true
	@docker run -d --name forensic-agent-e2e-windows -e PYTHONUNBUFFERED=1 forensic-agent-test-windows \
		sh -c "python E2E/test_e2e_windows.py; tail -f /dev/null"
	@echo "Container 'forensic-agent-e2e-windows' is running. Stream logs with: docker logs -f forensic-agent-e2e-windows"

unit_tests:
	@echo "Running unit tests..."
	@$(PYTHON) -m pytest -v EvidenceIngester/test_scanner.py ArtefactAnalysis/test_identifier.py ArtefactAnalysis/test_archiver.py IntegrityChecker/test_hasher.py
