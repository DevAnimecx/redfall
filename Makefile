SHELL := /bin/bash
TARGET ?= range/vulnbank
SCAN_OUT ?= scan.json
GATE_OUT ?= range/report.json
PY ?= python3

.PHONY: help install check check-no-mock check-version check-orphans check-clean-tree test \
        range-up range-down range-test range-pocs range-chains range-patches \
        range-python-test range-python-pocs manifests gate scan \
        doctor dashboard web-install web-build up

help:
	@echo "Redfall 0.1.1"
	@echo
	@echo "  make install          install redfall + range-runner (editable, with dev deps)"
	@echo "  make check            every contract checker plus the test suite"
	@echo "  make check-no-mock    scripts/check_no_mock.py (§1/§2 contract)"
	@echo "  make check-version    scripts/check_version.py (rule 21)"
	@echo "  make check-orphans    scripts/check_orphans.py (rule 24)"
	@echo "  make check-clean-tree scripts/check_clean_tree.py (rule 22)"
	@echo "  make test             pytest suite (367 tests)"
	@echo "  make doctor           prerequisite report"
	@echo
	@echo "  make range-up         start $(TARGET)"
	@echo "  make range-down       stop it"
	@echo "  make range-test       run the target's own test suite"
	@echo "  make range-pocs       replay every PoC against the running target"
	@echo "  make range-chains     replay every chainbank chain, step by step"
	@echo "  make range-patches    verify all 32 known-good vulnbank patches"
	@echo "  make range-python-test pythonbank's own pytest suite"
	@echo "  make range-python-pocs replay all 17 pythonbank PoCs (boots the target)"
	@echo
	@echo "  Targets: range/vulnbank (:4000)  range/vulnbank-adaptive (:4001)"
	@echo "           range/chainbank (:4002)  range/pythonbank (:4003)"
	@echo
	@echo "  make scan            redfall scan (needs gVisor + an LLM key)"
	@echo "  make gate            range-runner gate over $(SCAN_OUT)"
	@echo
	@echo "  make web-install     install dashboard dependencies"
	@echo "  make web-build       build the Next.js dashboard"
	@echo "  make dashboard       serve the built dashboard on :3000"

install:
	pip3 install -e ".[dev]"
	pip3 install -e range

check: check-no-mock check-version check-orphans check-clean-tree test

check-no-mock:
	$(PY) scripts/check_no_mock.py

check-version:
	$(PY) scripts/check_version.py

check-orphans:
	$(PY) scripts/check_orphans.py

check-clean-tree:
	$(PY) scripts/check_clean_tree.py

test:
	$(PY) -m pytest tests/ -q

doctor:
	redfall doctor

# ---- the range -------------------------------------------------------------
range-up:
	cd $(TARGET) && ./scripts/run_local.sh start

range-down:
	cd $(TARGET) && ./scripts/run_local.sh stop

range-test:
	cd $(TARGET) && npm test

range-pocs:
	cd $(TARGET) && npx ts-node scripts/replay_poc.ts --all

range-patches:
	cd $(TARGET) && ./scripts/verify_patches.sh

# pythonbank is Python-native: the target's own pytest suite and a replay
# script that boots it on :4003, replays all 16 PoCs over real HTTP and stops it.
range-python-test:
	cd range/pythonbank && $(PY) -m pytest tests/ -q -p no:cacheprovider

range-python-pocs:
	cd range/pythonbank && $(PY) scripts/replay_poc.py --all

# chainbank only: replays each chain in order, substituting the values the
# previous step actually produced.
range-chains:
	cd range/chainbank && npx ts-node scripts/replay_chain_poc.ts

# Regenerate the manifests. They are derived, never hand-edited.
manifests:
	cd range/vulnbank-adaptive && $(PY) scripts/write_manifest.py
	cd range/chainbank && $(PY) scripts/write_manifest.py
	cd range/pythonbank && $(PY) scripts/write_manifest.py

# ---- redfall ---------------------------------------------------------------
scan:
	redfall scan $(TARGET) --out $(SCAN_OUT)

gate:
	$(PY) -m range_runner.run --target $(TARGET) --scan $(SCAN_OUT) --out $(GATE_OUT)

web-install:
	cd web && npm install --no-audit --no-fund

web-build:
	cd web && npm run build

dashboard:
	cd web && npm run start

# ---- deliberately refused --------------------------------------------------
# `docker compose up` needs a container runtime. This host has none, and the
# gVisor sandbox refuses to fall back, so this target says so instead of
# pretending. See BLOCKED.md.
up:
	@echo "BLOCKED: no container runtime on this host (no docker CLI, no /var/run/docker.sock)." >&2
	@echo "The gVisor sandbox has no fallback execution path. See BLOCKED.md." >&2
	@exit 1
