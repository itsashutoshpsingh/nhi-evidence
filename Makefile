# One command per step. `make reproduce` rebuilds every committed result from the code in this repository.
PY ?= .venv/bin/python

.PHONY: setup refs fixtures test lint seeded mutants scale cost ablation lab figures summary reproduce

setup:            ## pinned environment from uv.lock
	uv sync --frozen

refs:             ## reference data from pinned Microsoft Graph, Entra and OWASP doc commits (network)
	$(PY) scripts/fetch_refs.py

fixtures:         ## clean and seeded fixture tenants
	$(PY) fixtures/seeded.py

test:
	$(PY) -m pytest -q

lint:
	$(PY) -m ruff check .

seeded:           ## seeded, clean, each issue alone, 51 mutations, report, paths
	$(PY) experiments/eval_seeded.py

mutants:          ## code mutation testing (~2 minutes, two interpreters at a time)
	$(PY) experiments/code_mutants.py

scale:            ## 18 synthetic tenants, 100 to 100,000 service principals (~1 minute, peak ~0.7 GB)
	$(PY) experiments/scale.py

cost:             ## collector against the Graph mock
	$(PY) experiments/collect_cost.py

ablation:
	$(PY) experiments/ablation.py

lab:              ## replay the live seeding plan against a simulated Graph
	$(PY) lab/simulate.py

figures:
	$(PY) experiments/figures.py

summary:
	$(PY) experiments/summary.py

reproduce: fixtures test seeded mutants scale cost ablation lab figures summary
