# Signet Runtime — convenience targets.
# The scorecard is the one-command "is the spec still holding?" report.

PY ?= python3

.PHONY: test scorecard scorecard-live scorecard-baseline

test:                       ## run the deterministic CI suite (the spec)
	$(PY) -m pytest -q

scorecard:                  ## offline scorecard: pytest + replay containment + architecture (no LLM)
	$(PY) -m evals.scorecard

scorecard-live:             ## + per-model live rows (needs OPENAI_API_KEY); MODELS=... K=... to override
	$(PY) -m evals.scorecard --live $(if $(MODELS),--models $(MODELS),) $(if $(K),--k $(K),)

scorecard-baseline:         ## repin the kernel-edit baseline (deliberate, reviewed kernel changes only)
	$(PY) -m evals.scorecard --update-kernel-baseline
