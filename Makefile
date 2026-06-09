# Signet Runtime — convenience targets.
# The scorecard is the one-command "is the spec still holding?" report.

PY ?= python3

.PHONY: test proof scorecard scorecard-live scorecard-baseline demo demo-serve

test:                       ## run the deterministic CI suite (the spec)
	$(PY) -m pytest -q

proof:                      ## structural proof that writing a rail is two functions
	$(PY) -m demos.two_functions_proof

demo:                       ## rebuild the static demo into docs/ from the unmodified kernel
	$(PY) -m demos.build_demo

demo-serve:                 ## rebuild and serve the demo locally at http://localhost:8000
	$(PY) -m demos.build_demo && cd docs && $(PY) -m http.server

scorecard:                  ## offline scorecard: pytest + replay containment + architecture (no LLM)
	$(PY) -m evals.scorecard

scorecard-live:             ## + per-model live rows (needs OPENAI_API_KEY); MODELS=... K=... to override
	$(PY) -m evals.scorecard --live $(if $(MODELS),--models $(MODELS),) $(if $(K),--k $(K),)

scorecard-baseline:         ## repin the kernel-edit baseline (deliberate, reviewed kernel changes only)
	$(PY) -m evals.scorecard --update-kernel-baseline
