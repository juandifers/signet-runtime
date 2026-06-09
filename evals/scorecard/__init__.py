"""Signet scorecard — one command that runs the full test surface and emits a committed report
split into INVARIANTS (binary; any deviation is a bug that FAILS the scorecard) and MEASUREMENTS
(model/corpus-dependent trends; watch the drift). See `evals/scorecard/__main__.py`.

Public surface used by tests:
  architecture.kernel_edit_check / architecture.loc_metrics
  collect.pytest_buckets / collect.replay_containment
  grade.assemble / grade.diff_against_prior
"""
