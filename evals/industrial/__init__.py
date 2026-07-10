"""Simulated multi-agent industrial IT/OT scenario (Track B / V2).

A deterministic, ground-truth-labeled maintenance/operations workflow used to
*measure* whether AIRE surfaces the internal-channel conditions an output-only
audit structurally cannot see — in an industrial IT/OT dressing.

Why deterministic (scripted events, not live LLM calls): measuring true/false
positives for the systems paper requires known ground truth and reproducible
runs. The V1 live validation already confirmed the collector captures real SDK
objects; this layer measures the *detection* pipeline against planted, labeled
conditions.

Everything here is synthetic — no real personal data, no secrets, no company
names. The domain is described generically (industrial IT/OT: asset telemetry,
control setpoints, maintenance logs, clearance tiers).
"""
