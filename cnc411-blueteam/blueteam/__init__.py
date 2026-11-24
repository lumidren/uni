"""CNC 411 — vendor-agnostic AI-augmented Blue Team defence pipeline.

Pipeline: normalise -> detect (ML + XAI) -> triage (explain, MITRE map) ->
contain (vendor-neutral SOAR) -> incident (MTTD/MTTC/MTTR) -> publish to GRC.
"""
__version__ = "1.0.0"
