"""CNC 418 — AI-powered autonomous red-team agent (lab-only).

The package is organised around one safety invariant: no request leaves the
allowlist. Everything else (planning, verification, chaining, reporting) is
built on top of that guarantee.
"""
__version__ = "1.0.0"
