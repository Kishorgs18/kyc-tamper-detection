"""KYC document tamper-detection — local-only forensic flagger.

Pipeline: ingest -> detectors -> aggregator -> router -> report.
No-data design: emits human-review evidence, not automated verdicts.
"""

__version__ = "0.1.0"
