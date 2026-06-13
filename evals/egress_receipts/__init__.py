"""Signet-side recorder that emits golden egress receipts in the published wire format
(`verify/RECEIPT_FORMAT.md`). This package MAY import Signet — it is the runtime side that
produces the artifact. The verifier (`verify/verify.py`) is the clean-room consumer and imports
none of this."""
