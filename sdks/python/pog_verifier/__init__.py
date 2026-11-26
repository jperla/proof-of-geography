"""Proof of Geography (PoG) offline verifier SDK for Python."""

from .verifier import (
    C_FIBER_KM_PER_S,
    C_VACUUM_KM_PER_S,
    EARTH_RADIUS_KM,
    HTTP_HEADER_POG_PROOF,
    CoreResult,
    VerificationPolicy,
    VerificationReport,
    decode_proof_header,
    receipt_signing_digest,
    verify_proof,
)

__all__ = [
    "C_FIBER_KM_PER_S",
    "C_VACUUM_KM_PER_S",
    "EARTH_RADIUS_KM",
    "HTTP_HEADER_POG_PROOF",
    "CoreResult",
    "VerificationPolicy",
    "VerificationReport",
    "decode_proof_header",
    "receipt_signing_digest",
    "verify_proof",
]
