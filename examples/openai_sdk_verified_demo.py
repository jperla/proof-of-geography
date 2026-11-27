#!/usr/bin/env python3
"""
End-to-end example using the UNMODIFIED official OpenAI Python SDK against the
Proof of Geography Verified LLM demo (CPU-only Intel TDX Confidential Space).

Demonstrates BOTH:
  1. Stock OpenAI SDK call (`with_raw_response.create`) showing standard usability + receipt headers
     (and honestly stating what a stock SDK has vs. has NOT checked).
  2. Full verified OpenAI SDK call (`PogVerifiedHttpClient`) verifying real TLS 1.3 EKM, live
     Google Confidential Space Intel TDX RS256 OIDC + JWKS, enclave Ed25519 signature, blinded
     request/output commitments, pinned model/weights, and separate PoG geographic proof status
     ON THAT VERY SAME SDK CALL (not a second inference on another session).
"""

import argparse
import json
import sys
from pathlib import Path

from openai import OpenAI

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sdks.python.pog_openai_verifier import PogVerifiedHttpClient


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default="https://llm.proofofgeography.com/v1")
    ap.add_argument("--prompt", default="What is 19 * 23? Answer in one short sentence.")
    ap.add_argument("--expected-image-digest", default=None)
    ap.add_argument("--out-evidence", default=None)
    ap.add_argument("--insecure-local-test", action="store_true")
    args = ap.parse_args()

    print("=== 1. Stock Unmodified Official OpenAI SDK Call ===")
    stock_client = OpenAI(base_url=args.base_url, api_key="pog-public-demo")
    if not args.insecure_local_test:
        raw = stock_client.chat.completions.with_raw_response.create(
            model="qwen2.5-0.5b-instruct-q4_k_m",
            messages=[{"role": "user", "content": args.prompt}],
            max_tokens=48,
            temperature=0.2,
        )
        parsed = raw.parse()
        print("Stock SDK answer:", parsed.choices[0].message.content)
        print("Stock SDK receipt header X-PoG-Receipt-Id:", raw.headers.get("x-pog-receipt-id"))
        print("Stock SDK receipt header X-PoG-Receipt-Sha256:", raw.headers.get("x-pog-receipt-sha256"))
        print(
            "NOTE: A stock SDK checks standard CA TLS only — it does NOT verify TLS 1.3 EKM, "
            "Google Intel TDX OIDC JWKS, blinded commitments, or PoG anchor quorum.\n"
        )

    print("=== 2. Unmodified Official OpenAI SDK + PogVerifiedHttpClient (Same-Call Verification) ===")
    http_client = PogVerifiedHttpClient(
        expected_image_digest=args.expected_image_digest,
        strict=True,
        verify_tls=not args.insecure_local_test,
        allow_dev_tee_local_test=args.insecure_local_test,
    )
    verified_client = OpenAI(
        base_url=args.base_url,
        api_key="pog-public-demo",
        http_client=http_client,
    )
    resp = verified_client.chat.completions.create(
        model="qwen2.5-0.5b-instruct-q4_k_m",
        messages=[{"role": "user", "content": args.prompt}],
        max_tokens=64,
        temperature=0.2,
    )
    print("Verified SDK answer:", resp.choices[0].message.content)
    print("Verification report:", json.dumps(http_client.last_report, indent=2))
    if args.out_evidence and http_client.last_evidence:
        Path(args.out_evidence).write_text(json.dumps(http_client.last_evidence, indent=2))
        print(f"Saved full offline-verifiable evidence bundle to {args.out_evidence}")


if __name__ == "__main__":
    main()
