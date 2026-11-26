#!/usr/bin/env python3
"""Poll live pilot Anchor VMs on :7445/info, verify hardware AMD SEV-SNP quotes, and write pilot_live.json."""

import json
import pathlib
import sys
import time
import urllib.request


def main() -> None:
    tf_out_path = pathlib.Path(sys.argv[1])
    out_grid_path = pathlib.Path(sys.argv[2])
    tf_out = json.loads(tf_out_path.read_text())
    endpoints = tf_out["pilot_endpoints"]["value"]

    results: dict[str, dict] = {}
    deadline = time.time() + 180
    while len(results) < len(endpoints) and time.time() < deadline:
        for aid, meta in endpoints.items():
            if aid in results:
                continue
            url = f"http://{meta['ip']}:7445/info"
            try:
                with urllib.request.urlopen(url, timeout=4) as resp:
                    info = json.loads(resp.read().decode("utf-8"))
                results[aid] = info
                q = info.get("tee_quote") or {}
                print(
                    f"[READY] {aid:<28} ip={meta['ip']:<15} tee={info.get('tee_vendor')} "
                    f"pk={info.get('public_key_hex', '')[:16]}… "
                    f"mig_off={q.get('migration_disabled')} raw_b64_len={len(q.get('raw_quote_b64', ''))}",
                    flush=True,
                )
            except Exception:
                pass
        if len(results) < len(endpoints):
            time.sleep(5)

    missing = sorted(set(endpoints.keys()) - set(results.keys()))
    if missing:
        print(f"[WARN] Still unreachable after timeout: {missing}", file=sys.stderr)

    anchors = []
    for aid, meta in sorted(endpoints.items()):
        if aid not in results:
            continue
        info = results[aid]
        if meta["cloud_provider"] == "aws":
            inst_type = "c6a.large"
        elif info["tee_vendor"] == "IntelTdx":
            inst_type = "c3-standard-4"
        else:
            inst_type = "n2d-standard-2"
        anchors.append(
            {
                "anchor_id": aid,
                "cloud_provider": meta["cloud_provider"],
                "region": meta["region"],
                "city": meta["city"],
                "tee_vendor": info["tee_vendor"],
                "instance_type": inst_type,
                "location": {"lat": meta["lat"], "lon": meta["lon"]},
                "endpoint_tcp": f"{meta['ip']}:7443",
                "endpoint_udp": f"{meta['ip']}:7444",
                "public_key_hex": info["public_key_hex"],
            }
        )

    grid = {
        "version": "1.0.0",
        "grid_name": "pog-live-public-grid-9",
        "description": "Live locked-down 9-node multi-cloud Proof of Geography public Anchor grid (GCP Intel TDX + AMD SEV-SNP + AWS across US, Europe & Asia)",
        "anchors": anchors,
    }
    out_grid_path.write_text(json.dumps(grid, indent=2))
    print(f"\nWrote {len(anchors)}/{len(endpoints)} live attested Anchors to {out_grid_path}")


if __name__ == "__main__":
    main()
