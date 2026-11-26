#!/usr/bin/env python3
"""Collect hardware-attested public keys from all live deployed PoG Anchors into config/global_grid_live.json."""

import json
import pathlib
import sys
import urllib.request


def main() -> None:
    if len(sys.argv) < 3:
        print("Usage: collect_registry.py <terraform-outputs.json> <template-grid.json> [out.json]")
        sys.exit(1)

    tf_out = json.loads(pathlib.Path(sys.argv[1]).read_text())
    grid = json.loads(pathlib.Path(sys.argv[2]).read_text())
    out_path = pathlib.Path(sys.argv[3]) if len(sys.argv) > 3 else pathlib.Path("config/global_grid_live.json")

    ip_map: dict[str, str] = {}
    for k, v in tf_out.get("gcp_anchor_endpoints", {}).get("value", {}).items():
        ip_map[k] = v["public_ip"]
    for k, v in tf_out.get("azure_anchor_endpoints", {}).get("value", {}).items():
        ip_map[k] = v["public_ip"]
    for k, ip in tf_out.get("aws_anchor_endpoints", {}).get("value", {}).items():
        ip_map[k] = ip

    live_anchors = []
    for a in grid["anchors"]:
        aid = a["anchor_id"]
        if aid not in ip_map:
            continue
        ip = ip_map[aid]
        url = f"http://{ip}:7445/info"
        try:
            with urllib.request.urlopen(url, timeout=8) as resp:
                info = json.loads(resp.read().decode("utf-8"))
            a["endpoint_tcp"] = f"{ip}:7443"
            a["endpoint_udp"] = f"{ip}:7444"
            a["public_key_hex"] = info["public_key_hex"]
            live_anchors.append(a)
            print(f"[OK] {aid} ({ip}) -> pk={info['public_key_hex'][:16]}… tee={info['tee_vendor']}")
        except Exception as e:
            print(f"[WARN] Could not reach {aid} at {url}: {e}")

    grid["grid_name"] = "pog-global-live"
    grid["anchors"] = live_anchors
    out_path.write_text(json.dumps(grid, indent=2))
    print(f"Wrote {len(live_anchors)} live attested Anchors to {out_path}")


if __name__ == "__main__":
    main()
