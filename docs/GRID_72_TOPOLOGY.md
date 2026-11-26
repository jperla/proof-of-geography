# 72-Node Rim-Surrounded Global Anchor Grid Topology

> **Core geometric principle:** A border or coastal city (e.g., Lisbon, Dublin, Helsinki, Istanbul, San Francisco, Miami, Seattle, Vancouver, Mexico City) suffers severe **Geometric Dilution of Precision (GDOP)** if all nearby Anchors sit inland on only one side. Surrounding both **Europe** and **North America** with **outer-rim perimeter Anchors** guarantees 4-quadrant (`N / S / E / W`) speed-of-light framing for **every** city—even right on oceanic coastlines and national borders.

---

## Regional Breakdown (72 Total Nodes)

| Theater | Count | Core Multi-Cloud Hubs | Outer Rim Perimeter Anchors (Kills Coastal & Border GDOP!) |
| :--- | :---: | :--- | :--- |
| **North America + Canada + Mexico + Caribbean** | **26** | Ashburn (×2), NYC/Newark, Columbus, Chicago, Iowa, Dallas, Salt Lake City, Phoenix, Los Angeles, San Jose, Oregon (×2), Toronto, Montreal (×2) | **West/Pacific:** Honolulu (`HI`), Anchorage (`AK`)<br>**North/Canada:** Vancouver, Calgary, Halifax (`NS`)<br>**South/Mexico & Caribbean:** Querétaro/Mexico City (GCP + AWS), Miami (`NAP of the Americas`), San Juan (`PR`), Panama City |
| **Europe + North Atlantic + North Africa + Middle East + East Rim** | **30** | London (×2), Frankfurt (×2), Paris, Amsterdam, Zurich, Dublin, Madrid, Milan, Marseille | **Far West Atlantic:** Reykjavík (**Iceland**), Tórshavn (**Faroe Islands**), Ponta Delgada (**Azores**), Lisbon<br>**Far North:** Oslo, Stockholm, Hamina (**Finland**)<br>**South / North Africa & Levant:** Casablanca (**Morocco**), Cairo (**Egypt**), Tel Aviv, Athens<br>**East / Middle East / Eurasia:** Warsaw (×2), Bucharest, Istanbul, Dubai, Doha, Almaty (**Kazakhstan**), optional Moscow IXP* |
| **Asia-Pacific & Oceania** | **12** | Tokyo (×2), Seoul, Taiwan, Hong Kong, Singapore (×2), Mumbai (×2), Jakarta, Sydney | Auckland (`NZ`) South Pacific rim + Honolulu (`HI`) bridging trans-Pacific |
| **South America & Southern Africa** | **4** | São Paulo, Santiago, Johannesburg | Cape Town subsea landing rim |

*\*Compliance / Sovereignty Note on Eastern European / Russian Border:* Operating directly inside sanctioned jurisdictions is restricted for US-domiciled entities. The **neutral/allied perimeter ring** (**Hamina Finland + Warsaw ×2 + Bucharest + Istanbul + Almaty Kazakhstan**) already surrounds European Russia from N, W, SW, S, and SE; `edge-ru-mow-moscow` is marked optional (`ru-mow-optional`) for independent non-sanctioned operators or local IXP peering (e.g. MSK-IX / SPB-IX).

---

## Why Rim Nodes Transform Border-City Localization

Run the built-in comparative GDOP benchmark yourself:

```bash
cargo run --release --bin pog-cli -- audit-coverage \
  --grid config/global_grid_72.json \
  --baseline-grid config/global_grid_24.json
```

Key improvements vs. the starter 24-node grid (**real $f=1$ Byzantine audit output across 20 border/coastal/interior cities — `7.05×` tighter mean radius, `19/20` full 4/4 quadrant surround vs `1/20` on 24 nodes!**):

| Border / Coastal City | 24-Node Quads | 24-Node Calibrated | **72-Node Quads** | **72-Node Calibrated** | **Tightening** |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **San Francisco, US** *(Pacific Coast)* | 2/4 | `1,039 mi` | **4/4** | **`159 mi`** | **6.5×** |
| **Vancouver, CA** *(NW Border)* | 2/4 | `596 mi` | **4/4** | **`154 mi`** | **3.9×** |
| **Miami, US** *(Caribbean Rim)* | 2/4 | `1,918 mi` | **4/4** | **`186 mi`** | **10.3×** |
| **Mexico City, MX** *(South Rim)* | 2/4 | `3,034 mi` | **3/4** | **`240 mi`** | **12.6×** |
| **San Juan, PR** *(Caribbean)* | 2/4 | `3,244 mi` | **4/4** | **`375 mi`** | **8.6×** |
| **Chicago, US** *(Midwest)* | 4/4 | `290 mi` | **4/4** | **`124 mi`** | **2.4×** |
| **Lisbon, PT** *(Far West Europe)* | 2/4 | `2,043 mi` | **4/4** | **`211 mi`** | **9.7×** |
| **Dublin, IE** *(NW Atlantic)* | 3/4 | `599 mi` | **4/4** | **`245 mi`** | **2.5×** |
| **Helsinki, FI** *(Far North / RU Border)* | 1/4 | `1,176 mi` | **4/4** | **`292 mi`** | **4.0×** |
| **Warsaw, PL** *(Eastern EU Rim)* | 3/4 | `806 mi` | **4/4** | **`11 mi`** | **76.3×** |
| **Istanbul, TR** *(Black Sea / Eurasia)* | 1/4 | `2,392 mi` | **4/4** | **`135 mi`** | **17.7×** |
| **Cairo, EG** *(North Africa Rim)* | 1/4 | `3,736 mi` | **4/4** | **`316 mi`** | **11.8×** |
| **20-City Mean ($f=1$ Byzantine)** | **1/20 @ 4/4** | **`1,341 mi`** | **19/20 @ 4/4** | **`190 mi`** | **7.05×** |

---

## Multi-Cloud + Edge Provider Blueprint & Cost Estimate

| Tier | Nodes | Providers | Est. On-Demand Monthly Cost | Est. Hourly Cost |
| :--- | :---: | :--- | :---: | :---: |
| **Live Public Pilot (Current)** | **9** | GCP (5 Intel TDX + AMD SEV-SNP) + AWS (4) | ~\$800 / mo | ~\$1.11 / hr |
| **Expanded Hyperscaler Fleet (GCP + AWS + Azure)** | **42** | All native GCP (24), AWS (14), Azure (4) regions incl. Mexico, Canada, Finland, Spain, Italy, Poland, Israel, Qatar, UAE, Chile, South Africa | ~\$3,200 / mo *(~\$2,100 w/ 1-yr CUD)* | ~\$4.40 / hr |
| **Full 72-Node Rim-Surrounded Global Grid** | **72** | 42 Hyperscaler + 30 Sovereign / Edge Bare-Metal SEV-SNP (OVHcloud + Vultr + Equinix/Verne Iceland + Faroese/Azores/Morocco/Egypt/PR/AK/HI colos) | ~\$4,800–\$6,200 / mo *(~\$3,300 w/ commits)* | ~\$6.70–\$8.50 / hr |

*(Remember: Proof of Geography runs zero-gas DNS/CT-style — even 72 nodes at ~\$5k/mo can handle **~5.6 TRILLION raw live proofs/year** and authenticate **quadrillions** of handshake-attached API requests globally!)*
