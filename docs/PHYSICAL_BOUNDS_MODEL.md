# Proof of Geography — Physical Outer Bounds, Timing Margins & Empirical Estimation Model

This document specifies the **exact physical assumptions** behind Proof of Geography's conservative outer bounds (`Tier 1A Vacuum c₀` and `Tier 1B Fiber`), contrasts **same-clock RTT + Sagnac** against **one-way** and **satellite** assumptions, and cleanly separates the hard physical outer bound from the empirical spatial likelihood estimate.

---

## 1. Hard Physical Outer Bound (`Tier 1A Vacuum c₀`)

### Exact Equation (Zero Empirical Speed, Zero Delay Subtraction)

Given an Anchor's measured round-trip time $t_{\text{RTT}}$ (from its own single local monotonic clock), conservative timing resolution margin $\delta t_{\text{clk}}$, local oscillator frequency-slew bound $\epsilon_{\text{slew}}$, and separately audited Anchor coordinate uncertainty $u_{\text{coord}}$:

1. **Conservative upper-bound propagation time:**
   $$t_{\text{upper}} = (t_{\text{RTT}} + \delta t_{\text{clk}})\,(1 + \epsilon_{\text{slew}})$$
   - Datacenter UDP default: $\delta t_{\text{clk}} = 50\,\mu\text{s}$, $\epsilon_{\text{slew}} = 500\,\text{ppm}$.
   - Browser HTTPS default: $\delta t_{\text{clk}} = 1{,}000\,\mu\text{s}$ (`1.0 ms`), $\epsilon_{\text{slew}} = 500\,\text{ppm}$.
   - **Invariant:** Processing time, queuing, last-mile overhead, and empirical RTT intercepts are **NEVER subtracted** from $t_{\text{RTT}}$. Empirical corridor speeds are **NEVER used** in `Tier 1A Vacuum`.

2. **One-way straight-line vacuum chord length:**
   $$L = \frac{1}{2}\, c_0 \, t_{\text{upper}}, \qquad c_0 = 299{,}792.458\;\text{km/s}$$

3. **WGS84 chord-to-surface-arc conversion + coordinate uncertainty:**
   Using the exact minimum meridional radius of curvature of the WGS84 reference ellipsoid, $M_0 = a(1 - e^2) = 6{,}335.439327\,\text{km}$, every surface pair with mean-sphere angle $\psi$ satisfies $\|P_1 - P_2\|_2 \ge 2 M_0 \sin(\psi/2)$. Therefore:
   $$\theta_{\text{prop}} = \begin{cases} \pi, & L \ge 2 M_0 \\ 2\arcsin\!\left(\dfrac{L}{2 M_0}\right), & L < 2 M_0 \end{cases}$$
   $$\theta_{\text{total}} = \min\!\left(\pi,\; \theta_{\text{prop}} + \frac{u_{\text{coord}}}{M_0}\right), \qquad r_{\text{outer}} = \theta_{\text{total}} \cdot R_{\text{mean}}$$
   with $R_{\text{mean}} = 6{,}371.0088\,\text{km}$ and default $u_{\text{coord}} = 35\,\text{km}$ (overridden upward by per-anchor audited uncertainty).
   - **No artificial radius cap:** When $\theta_{\text{total}} = \pi$ ($r_{\text{outer}} = 20{,}015.114\,\text{km}$, reached for $t_{\text{upper}} \ge 84.53\,\text{ms}$), the cap covers **100% of Earth** with no false boundary outline.
   - **Hardware identity $\ne$ physical coordinates:** Hardware TEE attestation proves what measured binary holds the signing key, **not** physical location; $u_{\text{coord}}$ comes strictly from a separate audited coordinate dossier and cross-cloud mesh audit.

---

## 2. Same-Clock RTT & Relativistic Sagnac Effect vs. One-Way & Satellite Assumptions

### A. Same-Clock RTT & Sagnac Effect
- **Single local monotonic clock:** Each Anchor timestamps `t_send` and `t_recv` on **its own local monotonic clock** (`CLOCK_MONOTONIC` / `SO_TIMESTAMPNS` / AMD Secure TSC). Constant inter-host clock offsets cancel identically in $t_{\text{recv}} - t_{\text{send}}$; only local timestamp resolution ($\delta t_{\text{clk}}$) and local oscillator rate error ($\epsilon_{\text{slew}} t_{\text{RTT}}$) enter the bound.
- **Symmetric-path Sagnac cancellation:** On a rotating Earth ($\Omega_E = 7.292115 \times 10^{-5}\,\text{rad/s}$), a round-trip signal that retraces the same spatial path accumulates equal and opposite Sagnac shifts $+\Delta t_S$ and $-\Delta t_S$ on the outbound and return legs, **cancelling to first order**.
- **Asymmetric-path Sagnac worst-case bound:** If outbound and return internet or satellite paths differ and enclose an equatorial projected area $A_{\text{eq}}$, the residual closed-loop Sagnac time shift is:
  $$|\Delta t_{\text{Sagnac}}| = \frac{2\,\Omega_E}{c_0^2}\,|A_{\text{eq}}|$$
  Even for an extreme whole-hemisphere equatorial loop ($|A_{\text{eq}}| = \pi a^2 \approx 1.278 \times 10^{14}\,\text{m}^2$), $|\Delta t_{\text{Sagnac}}| \le 0.207\,\mu\text{s}$ ($\sim 31\,\text{m}$ one-way). This is **$> 200\times$ smaller** than our `50 µs` datacenter $\delta t_{\text{clk}}$ margin (`> 4,800×` smaller than `1,000 µs` browser margin) and is strictly absorbed with wide headroom.

### B. Why One-Way Propagation Timestamps Are NOT Used for Hard Bounds
- One-way delay requires **synchronized clocks** across Anchor and Prover (GNSS/GPS, PTP, or atomic references).
- Any unsynchronized clock offset $\Delta\tau$ directly shifts apparent one-way distance by $c_0 \Delta\tau \approx 299.8\,\text{km/ms}$ (a 10 ms spoofed or drifted clock shifts the bound by 3,000 km) and exposes the bound to GNSS/NTP spoofing.
- One-way equatorial propagation also incurs an uncancelled first-order Sagnac term ($\sim 0.10\,\mu\text{s}$ over a half-circumference).
- Therefore, Proof of Geography's hard physical outer bound **strictly requires same-clock RTT** and never relies on one-way timestamps or inter-host clock synchronization.

### C. Satellite (LEO / MEO / GEO) & Prover-Altitude Assumptions
- **Tier 1A Vacuum `c₀` bounds satellite relays for surface provers:** Any satellite relay (LEO Starlink at $h \approx 340\text{–}550\,\text{km}$, MEO, or GEO at $35{,}786\,\text{km}$) adds upward/downward slant range plus orbital arc length strictly **greater than** the 3D WGS84 straight-line chord through Earth at $c_0$. Thus `Tier 1A Vacuum` remains a strict outer bound even against free-space vacuum laser inter-satellite links (ISLs), hollow-core fiber ($\sim 0.99\,c_0$), or line-of-sight microwave links.
- **Explicit surface-prover altitude assumption ($h_{\text{prover}} \ll R_E$):** The 2D Earth-surface cap projection assumes the Prover lies on or near Earth's surface (datacenters, ground stations). For an elevated airborne ($\sim 12\,\text{km}$) or orbital ($\sim 550\,\text{km}$) Prover, straight-line distance to an Anchor differs from surface chord distance by up to $O(h_{\text{prover}})$; verifying non-surface provers requires adding $h_{\text{prover}}$ to the geometric uncertainty budget (or solving in 3D ECEF shell geometry).
- **Tier 1B Optical Fiber (`204 km/ms`):** Conditional on terrestrial/subsea standard silica fiber ($n \approx 1.468$). Optimistic LEO vacuum laser ISLs cross over and beat ideal silica fiber beyond $\sim 2{,}000\text{–}4{,}300\,\text{km}$ depending on elevation angle and switching overhead, so **Tier 1B Fiber is NOT a universal adversarial bound** when satellite laser ISLs or hollow-core fiber are in-scope.

### D. Byzantine Fault Tolerance Against Single-Anchor Fast Clocks / Isolated-Fast Anomalies
- Artificial network **delay** can only *widen* an outer cap (never cause false exclusion).
- Conversely, a **faulty/compromised Anchor** reporting an anomalously small RTT (or an isolated-fast clock glitch) can *shrink* a single cap below true distance. At $f = 0$, a single bad fast cap can exclude the true location; enforcing **Byzantine $(K-f)$-core** containment with $f \ge 1$ ensures up to $f$ corrupted or glitched Anchors cannot falsely exclude an honest Prover.

---

## 3. Empirical Spatial Likelihood & Unstable-Route Uncertainty (Strictly Separate from Hard Bounds)

- The correlated spatial likelihood surface (`web/geo.js`, `crates/pog-geo/src/calibration.rs`, SDKs) is strictly an **empirical estimate ("More likely / Less likely")** evaluated inside the raw `Tier 1A Vacuum c₀` outer region; it **never narrows** the physical outer bound.
- **Frozen median winner retained:** Benchmarking a route-adaptive fast-mode center challenger against the frozen median winner (`corr_asym_t_median`) on disjoint measured cohorts (`T0`, `T1`, `T2`, with untouched Johannesburg/Santiago kept strictly separate from Phoenix/Seoul) showed the more complex fast-mode center did not improve both errors and coverage. We therefore keep the simpler frozen median center estimate.
- **Less certainty on unstable routes (`route_instability_spread_ms`):** Instead of using `median - min` alone (which is blind to upper slow-tail spikes and understates bimodal flapping), per-anchor variance folds in full-sample spread:
  $$\hat{s}_i = \max\!\Big(\text{median} - \min,\; 0.5\,(P_{90} - P_{10}),\; 0.6\,\text{IQR},\; 0.75\,\Delta_{\text{bimodal}},\; 0.5\,\Delta_{\text{iso\_fast}}\Big)$$
  On tight datacenter links $\hat{s}_i \approx 0.05\text{–}0.2\,\text{ms}$ (no false area bloat), while on slow-tail, multimodal, or isolated-fast paths $\hat{s}_i$ grows with route instability, automatically downweighting unstable anchors and widening empirical uncertainty bands.
