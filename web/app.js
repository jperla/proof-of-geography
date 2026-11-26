/* Proof of Geography — Interactive Live Speed-of-Light Visualizer */
(function () {
  const ANCHORS = [
    { id: "aws-us-west-1-sanjose", slug: "sjc-aws", city: "San Jose, CA", cloud: "aws", defaultTee: "AWS Pilot", lat: 37.3382, lon: -121.8863, color: "#f59e0b" },
    { id: "gcp-us-west1-oregon", slug: "pdx-gcp", city: "The Dalles, OR", cloud: "gcp", defaultTee: "Intel TDX", lat: 45.5946, lon: -121.1787, color: "#38bdf8" },
    { id: "gcp-us-central1-iowa", slug: "dsm-gcp", city: "Council Bluffs, IA", cloud: "gcp", defaultTee: "AMD SEV-SNP", lat: 41.2619, lon: -95.8608, color: "#818cf8" },
    { id: "gcp-us-east4-ashburn", slug: "iad-gcp", city: "Ashburn, VA (GCP)", cloud: "gcp", defaultTee: "Intel TDX", lat: 39.0438, lon: -77.4874, color: "#38bdf8" },
    { id: "aws-us-east-1-nvirginia", slug: "iad-aws", city: "Ashburn, VA (AWS)", cloud: "aws", defaultTee: "AWS Pilot", lat: 39.0180, lon: -77.4590, color: "#f59e0b" },
    { id: "gcp-europe-west3-frankfurt", slug: "fra-gcp", city: "Frankfurt, DE (GCP)", cloud: "gcp", defaultTee: "AMD SEV-SNP", lat: 50.1109, lon: 8.6821, color: "#818cf8" },
    { id: "aws-eu-central-1-frankfurt", slug: "fra-aws", city: "Frankfurt, DE (AWS)", cloud: "aws", defaultTee: "AWS Pilot", lat: 50.1167, lon: 8.6833, color: "#f59e0b" },
    { id: "aws-ap-northeast-1-tokyo", slug: "nrt-aws", city: "Tokyo, JP", cloud: "aws", defaultTee: "AWS Pilot", lat: 35.6895, lon: 139.6917, color: "#f59e0b" },
    { id: "gcp-asia-southeast1-singapore", slug: "sin-gcp", city: "Singapore", cloud: "gcp", defaultTee: "AMD SEV-SNP", lat: 1.3521, lon: 103.8198, color: "#818cf8" },
  ];

  const ANCHOR_BY_ID = Object.fromEntries(ANCHORS.map((a) => [a.id, a]));
  const anchorBaseUrl = (a) => `https://${a.slug}.a.proofofgeography.com`;

  const state = {
    tab: "live",
    tier: "calibrated", // vacuum | fiber | calibrated
    circleMode: "top5", // top5 | all | none
    focusedAnchorId: null,
    probing: false,
    liveInfo: {}, // anchorId -> /info JSON
    liveMeasurements: [], // [{ anchor, rttMs, samples }]
    spoofMode: false,
    spoofClaim: null, // { lat, lon, label }
    meshData: null,
    selectedMeshProver: "gcp-europe-west3-frankfurt",
    verifyBundleData: null, // last verified bundle to plot
  };

  // --- Initialize Leaflet Map with Esri World Dark Gray Canvas (zero watermark, zero API key) ---
  const map = L.map("map", {
    center: [32, -25],
    zoom: 3,
    minZoom: 2,
    maxZoom: 12,
    zoomControl: false,
    worldCopyJump: true,
    preferCanvas: true,
  });

  L.control.zoom({ position: "topright" }).addTo(map);

  L.tileLayer(
    "https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}",
    { attribution: "Tiles &copy; Esri &mdash; Proof of Geography Live Grid", maxZoom: 16 }
  ).addTo(map);
  L.tileLayer(
    "https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Reference/MapServer/tile/{z}/{y}/{x}",
    { maxZoom: 16, opacity: 0.72 }
  ).addTo(map);

  const circlesLayer = L.layerGroup().addTo(map);
  const raysLayer = L.layerGroup().addTo(map);
  const intersectionLayer = L.layerGroup().addTo(map);
  const anchorsLayer = L.layerGroup().addTo(map);
  const spoofLayer = L.layerGroup().addTo(map);

  // --- Helpers ---
  function teeBadge(anchor) {
    const info = state.liveInfo[anchor.id];
    const v = info?.tee_vendor || anchor.defaultTee;
    if (v === "IntelTdx" || v === "Intel TDX") return { label: "Intel TDX", cls: "tee-tdx", color: "#38bdf8" };
    if (v === "AmdSevSnp" || v === "AMD SEV-SNP") return { label: "AMD SEV-SNP", cls: "tee-snp", color: "#818cf8" };
    return { label: anchor.cloud === "aws" ? "AWS Pilot" : v, cls: "tee-aws", color: "#f59e0b" };
  }

  function fmtDist(km) {
    const mi = km * PogGeo.KM_TO_MI;
    return mi < 100 ? `${mi.toFixed(0)} mi` : `${Math.round(mi).toLocaleString()} mi`;
  }

  function fmtCoord(lat, lon) {
    const ns = lat >= 0 ? "N" : "S";
    const ew = lon >= 0 ? "E" : "W";
    return `${Math.abs(lat).toFixed(2)}°${ns}, ${Math.abs(lon).toFixed(2)}°${ew}`;
  }

  // --- Render 9 Global Anchor Pins ---
  function renderAnchorMarkers() {
    anchorsLayer.clearLayers();
    for (const a of ANCHORS) {
      const tb = teeBadge(a);
      const info = state.liveInfo[a.id];
      const online = !!info;
      for (const shift of [-360, 0, 360]) {
        const icon = L.divIcon({
          className: "",
          html: `<div class="anchor-pin" style="background:${tb.color};color:${tb.color};opacity:${online ? 1 : 0.75}"></div>`,
          iconSize: [14, 14],
          iconAnchor: [7, 7],
        });
        const marker = L.marker([a.lat, a.lon + shift], { icon, zIndexOffset: 250 });
        const pkShort = info?.public_key_hex ? `${info.public_key_hex.slice(0, 16)}…` : "connecting…";
        const quoteBytes = info?.tee_quote?.raw_quote_b64
          ? Math.round((info.tee_quote.raw_quote_b64.length * 3) / 4)
          : 0;
        marker.bindPopup(`
          <div style="min-width:210px">
            <div style="font-weight:800;font-size:13px;margin-bottom:4px">${a.city}</div>
            <div style="color:#94a3b8;font-family:var(--mono);font-size:11px;margin-bottom:6px">${a.id}</div>
            <div><strong>TEE:</strong> <span class="tee-tag ${tb.cls}">${tb.label}</span> ${quoteBytes ? `(${quoteBytes.toLocaleString()}B quote)` : ""}</div>
            <div><strong>Status:</strong> ${online ? (info.hardened ? "✅ Online · Hardened Public Mode" : "✅ Online") : "⏳ Checking…"}</div>
            <div><strong>Ed25519 Key:</strong> <code style="font-size:10.5px">${pkShort}</code></div>
            <div><strong>UDP Window:</strong> <code>40000–40999</code></div>
          </div>
        `);
        marker.on("click", () => {
          state.focusedAnchorId = state.focusedAnchorId === a.id ? null : a.id;
          redrawActiveScene();
        });
        marker.addTo(anchorsLayer);
      }
    }
  }

  // --- Fetch Live /info From All 9 Hardened Anchors Over HTTPS ---
  async function refreshAnchorInfos() {
    let onlineCount = 0;
    let hwTeeCount = 0;
    await Promise.all(
      ANCHORS.map(async (a) => {
        try {
          const ctrl = new AbortController();
          const timer = setTimeout(() => ctrl.abort(), 5000);
          const res = await fetch(`${anchorBaseUrl(a)}/info`, { mode: "cors", signal: ctrl.signal });
          clearTimeout(timer);
          if (!res.ok) return;
          const info = await res.json();
          state.liveInfo[a.id] = info;
          onlineCount++;
          if (info.tee_vendor === "IntelTdx" || info.tee_vendor === "AmdSevSnp") hwTeeCount++;
        } catch (_) {
          // ignore unreachable during transient network glitch
        }
      })
    );
    const pill = document.getElementById("grid-status-text");
    if (onlineCount > 0) {
      pill.textContent = `${onlineCount}/9 Live · ${hwTeeCount} Hardware TEEs`;
    } else {
      pill.textContent = "9 Multi-Cloud Anchors";
    }
    renderAnchorMarkers();
    renderMeshAnchorList();
    if (state.liveMeasurements.length === 0) {
      renderLiveAnchorList([], null);
    }
  }

  // --- Measure Single Anchor via Warmed HTTP/2 HTTPS /ping ---
  async function measureSingleAnchor(anchor, totalRounds, onRound) {
    const samples = [];
    let bestMs = Infinity;
    for (let r = 0; r < totalRounds; r++) {
      const url = `${anchorBaseUrl(anchor)}/ping?r=${r}&t=${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
      const t0 = performance.now();
      try {
        const ctrl = new AbortController();
        const timer = setTimeout(() => ctrl.abort(), 4500);
        const resp = await fetch(url, { method: "GET", mode: "cors", cache: "no-store", signal: ctrl.signal });
        clearTimeout(timer);
        if (!resp.ok && resp.status !== 204) continue;
        const wallMs = performance.now() - t0;

        // Prefer high-precision Resource Timing API (responseStart - requestStart) enabled by Timing-Allow-Origin: *
        let rttMs = wallMs;
        if (performance.getEntriesByName) {
          const entries = performance.getEntriesByName(url);
          const e = entries[entries.length - 1];
          if (e && e.requestStart > 0 && e.responseStart > e.requestStart) {
            const rt = e.responseStart - e.requestStart;
            if (rt > 0.2 && rt <= wallMs + 5) {
              rttMs = rt;
            }
          }
        }
        // Discard round 0 (TCP+TLS handshake warmup); keep round 1 as fallback and rounds 2..N as true warm RTTs
        if (r >= 2 || (r === 1 && samples.length === 0)) {
          if (r >= 2 && samples.length === 1 && totalRounds >= 4) {
            // Replace warmup fallback once true warm round arrives
            samples.length = 0;
            bestMs = Infinity;
          }
          samples.push(rttMs);
          if (rttMs < bestMs) bestMs = rttMs;
        }
        if (onRound) onRound(anchor, r, bestMs, samples.slice());
      } catch (_) {
        // timeout or network error on one round; continue
      }
    }
    if (!Number.isFinite(bestMs)) return null;
    return { anchor, rttMs: bestMs, samples };
  }

  // --- Run Live Speed-of-Light Probe Across All 9 Global Anchors ---
  async function runLiveProbe() {
    if (state.probing) return;
    state.probing = true;
    const btn = document.getElementById("btn-probe-live");
    const label = document.getElementById("btn-probe-label");
    const progWrap = document.getElementById("probe-progress-wrap");
    const progFill = document.getElementById("probe-progress-fill");
    const progText = document.getElementById("probe-progress-text");

    btn.disabled = true;
    label.textContent = "Probing 9 Global Anchors…";
    progWrap.classList.remove("hidden");
    progFill.style.width = "6%";
    progText.textContent = "Opening unicast TLS 1.3 connections to 9 global datacenters…";

    const TOTAL_ROUNDS = 6;
    const liveMap = new Map();
    let completedSteps = 0;
    const totalSteps = ANCHORS.length * TOTAL_ROUNDS;

    if (performance.clearResourceTimings) performance.clearResourceTimings();

    const results = await Promise.all(
      ANCHORS.map((a) =>
        measureSingleAnchor(a, TOTAL_ROUNDS, (anchor, r, bestMs, samples) => {
          completedSteps++;
          if (Number.isFinite(bestMs)) {
            liveMap.set(anchor.id, { anchor, rttMs: bestMs, samples });
          }
          const pct = Math.min(100, Math.round((completedSteps / totalSteps) * 100));
          progFill.style.width = `${pct}%`;
          progText.textContent =
            r < 2
              ? `Warming TLS handshakes (${liveMap.size}/9 responding)…`
              : `Measuring speed-of-light RTT floor: ${liveMap.size}/9 Anchors (${pct}%)`;

          // Live animation update every 4 steps
          if (completedSteps % 4 === 0 && liveMap.size >= 3) {
            state.liveMeasurements = Array.from(liveMap.values()).sort((x, y) => x.rttMs - y.rttMs);
            redrawActiveScene(false);
          }
        })
      )
    );

    state.liveMeasurements = results.filter(Boolean).sort((a, b) => a.rttMs - b.rttMs);
    state.probing = false;
    btn.disabled = false;
    label.textContent = "Re-Run Live Probe";
    progText.textContent = `Measured ${state.liveMeasurements.length}/9 multi-cloud Anchors (min RTT across warm rounds).`;
    setTimeout(() => progWrap.classList.add("hidden"), 2600);

    redrawActiveScene(true);
  }

  // --- Core Map Scene Renderer (Used by Live Mode, 9x9 Mesh Mode, and Verify Mode) ---
  function renderGeoScene({
    measurements,
    extraOverheadMs = 0,
    truePin = null,
    spoofClaim = null,
    fitCamera = false,
  }) {
    circlesLayer.clearLayers();
    raysLayer.clearLayers();
    intersectionLayer.clearLayers();
    spoofLayer.clearLayers();

    if (!measurements || measurements.length === 0) return null;

    const sorted = measurements.slice().sort((a, b) => a.rttMs - b.rttMs);
    const solution = PogGeo.solveLocation(sorted, state.tier, extraOverheadMs, 1);
    const spoofEval = spoofClaim
      ? PogGeo.evaluateSpoofClaim(spoofClaim.lat, spoofClaim.lon, sorted, state.tier, extraOverheadMs)
      : null;

    const violatedIds = new Set(spoofEval ? spoofEval.violations.map((v) => v.anchor.id) : []);
    const focusCenter = truePin || solution.mle;

    // Decide which Anchor circles to draw
    let visibleCircles = solution.circles.slice().sort((a, b) => a.rttMs - b.rttMs);
    if (state.circleMode === "none") {
      visibleCircles = [];
    } else if (state.circleMode === "top5") {
      // Keep 5 tightest + any focused or spoof-violating Anchor so violations are ALWAYS visible!
      const keep = new Set(visibleCircles.slice(0, 5).map((c) => c.anchor.id));
      if (state.focusedAnchorId) keep.add(state.focusedAnchorId);
      for (const vid of violatedIds) keep.add(vid);
      visibleCircles = visibleCircles.filter((c) => keep.has(c.anchor.id));
    }

    // Draw each Anchor's speed-of-light geodesic circle CENTERED ON THAT ANCHOR
    for (const c of visibleCircles) {
      const tb = teeBadge(c.anchor);
      const isViolated = violatedIds.has(c.anchor.id);
      const isFocused = state.focusedAnchorId === c.anchor.id;
      const strokeColor = isViolated ? "#f43f5e" : tb.color;
      const weight = isFocused ? 2.8 : isViolated ? 2.4 : 1.7;
      const opacity = isFocused ? 0.96 : isViolated ? 0.9 : 0.72;
      const fillOpacity = isFocused ? 0.11 : isViolated ? 0.08 : 0.035;

      // Render Mercator-safe geodesic circle centered on Anchor (polar-cap aware, zero horizontal tears!)
      for (const shift of [-360, 0, 360]) {
        const geom = PogGeo.geodesicCircleGeometry(c.lat, c.lon, c.radiusKm, 144, shift);
        if (geom.polar) {
          // Fill polar interior without drawing a border across the pole edge, then stroke only the true geodesic curve
          L.polygon(geom.fill, {
            stroke: false,
            fillColor: strokeColor,
            fillOpacity: fillOpacity * 0.85,
            interactive: false,
          }).addTo(circlesLayer);
          L.polyline(geom.stroke, {
            color: strokeColor,
            weight,
            opacity,
            dashArray: isViolated ? "7 5" : null,
            interactive: false,
          }).addTo(circlesLayer);
        } else {
          L.polygon(geom.fill, {
            color: strokeColor,
            weight,
            opacity,
            fillColor: strokeColor,
            fillOpacity,
            dashArray: isViolated ? "7 5" : null,
            interactive: false,
          }).addTo(circlesLayer);
        }
      }

      // Draw subtle great-circle ray from Anchor to intersection center
      const rayPts = PogGeo.greatCircleArc(c.lat, c.lon, focusCenter[0], focusCenter[1], 32);
      L.polyline(rayPts, {
        color: strokeColor,
        weight: isFocused ? 2.0 : 1.1,
        opacity: isFocused ? 0.85 : 0.34,
        dashArray: "4 6",
        interactive: false,
      }).addTo(raysLayer);
    }

    // Highlight exact Byzantine (K-f)-core Intersection Zone polygon!
    if (solution.hull && solution.hull.length >= 3) {
      for (const shift of [-360, 0, 360]) {
        const shifted = solution.hull.map(([lat, lon]) => [lat, lon + shift]);
        L.polygon(shifted, {
          color: "#2dd4bf",
          weight: 2.4,
          opacity: 0.95,
          fillColor: "#2dd4bf",
          fillOpacity: 0.22,
          interactive: false,
        }).addTo(intersectionLayer);
      }
    }

    // Target / Estimated Intersection Marker
    const pinIcon = L.divIcon({
      className: "",
      html: `<div class="est-pulse"></div>`,
      iconSize: [18, 18],
      iconAnchor: [9, 9],
    });
    const pinMarker = L.marker([focusCenter[0], focusCenter[1]], { icon: pinIcon, zIndexOffset: 500 });
    pinMarker.bindTooltip(
      truePin
        ? `<strong>${truePin.label || "Prover"}</strong> · ±${fmtDist(solution.maxRadiusKm)}`
        : `<strong>Physics Intersection</strong> · ${fmtCoord(focusCenter[0], focusCenter[1])} (±${fmtDist(solution.maxRadiusKm)})`,
      { direction: "top", offset: [0, -12], className: "anchor-label" }
    );
    pinMarker.addTo(intersectionLayer);

    // Draw Spoof Claim Marker & Red Physics Violation Lines
    if (spoofEval) {
      const sIcon = L.divIcon({
        className: "",
        html: `<div class="spoof-pin"></div>`,
        iconSize: [18, 18],
        iconAnchor: [9, 9],
      });
      const sm = L.marker([spoofClaim.lat, spoofClaim.lon], { icon: sIcon, zIndexOffset: 600 });
      sm.bindTooltip(
        spoofEval.caught
          ? `🚫 <strong>SPOOF CAUGHT</strong> (${spoofEval.violations.length} Anchors violated)`
          : `⚠️ Inside current ${state.tier} envelope`,
        { direction: "top", offset: [0, -12], permanent: true, className: "anchor-label" }
      );
      sm.addTo(spoofLayer);

      for (const v of spoofEval.violations.slice(0, 5)) {
        const arc = PogGeo.greatCircleArc(v.anchor.lat, v.anchor.lon, spoofClaim.lat, spoofClaim.lon, 36);
        L.polyline(arc, {
          color: "#f43f5e",
          weight: 2.3,
          opacity: 0.85,
          dashArray: "6 5",
          interactive: false,
        }).addTo(spoofLayer);
      }
    }

    if (fitCamera) {
      // Smoothly frame the intersection + closest 3 Anchors
      const framePts = [focusCenter];
      for (const c of sorted.slice(0, 4)) framePts.push([c.anchor.lat, c.anchor.lon]);
      if (spoofClaim) framePts.push([spoofClaim.lat, spoofClaim.lon]);
      const bounds = L.latLngBounds(framePts);
      map.flyToBounds(bounds.pad(0.35), { maxZoom: 6, duration: 0.9 });
    }

    return { solution, spoofEval };
  }

  // --- Render Left Panel: Live Mode ---
  function renderLiveAnchorList(measurements, spoofEval) {
    const listEl = document.getElementById("live-anchor-list");
    const measById = Object.fromEntries(measurements.map((m) => [m.anchor.id, m]));
    const violById = Object.fromEntries((spoofEval?.results || []).map((r) => [r.anchor.id, r]));

    const ordered = measurements.length
      ? measurements.map((m) => m.anchor)
      : ANCHORS;

    const maxRtt = measurements.length ? Math.max(...measurements.map((m) => m.rttMs), 20) : 200;

    listEl.innerHTML = ordered
      .map((a) => {
        const tb = teeBadge(a);
        const m = measById[a.id];
        const v = violById[a.id];
        const radiusKm = m ? PogGeo.rttToRadiusKm(m.rttMs, state.tier, 1.5) : null;
        const pct = m ? Math.min(100, Math.max(4, (m.rttMs / maxRtt) * 100)) : 0;
        const isViol = v && v.violated;
        const isFoc = state.focusedAnchorId === a.id;

        return `
          <div class="anchor-row ${isViol ? "violated" : ""} ${isFoc ? "focused" : ""}" data-anchor="${a.id}">
            <div class="anchor-top">
              <div class="anchor-name">
                <i class="dot" style="background:${isViol ? "#f43f5e" : tb.color}"></i>
                <span>${a.city}</span>
              </div>
              <div class="anchor-rtt" style="color:${isViol ? "#fda4af" : "var(--cyan)"}">
                ${m ? `${m.rttMs.toFixed(1)} ms` : "ready"}
              </div>
            </div>
            <div class="anchor-meta">
              <span class="tee-tag ${tb.cls}">${tb.label}</span>
              <span>${
                isViol
                  ? `🚫 ${Math.round(v.excessMi).toLocaleString()} mi outside circle!`
                  : radiusKm !== null
                  ? `Circle radius: ≤ ${fmtDist(radiusKm)}`
                  : a.slug + ".a.proofofgeography.com"
              }</span>
            </div>
            ${
              m
                ? `<div class="rtt-bar-track"><div class="rtt-bar-fill" style="width:${pct}%;background:${
                    isViol ? "#f43f5e" : tb.color
                  }"></div></div>`
                : ""
            }
          </div>
        `;
      })
      .join("");

    listEl.querySelectorAll(".anchor-row").forEach((el) => {
      el.addEventListener("click", () => {
        const id = el.dataset.anchor;
        state.focusedAnchorId = state.focusedAnchorId === id ? null : id;
        redrawActiveScene(false);
      });
    });
  }

  function updateLiveSummary(measurements, res) {
    const sumEl = document.getElementById("live-summary");
    const noteEl = document.getElementById("live-note");
    if (!measurements.length || !res?.solution) {
      sumEl.classList.add("hidden");
      noteEl.classList.add("hidden");
      return;
    }
    sumEl.classList.remove("hidden");

    const solVac = PogGeo.solveLocation(measurements, "vacuum", 0, 1);
    const solFib = PogGeo.solveLocation(measurements, "fiber", 0, 1);
    const solCal = PogGeo.solveLocation(measurements, "calibrated", 1.5, 1);

    const best = res.solution;
    document.getElementById("m-coords").textContent = fmtCoord(best.mle[0], best.mle[1]);
    document.getElementById("m-nearest").textContent = `Nearest: ${best.nearest.anchor.city} (${best.nearest.rttMs.toFixed(1)} ms)`;
    document.getElementById("m-cal").textContent = `± ${fmtDist(solCal.maxRadiusKm)}`;
    document.getElementById("m-fiber").textContent = `± ${fmtDist(solFib.maxRadiusKm)}`;
    document.getElementById("m-vac").textContent = `± ${fmtDist(solVac.maxRadiusKm)}`;

    if (!best.strictFeasible) {
      noteEl.classList.remove("hidden");
      noteEl.innerHTML = `<strong>Note:</strong> High local Wi-Fi / VPN / cellular jitter detected (${best.feasibleCount}/${measurements.length} circles overlap under <em>${state.tier}</em>). Switch Physics Tier to <strong>Optical Fiber</strong> or <strong>Vacuum c₀</strong> for a guaranteed upper bound!`;
    } else {
      noteEl.classList.remove("hidden");
      noteEl.innerHTML = `<strong>Physics Proven:</strong> ${best.feasibleCount}/${measurements.length} independent multi-cloud Anchor circles intersect in the bright teal zone (Byzantine <code>f=1</code> fault-tolerant). Click any Anchor row to isolate its circle!`;
    }
  }

  function updateSpoofVerdict(spoofEval) {
    const el = document.getElementById("spoof-verdict");
    if (!spoofEval) {
      el.classList.add("hidden");
      return;
    }
    el.classList.remove("hidden");
    const lbl = state.spoofClaim?.label || fmtCoord(spoofEval.claimLat, spoofEval.claimLon);
    if (spoofEval.caught) {
      const worst = spoofEval.violations[0];
      const tierName = PogGeo.TIERS[state.tier].label;
      el.className = "verdict-card bad";
      el.innerHTML = `
        <strong>🚫 LIE CAUGHT BY SPEED OF LIGHT!</strong><br/>
        Claiming <strong>${lbl}</strong> violates <strong>${spoofEval.violations.length}/${spoofEval.results.length} Anchors</strong> under ${tierName}.<br/>
        Worst violation: <strong>${worst.anchor.city}</strong> measured <code>${worst.rttMs.toFixed(1)} ms</code> (max <code>${fmtDist(worst.maxKm)}</code>), yet ${lbl} is <code>${fmtDist(worst.distKm)}</code> away — ${
        worst.cMultiple > 1
          ? `requiring packets to travel at <strong>${worst.cMultiple.toFixed(2)}× c (faster than light in vacuum!)</strong>`
          : `violating calibrated fiber speed by <strong>+${fmtDist(worst.excessKm)}</strong>`
      }.
      `;
    } else {
      el.className = "verdict-card ok";
      el.innerHTML = `
        <strong>✅ PHYSICALLY CONSISTENT WITH ${PogGeo.TIERS[state.tier].label.toUpperCase()}</strong><br/>
        <strong>${lbl}</strong> lies inside all ${spoofEval.results.length} speed-of-light circles! Try clicking farther away (another continent or coast) to watch light-speed physics catch the spoof.
      `;
    }
  }

  // --- Mode 2: 9x9 Cloud Mesh ---
  async function loadMeshData() {
    try {
      const resp = await fetch("/data/live_mesh_summary.json");
      if (!resp.ok) return;
      state.meshData = await resp.json();
      renderMeshPicker();
    } catch (_) {}
  }

  function renderMeshPicker() {
    const el = document.getElementById("mesh-prover-picker");
    el.innerHTML = ANCHORS.map((a) => {
      const tb = teeBadge(a);
      return `
        <button class="mesh-btn ${state.selectedMeshProver === a.id ? "active" : ""}" data-prover="${a.id}">
          <div class="mesh-btn-city">${a.city}</div>
          <div class="mesh-btn-sub">${tb.label}</div>
        </button>
      `;
    }).join("");
    el.querySelectorAll(".mesh-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        state.selectedMeshProver = btn.dataset.prover;
        renderMeshPicker();
        redrawActiveScene(true);
      });
    });
  }

  function renderMeshAnchorList() {
    const el = document.getElementById("mesh-anchor-list");
    const proverData = state.meshData?.provers?.[state.selectedMeshProver];
    const rtts = proverData?.rtts_ms || {};

    el.innerHTML = ANCHORS.map((a) => {
      const tb = teeBadge(a);
      const info = state.liveInfo[a.id];
      const rtt = rtts[a.id];
      const isSelf = a.id === state.selectedMeshProver;
      const pk = info?.public_key_hex ? info.public_key_hex.slice(0, 14) + "…" : "pending";
      return `
        <div class="anchor-row ${state.focusedAnchorId === a.id ? "focused" : ""}" data-anchor="${a.id}">
          <div class="anchor-top">
            <div class="anchor-name">
              <i class="dot" style="background:${tb.color}"></i>
              <span>${a.city}${isSelf ? " (Prover)" : ""}</span>
            </div>
            <div class="anchor-rtt">${rtt !== undefined ? `${rtt.toFixed(2)} ms` : "—"}</div>
          </div>
          <div class="anchor-meta">
            <span class="tee-tag ${tb.cls}">${tb.label}</span>
            <span class="mono">${info?.hardened ? "🔒 " : ""}pk:${pk}</span>
          </div>
        </div>
      `;
    }).join("");

    el.querySelectorAll(".anchor-row").forEach((row) => {
      row.addEventListener("click", () => {
        const id = row.dataset.anchor;
        state.focusedAnchorId = state.focusedAnchorId === id ? null : id;
        redrawActiveScene(false);
      });
    });
  }

  function renderMeshScene(fitCamera) {
    const proverAnchor = ANCHOR_BY_ID[state.selectedMeshProver];
    const proverData = state.meshData?.provers?.[state.selectedMeshProver];
    if (!proverAnchor || !proverData) return;

    // Exclude self-same-VM loopback (<0.35ms) so we showcase authentic cross-datacenter / cross-cloud multilateration!
    const measurements = Object.entries(proverData.rtts_ms || {})
      .filter(([aid]) => aid !== state.selectedMeshProver && ANCHOR_BY_ID[aid])
      .map(([aid, rttMs]) => ({ anchor: ANCHOR_BY_ID[aid], rttMs }))
      .sort((a, b) => a.rttMs - b.rttMs);

    const best = measurements[0];
    document.getElementById("mesh-name").textContent = proverAnchor.city;
    document.getElementById("mesh-tee").textContent = `${teeBadge(proverAnchor).label} · Live UDP Mesh`;
    if (best) {
      const calKm = PogGeo.rttToRadiusKm(best.rttMs, "calibrated", 0);
      document.getElementById("mesh-best").textContent = `${best.rttMs.toFixed(2)} ms → ${fmtDist(calKm)}`;
      document.getElementById("mesh-best-sub").textContent = `via ${best.anchor.city}`;
    }
    renderMeshAnchorList();

    renderGeoScene({
      measurements,
      extraOverheadMs: 0,
      truePin: Object.assign([proverAnchor.lat, proverAnchor.lon], { label: proverAnchor.city }),
      spoofClaim: null,
      fitCamera,
    });
  }

  // --- Mode 3: Verify X-PoG-Proof Header via Live Rust Backend ---
  async function verifyHeaderInput() {
    const headerVal = document.getElementById("verify-input").value.trim();
    const verdictEl = document.getElementById("verify-verdict");
    const jsonEl = document.getElementById("verify-json");
    if (!headerVal) return;

    verdictEl.className = "verdict-card ok";
    verdictEl.classList.remove("hidden");
    verdictEl.textContent = "Verifying Ed25519 Anchor signatures & Byzantine (K-f)-core physics bounds…";

    try {
      const resp = await fetch("/v1/verify-header", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ header_value: headerVal }),
      });
      const data = await resp.json();
      jsonEl.classList.remove("hidden");
      jsonEl.textContent = JSON.stringify(data, null, 2);

      if (data.overall_valid) {
        const vacMi = (data.tier1a_vacuum.proven_max_radius_km * PogGeo.KM_TO_MI).toFixed(1);
        const fibMi = (data.tier1b_fiber.proven_max_radius_km * PogGeo.KM_TO_MI).toFixed(1);
        const calMi = (data.tier2_calibrated.proven_max_radius_km * PogGeo.KM_TO_MI).toFixed(1);
        verdictEl.className = "verdict-card ok";
        verdictEl.innerHTML = `
          <strong>✅ CRYPTOGRAPHICALLY VERIFIED!</strong><br/>
          All Anchor Ed25519 receipts valid · Vacuum: <code>${vacMi} mi</code> · Fiber: <code>${fibMi} mi</code> · Calibrated: <code>${calMi} mi</code>
        `;
      } else {
        verdictEl.className = "verdict-card bad";
        verdictEl.innerHTML = `<strong>🚫 VERIFICATION FAILED</strong><br/>${(
          data.failure_reasons || [data.error || "Invalid proof"]
        ).join("; ")}`;
      }

      // Decode bundle locally to visualize its Anchor circles on the map!
      try {
        const b64 = headerVal.replace(/-/g, "+").replace(/_/g, "/");
        const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
        const bundle = JSON.parse(atob(padded));
        if (bundle.receipts) {
          state.verifyBundleData = bundle;
          redrawActiveScene(true);
        }
      } catch (_) {}
    } catch (e) {
      verdictEl.className = "verdict-card bad";
      verdictEl.textContent = `Verifier API error: ${e.message}`;
    }
  }

  function renderVerifyScene(fitCamera) {
    const b = state.verifyBundleData;
    if (!b || !b.receipts) return;
    const measurements = b.receipts
      .filter((r) => ANCHOR_BY_ID[r.anchor_id])
      .map((r) => ({ anchor: ANCHOR_BY_ID[r.anchor_id], rttMs: r.rtt_min_us / 1000.0 }));
    const tgt = b.target_location
      ? Object.assign([b.target_location.lat, b.target_location.lon], { label: "Verified Proof Target" })
      : null;
    renderGeoScene({ measurements, extraOverheadMs: 0, truePin: tgt, fitCamera });
  }

  // --- Central Redraw Dispatcher ---
  function redrawActiveScene(fitCamera = false) {
    if (state.tab === "live") {
      const res = renderGeoScene({
        measurements: state.liveMeasurements,
        extraOverheadMs: 1.5,
        spoofClaim: state.spoofMode ? state.spoofClaim : null,
        fitCamera,
      });
      renderLiveAnchorList(state.liveMeasurements, res?.spoofEval || null);
      updateLiveSummary(state.liveMeasurements, res);
      updateSpoofVerdict(res?.spoofEval || null);
    } else if (state.tab === "mesh") {
      renderMeshScene(fitCamera);
    } else if (state.tab === "verify") {
      renderVerifyScene(fitCamera);
    }
  }

  // --- Event Wiring ---
  document.querySelectorAll(".tab").forEach((btn) => {
    btn.addEventListener("click", () => {
      state.tab = btn.dataset.tab;
      document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t === btn));
      document.querySelectorAll(".tab-pane").forEach((p) => p.classList.toggle("active", p.id === `pane-${state.tab}`));
      state.focusedAnchorId = null;
      redrawActiveScene(state.tab === "mesh");
    });
  });

  document.getElementById("panel-toggle").addEventListener("click", () => {
    document.getElementById("panel").classList.toggle("collapsed");
  });

  document.getElementById("btn-probe-live").addEventListener("click", runLiveProbe);

  document.getElementById("btn-spoof-toggle").addEventListener("click", async () => {
    state.spoofMode = !state.spoofMode;
    document.getElementById("btn-spoof-toggle").classList.toggle("active", state.spoofMode);
    document.getElementById("spoof-box").classList.toggle("hidden", !state.spoofMode);
    if (state.spoofMode && state.liveMeasurements.length === 0) {
      await runLiveProbe();
    }
    if (!state.spoofMode) {
      state.spoofClaim = null;
      redrawActiveScene(false);
    }
  });

  document.getElementById("btn-spoof-clear").addEventListener("click", () => {
    state.spoofMode = false;
    state.spoofClaim = null;
    document.getElementById("btn-spoof-toggle").classList.remove("active");
    document.getElementById("spoof-box").classList.add("hidden");
    redrawActiveScene(false);
  });

  document.querySelectorAll("[data-spoof]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      if (state.liveMeasurements.length === 0) await runLiveProbe();
      const [latStr, lonStr, ...labelParts] = btn.dataset.spoof.split(",");
      state.spoofMode = true;
      state.spoofClaim = { lat: parseFloat(latStr), lon: parseFloat(lonStr), label: labelParts.join(",") };
      redrawActiveScene(true);
    });
  });

  map.on("click", (ev) => {
    if (state.tab === "live" && state.spoofMode && state.liveMeasurements.length > 0) {
      let lon = ev.latlng.lng;
      while (lon > 180) lon -= 360;
      while (lon < -180) lon += 360;
      state.spoofClaim = { lat: ev.latlng.lat, lon, label: `Clicked (${fmtCoord(ev.latlng.lat, lon)})` };
      redrawActiveScene(false);
    }
  });

  document.querySelectorAll("#tier-switcher .seg-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      state.tier = btn.dataset.tier;
      document.querySelectorAll("#tier-switcher .seg-btn").forEach((b) => b.classList.toggle("active", b === btn));
      redrawActiveScene(false);
    });
  });

  document.querySelectorAll("#circle-switcher .seg-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      state.circleMode = btn.dataset.circles;
      document.querySelectorAll("#circle-switcher .seg-btn").forEach((b) => b.classList.toggle("active", b === btn));
      redrawActiveScene(false);
    });
  });

  document.getElementById("btn-refresh-tees").addEventListener("click", refreshAnchorInfos);
  document.getElementById("btn-verify-header").addEventListener("click", verifyHeaderInput);

  document.querySelectorAll(".verify-sample").forEach((btn) => {
    btn.addEventListener("click", () => {
      const sample = state.meshData?.sample_headers?.[btn.dataset.sample];
      if (!sample) {
        alert("Sample header is loading — please try again in a second.");
        return;
      }
      document.getElementById("verify-input").value = sample;
      verifyHeaderInput();
    });
  });

  document.querySelectorAll(".copy-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const text = document.getElementById(btn.dataset.copy).textContent;
      await navigator.clipboard.writeText(text);
      const old = btn.textContent;
      btn.textContent = "Copied!";
      setTimeout(() => (btn.textContent = old), 1400);
    });
  });

  // --- Boot ---
  renderAnchorMarkers();
  renderLiveAnchorList([], null);
  refreshAnchorInfos();
  loadMeshData();
})();
