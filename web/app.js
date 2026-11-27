/* Proof of Geography — Exact Spherical Outer-Bound & Correlated Spatial Likelihood Visualizer */
(function () {
  // Legacy 9-node mesh anchor catalog preserved so Cloud Mesh never loses its 5 GCP nodes
  // when /data/anchors.json loads the 42-node pilot grid!
  const LEGACY_MESH_ANCHORS = [
    { id: "aws-us-west-1-sanjose", slug: "sjc-aws", city: "San Jose, CA", cloud: "aws", defaultTee: "SoftwareDev", lat: 37.3382, lon: -121.8863, color: "#f59e0b" },
    { id: "gcp-us-west1-oregon", slug: "pdx-gcp", city: "The Dalles, OR", cloud: "gcp", defaultTee: "IntelTdx", lat: 45.5946, lon: -121.1787, color: "#38bdf8" },
    { id: "gcp-us-central1-iowa", slug: "dsm-gcp", city: "Council Bluffs, IA", cloud: "gcp", defaultTee: "AmdSevSnp", lat: 41.2619, lon: -95.8608, color: "#818cf8" },
    { id: "gcp-us-east4-ashburn", slug: "iad-gcp", city: "Ashburn, VA (GCP)", cloud: "gcp", defaultTee: "IntelTdx", lat: 39.0438, lon: -77.4874, color: "#38bdf8" },
    { id: "aws-us-east-1-nvirginia", slug: "iad-aws", city: "Ashburn, VA (AWS)", cloud: "aws", defaultTee: "SoftwareDev", lat: 39.0180, lon: -77.4590, color: "#f59e0b" },
    { id: "gcp-europe-west3-frankfurt", slug: "fra-gcp", city: "Frankfurt, DE (GCP)", cloud: "gcp", defaultTee: "AmdSevSnp", lat: 50.1109, lon: 8.6821, color: "#818cf8" },
    { id: "aws-eu-central-1-frankfurt", slug: "fra-aws", city: "Frankfurt, DE (AWS)", cloud: "aws", defaultTee: "SoftwareDev", lat: 50.1167, lon: 8.6833, color: "#f59e0b" },
    { id: "aws-ap-northeast-1-tokyo", slug: "nrt-aws", city: "Tokyo, JP", cloud: "aws", defaultTee: "SoftwareDev", lat: 35.6895, lon: 139.6917, color: "#f59e0b" },
    { id: "gcp-asia-southeast1-singapore", slug: "sin-gcp", city: "Singapore", cloud: "gcp", defaultTee: "AmdSevSnp", lat: 1.3521, lon: 103.8198, color: "#818cf8" },
  ];
  const LEGACY_BY_ID = Object.fromEntries(LEGACY_MESH_ANCHORS.map((a) => [a.id, a]));

  let ANCHORS = LEGACY_MESH_ANCHORS.slice();
  let ANCHOR_BY_ID = Object.assign({}, LEGACY_BY_ID);
  const anchorBaseUrl = (a) => {
    const active = state.constellationStore ? state.constellationStore.getActive() : { isOfficial: true };
    return PogConstellation.resolveAnchorBaseUrl(a, active, window.location.origin);
  };

  const state = {
    tab: "live",
    tier: "vacuum",        // Default: strict Vacuum c0 outer bound! ("vacuum" | "fiber")
    showLikelihood: true,  // Empirical spatial likelihood overlay inside Vacuum c0
    circleMode: "none",    // "none" | "top5" | "all"
    focusedAnchorId: null,
    probing: false,
    constellationStore: null,
    externalRegistryError: null,
    liveInfo: {},          // anchorId -> /info JSON (strictly scoped to selected constellation)
    publishedRegistry: null,
    fleetAudit: { configured: 0, reachable: 0, hwTee: 0, keyMatched: 0, proofEligible: 0, isOfficial: true, isExternal: false },
    liveMeasurements: [],
    spoofMode: false,
    spoofClaim: null,
    meshData: null,
    qaHeldoutData: null,
    activeQaPreset: null,  // null | "chicago" | "seoul" | "frankfurt" | "repro150" | "dateline" | "polar" | "multipeak"
    selectedMeshProver: "gcp-europe-west3-frankfurt",
    grid72Data: null,
    grid72Target: { lat: 38.7223, lon: -9.1393, label: "Lisbon, PT" },
    verifyBundleData: null,
  };

  // --- Initialize Leaflet Map ---
  const map = L.map("map", {
    center: [32, -25],
    zoom: 3,
    minZoom: 1,
    maxZoom: 12,
    zoomControl: false,
    worldCopyJump: true,
    preferCanvas: true,
  });

  L.control.zoom({ position: "topright" }).addTo(map);

  L.tileLayer(
    "https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}",
    { attribution: "Tiles &copy; Esri &mdash; Proof of Geography", maxZoom: 16 }
  ).addTo(map);
  L.tileLayer(
    "https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Reference/MapServer/tile/{z}/{y}/{x}",
    { maxZoom: 16, opacity: 0.72 }
  ).addTo(map);

  // --- Exact Spherical Pixel-Canvas Layer (Zero Wrong-Side Fill, Zero Polar/Dateline/Whole-Earth Bugs!) ---
  const SphericalRegionCanvasLayer = L.Layer.extend({
    onAdd(mapInst) {
      this._map = mapInst;
      this._canvas = L.DomUtil.create("canvas", "pog-spherical-canvas");
      this._canvas.style.position = "absolute";
      this._canvas.style.pointerEvents = "none";
      this._canvas.style.zIndex = "350";
      mapInst.getPanes().overlayPane.appendChild(this._canvas);
      mapInst.on("moveend zoomend resize viewreset", this._redraw, this);
      this._scene = null;
      this._redraw();
    },
    onRemove(mapInst) {
      mapInst.off("moveend zoomend resize viewreset", this._redraw, this);
      if (this._canvas && this._canvas.parentNode) {
        this._canvas.parentNode.removeChild(this._canvas);
      }
    },
    setScene(scene) {
      this._scene = scene;
      this._redraw();
    },
    _redraw() {
      if (!this._map || !this._canvas) return;
      const size = this._map.getSize();
      const topLeft = this._map.containerPointToLayerPoint([0, 0]);
      L.DomUtil.setPosition(this._canvas, topLeft);
      const w = Math.max(1, Math.round(size.x));
      const h = Math.max(1, Math.round(size.y));
      this._canvas.width = w;
      this._canvas.height = h;
      const ctx = this._canvas.getContext("2d");
      ctx.clearRect(0, 0, w, h);

      const sc = this._scene;
      if (!sc || !sc.disks || sc.disks.length === 0) return;

      const disks = sc.disks;
      const k = disks.length;
      const req = sc.requiredCount;
      const showLike =
        !!sc.showLikelihood &&
        !!sc.likelihood &&
        (sc.likelihood.moreLikelyAreaFraction ?? 1) < 0.85;
      const like = sc.likelihood;
      const vacDisks = sc.vacuumDisks || disks;
      const reqVac = sc.vacuumRequiredCount ?? req;

      // Coarse cell stride: 3px desktop, 4px mobile -> ~120k ops max (<10 ms!)
      const stride = w < 640 ? 4 : 3;
      const cols = Math.ceil(w / stride);
      const rows = Math.ceil(h / stride);
      const mask = new Uint8Array(cols * rows);
      const img = ctx.createImageData(w, h);
      const data = img.data;

      // Precompute row latitudes & col longitudes once!
      const rowLatSin = new Float64Array(rows);
      const rowLatCos = new Float64Array(rows);
      const rowValid = new Uint8Array(rows);
      for (let r = 0; r < rows; r++) {
        const py = r * stride + stride * 0.5;
        const ll = this._map.containerPointToLatLng([0, py]);
        if (ll.lat >= -85.05 && ll.lat <= 85.05) {
          rowValid[r] = 1;
          const rad = (ll.lat * Math.PI) / 180;
          rowLatSin[r] = Math.sin(rad);
          rowLatCos[r] = Math.cos(rad);
        }
      }
      const colLonCos = new Float64Array(cols);
      const colLonSin = new Float64Array(cols);
      for (let c = 0; c < cols; c++) {
        const px = c * stride + stride * 0.5;
        const ll = this._map.containerPointToLatLng([px, 0]);
        const rad = (ll.lng * Math.PI) / 180;
        colLonCos[c] = Math.cos(rad);
        colLonSin[c] = Math.sin(rad);
      }

      const ux = new Float64Array(k), uy = new Float64Array(k), uz = new Float64Array(k), ct = new Float64Array(k);
      for (let i = 0; i < k; i++) {
        ux[i] = disks[i].u[0];
        uy[i] = disks[i].u[1];
        uz[i] = disks[i].u[2];
        ct[i] = disks[i].cosTheta - 1e-11;
      }

      const vux = new Float64Array(vacDisks.length);
      const vuy = new Float64Array(vacDisks.length);
      const vuz = new Float64Array(vacDisks.length);
      const vct = new Float64Array(vacDisks.length);
      for (let i = 0; i < vacDisks.length; i++) {
        vux[i] = vacDisks[i].u[0];
        vuy[i] = vacDisks[i].u[1];
        vuz[i] = vacDisks[i].u[2];
        vct[i] = vacDisks[i].cosTheta - 1e-11;
      }

      const tauMl = like ? like.tauMoreLikely : 1.75;
      const tauPl = like ? like.tauPlausible : 3.91;
      const ptBuf = [0, 0, 0];

      // Pass 1: exact spherical membership + correlated likelihood ramp strictly inside Vacuum c0
      for (let r = 0; r < rows; r++) {
        if (!rowValid[r]) continue;
        const cl = rowLatCos[r];
        const sl = rowLatSin[r];
        for (let c = 0; c < cols; c++) {
          const x = cl * colLonCos[c];
          const y = cl * colLonSin[c];
          const z = sl;

          let inside = sc.wholeEarth ? 1 : 0;
          if (!sc.wholeEarth) {
            let cnt = 0;
            for (let i = 0; i < k; i++) {
              if (x * ux[i] + y * uy[i] + z * uz[i] >= ct[i]) cnt++;
            }
            if (cnt >= req) inside = 1;
          }
          mask[r * cols + c] = inside;
          if (!inside) continue;

          // Base subtle cyan tint for raw outer bound
          let R = 45, G = 212, B = 191, A = sc.wholeEarth ? 42 : 34;

          // Overlay empirical spatial likelihood strictly inside raw Vacuum c0 outer bound!
          if (showLike) {
            let inVac = true;
            if (vacDisks !== disks) {
              let vcnt = 0;
              for (let i = 0; i < vacDisks.length; i++) {
                if (x * vux[i] + y * vuy[i] + z * vuz[i] >= vct[i]) vcnt++;
              }
              inVac = vcnt >= reqVac;
            }
            if (inVac) {
              ptBuf[0] = x; ptBuf[1] = y; ptBuf[2] = z;
              const delta = like.evalDeltaNllUnit(ptBuf);
              if (delta <= tauMl) {
                // "More likely" core: warm amber-gold (#fbbf24) -> vibrant coral-magenta (#ec4899)
                const t = Math.max(0, Math.min(1, delta / Math.max(0.1, tauMl)));
                R = Math.round(251 * (1 - t) + 236 * t);
                G = Math.round(191 * (1 - t) + 72 * t);
                B = Math.round(36 * (1 - t) + 153 * t);
                A = Math.round(178 * (1 - t) + 125 * t);
              } else if (delta <= tauPl) {
                // "Plausible" outer halo: magenta (#ec4899) -> indigo-violet (#6366f1)
                const t = Math.max(0, Math.min(1, (delta - tauMl) / Math.max(0.1, tauPl - tauMl)));
                R = Math.round(168 * (1 - t) + 99 * t);
                G = Math.round(85 * (1 - t) + 102 * t);
                B = Math.round(247 * (1 - t) + 241 * t);
                A = Math.round(108 * (1 - t) + 48 * t);
              }
            }
          }

          const y0 = r * stride;
          const x0 = c * stride;
          const yMax = Math.min(h, y0 + stride);
          const xMax = Math.min(w, x0 + stride);
          for (let py = y0; py < yMax; py++) {
            let off = (py * w + x0) * 4;
            for (let px = x0; px < xMax; px++) {
              data[off] = R;
              data[off + 1] = G;
              data[off + 2] = B;
              data[off + 3] = A;
              off += 4;
            }
          }
        }
      }

      // Pass 2: Crisp 2px solid cyan boundary outline ONLY when there is a real geographic boundary!
      // On Whole-Earth (100% feasible), NEVER draw a false outline around ±85.05° or viewport edges;
      // the translucent all-world fill + explicit Whole-Earth banner communicates full-globe feasibility.
      if (!sc.wholeEarth) {
        for (let r = 0; r < rows; r++) {
          if (!rowValid[r]) continue;
          for (let c = 0; c < cols; c++) {
            if (!mask[r * cols + c]) continue;
            const isEdge =
              (r > 0 && rowValid[r - 1] && !mask[(r - 1) * cols + c]) ||
              (r + 1 < rows && rowValid[r + 1] && !mask[(r + 1) * cols + c]) ||
              (c > 0 && !mask[r * cols + (c - 1)]) ||
              (c + 1 < cols && !mask[r * cols + (c + 1)]);
            if (!isEdge) continue;
            const y0 = r * stride;
            const x0 = c * stride;
            const yMax = Math.min(h, y0 + stride);
            const xMax = Math.min(w, x0 + stride);
            for (let py = y0; py < yMax; py++) {
              let off = (py * w + x0) * 4;
              for (let px = x0; px < xMax; px++) {
                data[off] = 45;
                data[off + 1] = 212;
                data[off + 2] = 191;
                data[off + 3] = 242;
                off += 4;
              }
            }
          }
        }
      }

      ctx.putImageData(img, 0, 0);

      // Optional self-audit of actual rendered canvas pixels (used by automated visual QA!)
      let outlinePixels = 0;
      let maxAlpha = 0;
      for (let i = 3; i < data.length; i += 4) {
        const a = data[i];
        if (a > maxAlpha) maxAlpha = a;
        if (a >= 200) outlinePixels++;
      }
      let worldChecked = 0, worldFilled = 0;
      for (let lat = -80; lat <= 80; lat += 10) {
        for (let lon = -170; lon <= 170; lon += 10) {
          const pt = this._map.latLngToContainerPoint([lat, lon]);
          const px = Math.round(pt.x), py = Math.round(pt.y);
          if (px < 0 || py < 0 || px >= w || py >= h) continue;
          worldChecked++;
          if (data[(py * w + px) * 4 + 3] > 10) worldFilled++;
        }
      }
      this._canvas.dataset.pixelAudit = JSON.stringify({
        width: w,
        height: h,
        wholeEarth: !!sc.wholeEarth,
        worldChecked,
        worldFilled,
        outlinePixels,
        maxAlpha,
      });
    },
  });

  const regionCanvasLayer = new SphericalRegionCanvasLayer().addTo(map);
  const circlesLayer = L.layerGroup().addTo(map);
  const raysLayer = L.layerGroup().addTo(map);
  const markersLayer = L.layerGroup().addTo(map);
  const anchorsLayer = L.layerGroup().addTo(map);
  const grid72Layer = L.layerGroup().addTo(map);
  const spoofLayer = L.layerGroup().addTo(map);

  // --- Helpers ---
  function teeBadge(anchor) {
    const info = state.liveInfo[anchor.id];
    const v = info?.tee_vendor || anchor.defaultTee || "SoftwareDev";
    return PogConstellation.teeBadgeForVendor(v, anchor.cloud);
  }

  function createIconDiv(className, styleProps) {
    const div = document.createElement("div");
    div.className = className;
    if (styleProps) Object.assign(div.style, styleProps);
    return div;
  }

  function fmtDist(km) {
    if (km >= PogGeo.HALF_CIRCUMFERENCE_KM - 1) return "20,015 km (Whole Earth)";
    const mi = km * PogGeo.KM_TO_MI;
    return `${Math.round(km).toLocaleString()} km (${Math.round(mi).toLocaleString()} mi)`;
  }

  function fmtArea(km2) {
    const pct = (100 * km2) / PogGeo.EARTH_SURFACE_KM2;
    if (pct >= 99.5) return "510.1M km² (100% Earth)";
    if (km2 >= 1e6) return `${(km2 / 1e6).toFixed(2)}M km² (${pct.toFixed(2)}%)`;
    return `${Math.round(km2).toLocaleString()} km² (${pct.toFixed(3)}%)`;
  }

  function fmtCoord(lat, lon) {
    const ns = lat >= 0 ? "N" : "S";
    const ew = lon >= 0 ? "E" : "W";
    return `${Math.abs(lat).toFixed(2)}°${ns}, ${Math.abs(lon).toFixed(2)}°${ew}`;
  }

  function getFitPadding() {
    const isMobile = window.innerWidth <= 900;
    const panelCollapsed = document.getElementById("panel").classList.contains("collapsed");
    if (isMobile) {
      return {
        paddingTopLeft: [16, 130],
        paddingBottomRight: [16, panelCollapsed ? 55 : Math.round(window.innerHeight * 0.48)],
      };
    }
    return {
      paddingTopLeft: [panelCollapsed ? 24 : 425, 84],
      paddingBottomRight: [40, 74],
    };
  }

  // --- Render Anchor Pins ---
  function renderAnchorMarkers() {
    anchorsLayer.clearLayers();
    const active = state.constellationStore ? state.constellationStore.getActive() : { isOfficial: true, isExternal: false, operatorName: "Proof of Geography" };
    const pubAnchors =
      active.signedRegistry?.grid?.anchors ||
      (active.isOfficial ? state.publishedRegistry?.grid?.anchors : null) ||
      [];
    for (const a of ANCHORS) {
      const tb = teeBadge(a);
      const info = state.liveInfo[a.id];
      const online = !!info;
      const pubAnc = pubAnchors.find((x) => (x.anchor_id || x.id) === a.id);
      const expectedPk = pubAnc?.public_key_hex || a.public_key_hex || null;
      const pkMatchesPub = !!(online && expectedPk && info.public_key_hex && info.public_key_hex.toLowerCase() === expectedPk.toLowerCase());
      const endorseMatchesLive = !!(
        online &&
        info.operator_endorsement &&
        info.operator_endorsement.anchor_public_key_hex &&
        info.public_key_hex &&
        info.operator_endorsement.anchor_public_key_hex.toLowerCase() === info.public_key_hex.toLowerCase()
      );
      const prodEligible = active.isOfficial && online && tb.isHw && pkMatchesPub && endorseMatchesLive;
      const baseUrl = anchorBaseUrl(a);

      const pinColor = PogConstellation.sanitizeHexColor(tb.color);
      for (const shift of [-360, 0, 360]) {
        const icon = L.divIcon({
          className: "",
          html: createIconDiv("anchor-pin", {
            background: pinColor,
            color: pinColor,
            opacity: online ? "1" : "0.78",
          }),
          iconSize: [13, 13],
          iconAnchor: [6.5, 6.5],
        });
        const marker = L.marker([a.lat, a.lon + shift], { icon, zIndexOffset: 240 });
        const pkShort = info?.public_key_hex ? `${String(info.public_key_hex).slice(0, 14)}…` : "not queried";
        marker.bindPopup(
          PogConstellation.buildAnchorPopupElement(document, {
            anchor: a,
            active,
            badge: tb,
            baseUrl,
            online,
            pkMatchesPub,
            prodEligible,
            pkShort,
          })
        );
        marker.on("click", () => {
          state.focusedAnchorId = state.focusedAnchorId === a.id ? null : a.id;
          redrawActiveScene(false);
        });
        marker.addTo(anchorsLayer);
      }
    }
  }

  function renderExternalConstellationBanner() {
    const banner = document.getElementById("external-constellation-banner");
    if (!banner) return;
    const active = state.constellationStore ? state.constellationStore.getActive() : null;
    if (state.externalRegistryError) {
      banner.classList.remove("hidden");
      banner.replaceChildren(
        PogConstellation.buildExternalBannerElement(document, {
          errorMessage: state.externalRegistryError,
        })
      );
      return;
    }
    if (active && active.isExternal) {
      const officialCount = state.constellationStore.getOfficial().anchors.length;
      banner.classList.remove("hidden");
      banner.replaceChildren(
        PogConstellation.buildExternalBannerElement(document, {
          active,
          officialCount,
        })
      );
    } else {
      banner.classList.add("hidden");
      banner.replaceChildren();
    }
  }

  function applySelectedConstellationToUi() {
    const active = state.constellationStore.getActive();
    ANCHORS = active.anchors.slice();
    // Strictly isolate external constellation: NEVER mix official or legacy nodes into ANCHOR_BY_ID when external!
    ANCHOR_BY_ID = active.isOfficial
      ? Object.assign({}, LEGACY_BY_ID, Object.fromEntries(ANCHORS.map((a) => [a.id, a])))
      : Object.fromEntries(ANCHORS.map((a) => [a.id, a]));
    state.liveInfo = {};
    state.liveMeasurements = [];

    const heroCount = document.getElementById("hero-anchor-count");
    if (heroCount) {
      heroCount.textContent = active.isExternal
        ? `${ANCHORS.length} independently operated Anchors (${active.operatorName})`
        : `${ANCHORS.length} live official tri-cloud Anchors`;
    }
    const badge = document.getElementById("anchor-count-badge");
    if (badge) {
      badge.textContent = active.isExternal ? `${ANCHORS.length} External Anchors` : `${ANCHORS.length} Official Anchors`;
    }
    renderExternalConstellationBanner();
  }

  // --- Load Official Constellation (/data/anchors.json by default) & Optional Separate ?registry=<url> ---
  async function loadLiveAnchorsList() {
    let officialPayload = {
      network_id: PogConstellation.OFFICIAL_NETWORK_ID,
      operator_name: PogConstellation.OFFICIAL_OPERATOR_NAME,
      official: true,
      anchors: LEGACY_MESH_ANCHORS,
    };
    try {
      const resp = await fetch("/data/anchors.json?v=10");
      if (resp.ok) {
        const data = await resp.json();
        if (Array.isArray(data.anchors) && data.anchors.length > 0) {
          officialPayload = data;
        }
      }
    } catch (_) {}

    state.constellationStore = PogConstellation.createConstellationStore(officialPayload, {
      pageOrigin: window.location.origin,
    });
    state.externalRegistryError = null;

    // Optional `?registry=<url>` selects an independent external constellation INSTEAD of merging with official!
    const params = new URLSearchParams(window.location.search);
    const extRegistryParam = params.get("registry");
    if (extRegistryParam && extRegistryParam.trim()) {
      const validUrl = PogConstellation.validateHttpsOrLocalUrl(extRegistryParam, window.location.origin);
      if (!validUrl) {
        state.externalRegistryError = `Rejected non-HTTPS external registry URL: ${extRegistryParam}`;
      } else {
        try {
          const extResp = await fetch(validUrl, { mode: "cors", cache: "no-store" });
          if (!extResp.ok) throw new Error(`HTTP ${extResp.status}`);
          const extPayload = await extResp.json();
          state.constellationStore.selectExternal(extPayload, validUrl);
        } catch (err) {
          state.externalRegistryError = `Failed to load external registry (${validUrl}): ${err.message || err}`;
        }
      }
    }

    applySelectedConstellationToUi();

    // Load official signed registry ONLY when viewing the official constellation!
    if (state.constellationStore.getActive().isOfficial) {
      try {
        const regResp = await fetch("/.well-known/pog-network.json");
        if (regResp.ok) {
          state.publishedRegistry = await regResp.json();
        }
      } catch (_) {}
    } else {
      state.publishedRegistry = state.constellationStore.getActive().signedRegistry;
    }
  }

  // --- Audit Live /info Across Selected Constellation ONLY (Never Mixes External & Official Counts!) ---
  async function refreshAnchorInfos() {
    const active = state.constellationStore ? state.constellationStore.getActive() : null;

    for (let i = 0; i < ANCHORS.length; i += 12) {
      const slice = ANCHORS.slice(i, i + 12);
      await Promise.all(
        slice.map(async (a) => {
          const base = anchorBaseUrl(a);
          if (!base) return;
          try {
            const ctrl = new AbortController();
            const timer = setTimeout(() => ctrl.abort(), 4500);
            const res = await fetch(`${base}/info?_t=${Date.now()}`, { mode: "cors", signal: ctrl.signal });
            clearTimeout(timer);
            if (!res.ok) return;
            const info = await res.json();
            state.liveInfo[a.id] = info;
            if (state.constellationStore) {
              state.constellationStore.recordLiveInfo(a.id, info);
            }
          } catch (_) {}
        })
      );
    }

    const audit = state.constellationStore
      ? state.constellationStore.getActiveAudit(state.publishedRegistry)
      : { configured: ANCHORS.length, reachable: 0, hwTee: 0, keyMatched: 0, proofEligible: 0, isOfficial: true, isExternal: false };
    state.fleetAudit = audit;

    const pill = document.getElementById("grid-status-pill");
    const pillText = document.getElementById("grid-status-text");
    const dot = document.getElementById("grid-status-dot");
    pill.classList.toggle("external", !!audit.isExternal);
    if (audit.isExternal) {
      pillText.textContent =
        audit.reachable > 0
          ? `External · ${audit.reachable}/${audit.configured} Up · ${audit.hwTee} HW TEE (Not Official)`
          : `External (${active?.networkId || "custom"}) · ${audit.configured} Anchors (Not Official)`;
      pill.classList.remove("warn");
      dot.classList.add("warn");
    } else if (audit.reachable > 0) {
      pillText.textContent = `${audit.reachable}/${audit.configured} Up · ${audit.hwTee} HW TEE · ${audit.proofEligible} Prod-Eligible`;
      pill.classList.toggle("warn", audit.proofEligible === 0);
      dot.classList.toggle("warn", audit.proofEligible === 0);
    } else {
      pillText.textContent = `${audit.configured} Official Configured · Offline/Local Mode`;
      pill.classList.add("warn");
      dot.classList.add("warn");
    }

    renderAnchorMarkers();
    if (!state.activeQaPreset) renderMeshAnchorList();
    if (state.liveMeasurements.length === 0) renderLiveAnchorList([], null, null);
  }

  // --- Measure Single Anchor via Browser HTTPS /ping (Collects min, median, jitter!) ---
  async function measureSingleAnchor(anchor, totalRounds) {
    const base = anchorBaseUrl(anchor);
    if (!base) return null;
    const samples = [];
    for (let r = 0; r < totalRounds; r++) {
      const url = `${base}/ping?r=${r}&t=${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
      const t0 = performance.now();
      try {
        const ctrl = new AbortController();
        const timer = setTimeout(() => ctrl.abort(), 4500);
        const resp = await fetch(url, { method: "GET", mode: "cors", cache: "no-store", signal: ctrl.signal });
        clearTimeout(timer);
        if (!resp.ok && resp.status !== 204) continue;
        const wallMs = performance.now() - t0;
        let rttMs = wallMs;
        if (performance.getEntriesByName) {
          const entries = performance.getEntriesByName(url);
          const e = entries[entries.length - 1];
          if (e && e.requestStart > 0 && e.responseStart > e.requestStart) {
            const rt = e.responseStart - e.requestStart;
            if (rt > 0.2 && rt <= wallMs + 5) rttMs = rt;
          }
        }
        if (r >= 1) samples.push(rttMs);
      } catch (_) {}
      if (r + 1 < totalRounds) await new Promise((res) => setTimeout(res, 18));
    }
    if (samples.length === 0) return null;
    const sorted = samples.slice().sort((a, b) => a - b);
    const minMs = sorted[0];
    const medianMs = sorted[Math.floor(sorted.length / 2)];
    const jitterMs = PogGeo.routeInstabilitySpreadMs ? PogGeo.routeInstabilitySpreadMs(sorted) : Math.max(0, medianMs - minMs);
    return { anchor, rttMs: minMs, minMs, medianMs, jitterMs, samples: sorted };
  }

  async function runLiveProbe() {
    if (state.probing) return;
    state.probing = true;
    const btn = document.getElementById("btn-probe-live");
    const label = document.getElementById("btn-probe-label");
    const progWrap = document.getElementById("probe-progress-wrap");
    const progFill = document.getElementById("probe-progress-fill");
    const progText = document.getElementById("probe-progress-text");
    const totalN = ANCHORS.length;

    btn.disabled = true;
    label.textContent = `Probing ${totalN} Anchors…`;
    progWrap.classList.remove("hidden");
    progFill.style.width = "5%";
    progText.textContent = `Phase 1: Scanning ${totalN} Anchors (diagnostic browser HTTPS)…`;

    const liveMap = new Map();
    if (performance.clearResourceTimings) performance.clearResourceTimings();

    const waveSize = totalN > 15 ? 10 : 3;
    const phase1Rounds = totalN > 15 ? 3 : 6;
    let doneP1 = 0;
    for (let wave = 0; wave < ANCHORS.length; wave += waveSize) {
      const batch = ANCHORS.slice(wave, wave + waveSize);
      await Promise.all(
        batch.map((a, idx) =>
          (async () => {
            if (idx > 0) await new Promise((r) => setTimeout(r, idx * 20));
            const res = await measureSingleAnchor(a, phase1Rounds);
            doneP1++;
            if (res) liveMap.set(a.id, res);
            const pct = totalN > 15 ? Math.round((doneP1 / totalN) * 50) : Math.round((doneP1 / totalN) * 95);
            progFill.style.width = `${Math.max(5, pct)}%`;
            progText.textContent = `Phase 1: Measured ${liveMap.size}/${totalN} Anchors…`;
          })()
        )
      );
      if (liveMap.size >= 4) {
        state.liveMeasurements = Array.from(liveMap.values()).sort((x, y) => x.minMs - y.minMs);
        redrawActiveScene(false);
      }
    }

    if (totalN > 15 && liveMap.size > 0) {
      const top12 = Array.from(liveMap.values()).sort((x, y) => x.minMs - y.minMs).slice(0, 12).map((m) => m.anchor);
      let doneP2 = 0;
      for (let w = 0; w < top12.length; w += 4) {
        const batch = top12.slice(w, w + 4);
        await Promise.all(
          batch.map((a, idx) =>
            (async () => {
              if (idx > 0) await new Promise((r) => setTimeout(r, idx * 25));
              const res = await measureSingleAnchor(a, 6);
              doneP2++;
              if (res) {
                const prev = liveMap.get(a.id);
                if (!prev || res.minMs < prev.minMs) liveMap.set(a.id, res);
              }
              progFill.style.width = `${50 + Math.round((doneP2 / top12.length) * 50)}%`;
              progText.textContent = `Phase 2: Refining closest ${top12.length} Anchors (${doneP2}/${top12.length})…`;
            })()
          )
        );
        state.liveMeasurements = Array.from(liveMap.values()).sort((x, y) => x.minMs - y.minMs);
        redrawActiveScene(false);
      }
    }

    state.liveMeasurements = Array.from(liveMap.values()).sort((a, b) => a.minMs - b.minMs);
    state.probing = false;
    btn.disabled = false;
    label.textContent = "Re-Run Live Probe";
    progFill.style.width = "100%";
    progText.textContent = `Measured ${state.liveMeasurements.length}/${totalN} Anchors (diagnostic browser HTTPS).`;
    setTimeout(() => progWrap.classList.add("hidden"), 2500);
    redrawActiveScene(true);
  }

  // --- Core Map Scene Renderer ---
  function renderGeoScene({
    measurements,
    isBrowserProbe = false,
    byzantineF = null,
    truePin = null,
    spoofClaim = null,
    fitCamera = false,
    fitToWholeWorld = false,
    disableLikelihood = false,
  }) {
    circlesLayer.clearLayers();
    raysLayer.clearLayers();
    markersLayer.clearLayers();
    spoofLayer.clearLayers();
    regionCanvasLayer.setScene(null);
    const wholeEarthBanner = document.getElementById("whole-earth-banner");
    if (wholeEarthBanner) wholeEarthBanner.classList.add("hidden");

    if (!measurements || measurements.length === 0) return null;

    const sorted = measurements.slice().sort((a, b) => (a.minMs ?? a.rttMs) - (b.minMs ?? b.rttMs));
    const effF = byzantineF !== null ? byzantineF : sorted.length >= 4 ? 1 : 0;
    const refLatLon = truePin ? [truePin[0], truePin[1]] : null;

    const solution = PogGeo.solveLocation(sorted, state.tier, {
      isBrowserProbe,
      byzantineF: effF,
      refLatLon,
      skipLikelihood: disableLikelihood,
    });
    const vacSolution =
      state.tier === "vacuum"
        ? solution
        : PogGeo.solveLocation(sorted, "vacuum", { isBrowserProbe, byzantineF: effF, refLatLon, skipLikelihood: true });

    const spoofEval = spoofClaim
      ? PogGeo.evaluateSpoofClaim(spoofClaim.lat, spoofClaim.lon, sorted, state.tier, {
          isBrowserProbe,
          byzantineF: effF,
        })
      : null;

    // 1. Render exact pixel-accurate spherical outer bound + correlated likelihood heatmap on canvas!
    regionCanvasLayer.setScene({
      disks: solution.core.disks,
      requiredCount: solution.requiredCount,
      wholeEarth: solution.wholeEarth,
      showLikelihood: state.showLikelihood && !disableLikelihood,
      likelihood: disableLikelihood ? null : solution.likelihood,
      vacuumDisks: vacSolution.core.disks,
      vacuumRequiredCount: vacSolution.requiredCount,
    });

    if (wholeEarthBanner) {
      if (solution.wholeEarth) {
        const tierLabel = PogGeo.TIERS[state.tier]?.label || "Vacuum c₀";
        const segs =
          window.innerWidth <= 900
            ? [{ tag: "strong", text: "🌐 All World Feasible (100%)" }, " · No outer boundary"]
            : [
                { tag: "strong", text: "🌐 All World Feasible (100% Earth)" },
                ` · ${tierLabel} places no geographic boundary (no false outline)`,
              ];
        wholeEarthBanner.replaceChildren(PogConstellation.buildTooltipElement(document, segs));
        wholeEarthBanner.classList.remove("hidden");
      } else {
        wholeEarthBanner.classList.add("hidden");
        wholeEarthBanner.replaceChildren();
      }
    }

    // 2. Optional individual Anchor circles (never capped at 19,000 km; capFill polygons drawn with stroke: false!)
    const violatedIds = new Set(spoofEval ? spoofEval.violations.map((v) => v.anchor.id) : []);
    let visibleCircles = solution.circles.slice();
    if (state.circleMode === "none") {
      visibleCircles = state.focusedAnchorId
        ? visibleCircles.filter((c) => c.anchor.id === state.focusedAnchorId || violatedIds.has(c.anchor.id))
        : visibleCircles.filter((c) => violatedIds.has(c.anchor.id));
    } else if (state.circleMode === "top5") {
      const keep = new Set(visibleCircles.slice(0, 5).map((c) => c.anchor.id));
      if (state.focusedAnchorId) keep.add(state.focusedAnchorId);
      for (const vid of violatedIds) keep.add(vid);
      visibleCircles = visibleCircles.filter((c) => keep.has(c.anchor.id));
    }

    const focusCenter = truePin || (solution.likelihood?.peaks?.[0] ? [solution.likelihood.peaks[0].lat, solution.likelihood.peaks[0].lon] : solution.centroid);

    for (const c of visibleCircles) {
      const tb = teeBadge(c.anchor);
      const isViolated = violatedIds.has(c.anchor.id);
      const isFocused = state.focusedAnchorId === c.anchor.id;
      const strokeColor = PogConstellation.sanitizeHexColor(isViolated ? "#f43f5e" : tb.color);
      const weight = isFocused ? 2.4 : isViolated ? 2.2 : 1.4;
      const opacity = isFocused ? 0.92 : isViolated ? 0.88 : 0.55;

      for (const shift of [-360, 0, 360]) {
        const geom = PogGeo.geodesicCircleGeometry(c.lat, c.lon, c.radiusKm, 144, shift);
        if (isFocused && geom.fill && geom.fill.length >= 3) {
          L.polygon(geom.fill, {
            stroke: false,
            fillColor: strokeColor,
            fillOpacity: 0.14,
            interactive: false,
          }).addTo(circlesLayer);
        }
        if (!geom.wholeEarth && geom.stroke && geom.stroke.length >= 2) {
          L.polyline(geom.stroke, {
            color: strokeColor,
            weight,
            opacity,
            dashArray: isViolated ? "7 5" : "4 5",
            interactive: false,
          }).addTo(circlesLayer);
        }
      }

      if (isFocused || isViolated) {
        const rayPts = PogGeo.greatCircleArc(c.lat, c.lon, focusCenter[0], focusCenter[1], 32);
        L.polyline(rayPts, {
          color: strokeColor,
          weight: 1.6,
          opacity: 0.72,
          dashArray: "4 6",
          interactive: false,
        }).addTo(raysLayer);
      }
    }

    // 3. Plot Empirical Spatial Likelihood Peak Marker(s) (Amber/Pink Diamonds — distinct from Known Target!)
    const showPeakOverlay =
      state.showLikelihood &&
      !disableLikelihood &&
      solution.likelihood &&
      solution.likelihood.peaks.length > 0 &&
      (solution.likelihood.moreLikelyAreaFraction ?? 1) < 0.85;
    if (showPeakOverlay) {
      solution.likelihood.peaks.forEach((pk, idx) => {
        for (const shift of [-360, 0, 360]) {
          const pIcon = L.divIcon({
            className: "",
            html: createIconDiv(`peak-diamond-pin${idx > 0 ? " secondary" : ""}`),
            iconSize: [14, 14],
            iconAnchor: [7, 7],
          });
          const m = L.marker([pk.lat, pk.lon + shift], { icon: pIcon, zIndexOffset: 520 });
          m.bindTooltip(
            PogConstellation.buildTooltipElement(document, [
              { tag: "strong", text: `Empirical Peak #${idx + 1} (Estimate, not proof)` },
              ` · ${fmtCoord(pk.lat, pk.lon)}`,
            ]),
            { direction: "top", offset: [0, -10], className: "anchor-label" }
          );
          m.addTo(markersLayer);
        }
      });
    }

    // 4. Plot Known Test Server / Target Marker (Crisp White/Emerald Bullseye — strictly separate from Peak!)
    if (truePin) {
      const targetInsideOuter = solution.wholeEarth || (() => {
        const tu = PogGeo.toVec3(truePin[0], truePin[1]);
        let cnt = 0;
        for (const d of solution.core.disks) {
          if (PogGeo.dot3(tu, d.u) >= d.cosTheta - 1e-11) cnt++;
        }
        return cnt >= solution.requiredCount;
      })();
      for (const shift of [-360, 0, 360]) {
        const tIcon = L.divIcon({
          className: "",
          html: createIconDiv("known-target-pin"),
          iconSize: [20, 20],
          iconAnchor: [10, 10],
        });
        const m = L.marker([truePin[0], truePin[1] + shift], { icon: tIcon, zIndexOffset: 580 });
        const rawPinLabel = String(truePin.label || "Test Server");
        const tipSegs =
          window.innerWidth <= 900
            ? [
                { tag: "strong", text: (truePin.label ? rawPinLabel : "Target").split(",")[0] },
                ` · ${targetInsideOuter ? "✅ Inside c₀" : "⚠️ Outside"}`,
              ]
            : [
                { tag: "strong", text: `Known Target: ${rawPinLabel}` },
                ` · ${targetInsideOuter ? "✅ Inside outer bound" : "⚠️ Outside active bound"}`,
              ];
        m.bindTooltip(
          PogConstellation.buildTooltipElement(document, tipSegs),
          { direction: "bottom", offset: [0, 12], permanent: shift === 0, className: "anchor-label" }
        );
        m.addTo(markersLayer);
      }
    }

    // 5. Spoof Claim Marker & Red Physics Violation Lines
    if (spoofEval) {
      const sIcon = L.divIcon({
        className: "",
        html: createIconDiv("spoof-pin"),
        iconSize: [18, 18],
        iconAnchor: [9, 9],
      });
      const sm = L.marker([spoofClaim.lat, spoofClaim.lon], { icon: sIcon, zIndexOffset: 620 });
      const spoofTipSegs = spoofEval.caught
        ? [
            "🚫 ",
            { tag: "strong", text: `EXCLUDED BY ${String(state.tier).toUpperCase()}` },
            ` (${spoofEval.violations.length} caps violated)`,
          ]
        : [`⚠️ Consistent with ${String(state.tier)} outer bound (overlap ≠ proof)`];
      sm.bindTooltip(
        PogConstellation.buildTooltipElement(document, spoofTipSegs),
        { direction: "top", offset: [0, -12], permanent: true, className: "anchor-label" }
      );
      sm.addTo(spoofLayer);

      for (const v of spoofEval.violations.slice(0, 5)) {
        const arc = PogGeo.greatCircleArc(v.anchor.lat, v.anchor.lon, spoofClaim.lat, spoofClaim.lon, 36);
        L.polyline(arc, { color: "#f43f5e", weight: 2.2, opacity: 0.85, dashArray: "6 5", interactive: false }).addTo(spoofLayer);
      }
    }

    if (fitCamera) {
      const pad = getFitPadding();
      if (fitToWholeWorld || (solution.wholeEarth && (disableLikelihood || !solution.likelihood || solution.likelihood.moreLikelyAreaKm2 > 5e6))) {
        if (window.innerWidth <= 900 && truePin) {
          map.setView([Math.max(-25, Math.min(35, truePin[0])), truePin[1]], 1, { animate: false });
        } else {
          map.setView([20, 10], window.innerWidth <= 900 ? 1 : 2, { animate: false });
        }
      } else if (solution.wholeEarth && truePin) {
        // Whole-Earth outer bound (e.g. f=1 Frankfurt with 1 EU anchor) paired with localized empirical heatmap:
        // center cleanly in the visible map viewport (accounting for left desktop panel / bottom mobile drawer)!
        const isMob = window.innerWidth <= 900;
        const latOff = isMob ? -6.5 : 0;
        const lonOff = isMob ? 0 : -4.5;
        map.setView([truePin[0] + latOff, truePin[1] + lonOff], isMob ? 4 : 5, { animate: false });
      } else {
        // Frame the outer Vacuum c0 bound extents alongside closest anchors so BOTH the crisp cyan
        // outer perimeter AND the interior empirical spatial likelihood heatmap are clearly visible!
        const framePts = [focusCenter];
        const rFrame = Math.min(solution.maxRadiusKm * 0.92, 5500);
        if (rFrame > 250) {
          for (let i = 0; i < 8; i++) {
            framePts.push(PogGeo.destPoint(focusCenter[0], focusCenter[1], (2 * Math.PI * i) / 8, rFrame));
          }
        }
        for (const c of sorted.slice(0, 4)) framePts.push([c.anchor.lat, c.anchor.lon]);
        if (spoofClaim) framePts.push([spoofClaim.lat, spoofClaim.lon]);
        const lons = framePts.map((p) => p[1]);
        const rawSpan = Math.max(...lons) - Math.min(...lons);
        let adjPts = framePts;
        if (rawSpan > 180) {
          adjPts = framePts.map(([lt, ln]) => [lt, ln < 0 ? ln + 360 : ln]);
        }
        const bounds = L.latLngBounds(adjPts);
        const capZoom = solution.maxRadiusKm > 1500 ? 4 : 6;
        map.fitBounds(bounds, Object.assign({ maxZoom: capZoom, animate: false }, pad));
      }
    }

    return { solution, vacSolution, spoofEval };
  }

  // --- Left Panel: Live Mode ---
  function renderLiveAnchorList(measurements, spoofEval, solution) {
    const listEl = document.getElementById("live-anchor-list");
    const measById = Object.fromEntries(measurements.map((m) => [m.anchor.id, m]));
    const circleById = Object.fromEntries((solution?.circles || []).map((c) => [c.anchor.id, c]));
    const violById = Object.fromEntries((spoofEval?.results || []).map((r) => [r.anchor.id, r]));
    const ordered = measurements.length ? measurements.map((m) => m.anchor) : ANCHORS;
    const maxRtt = measurements.length ? Math.max(...measurements.map((m) => m.minMs ?? m.rttMs), 20) : 200;

    const frag = document.createDocumentFragment();
    for (const a of ordered) {
      const tb = teeBadge(a);
      const m = measById[a.id];
      const v = violById[a.id];
      const radiusKm = circleById[a.id]?.radiusKm ?? null;
      const rttVal = m ? (m.minMs ?? m.rttMs) : null;
      const pct = rttVal !== null ? Math.min(100, Math.max(4, (rttVal / maxRtt) * 100)) : null;
      const isViol = !!(v && v.violated);
      const isFoc = state.focusedAnchorId === a.id;
      const metaText = isViol
        ? `🚫 +${Math.round(v.excessKm).toLocaleString()} km outside cap`
        : radiusKm !== null
        ? `Outer cap ≤ ${fmtDist(radiusKm)}`
        : String(anchorBaseUrl(a) || a.endpoint_tcp || "no https_url").replace(/^https?:\/\//, "");

      const row = PogConstellation.buildAnchorRowElement(document, {
        anchor: a,
        badge: tb,
        rttText: rttVal !== null ? `${rttVal.toFixed(1)} ms` : "ready",
        rttColor: isViol ? "#fda4af" : "var(--cyan)",
        metaText,
        barPct: pct,
        barColor: tb.color,
        isViolated: isViol,
        isFocused: isFoc,
      });
      row.addEventListener("click", () => {
        const id = row.dataset.anchor;
        state.focusedAnchorId = state.focusedAnchorId === id ? null : id;
        redrawActiveScene(false);
      });
      frag.appendChild(row);
    }
    listEl.replaceChildren(frag);
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
    const solVac = PogGeo.solveLocation(measurements, "vacuum", { isBrowserProbe: true, skipLikelihood: true });
    const solFib = PogGeo.solveLocation(measurements, "fiber", { isBrowserProbe: true, skipLikelihood: true });
    const like = res.solution.likelihood;

    document.getElementById("m-vac").textContent = solVac.wholeEarth ? "Whole Earth" : `≤ ${fmtDist(solVac.maxRadiusKm)}`;
    document.getElementById("m-vac-area").textContent = fmtArea(solVac.areaKm2);
    document.getElementById("m-fiber").textContent = solFib.wholeEarth ? "Whole Earth" : `≤ ${fmtDist(solFib.maxRadiusKm)}`;
    document.getElementById("m-fiber-area").textContent = fmtArea(solFib.areaKm2);

    if (like && like.peaks.length > 0) {
      const pk = like.peaks[0];
      document.getElementById("m-coords").textContent = fmtCoord(pk.lat, pk.lon);
      document.getElementById("m-peaks-sub").textContent = `${like.peaks.length} peak(s) · k_eff=${like.effectiveIndependentAnchors.toFixed(1)} (estimate)`;
      document.getElementById("m-like-area").textContent = fmtArea(like.moreLikelyAreaKm2);
    } else {
      document.getElementById("m-coords").textContent = "—";
      document.getElementById("m-like-area").textContent = "—";
    }
    document.getElementById("m-nearest").textContent = `Nearest: ${res.solution.nearest.anchor.city} (${res.solution.nearest.rttMs.toFixed(1)} ms)`;

    noteEl.classList.remove("hidden");
    const tierLabel = PogGeo.TIERS[state.tier].label;
    const noteSegs = res.solution.wholeEarth
      ? [
          { tag: "strong", text: "Whole Earth Feasible (No Geographic Constraint):" },
          ` Measured RTTs allow every point on Earth under conservative ${tierLabel}.`,
        ]
      : [
          { tag: "strong", text: "Diagnostic Browser Result (Not Hardware Proof):" },
          " Solid cyan outline = conservative ",
          { tag: "strong", text: tierLabel },
          " (conditional on trusted anchors & audited coordinates). Violet→amber heatmap = correlated empirical estimate (",
          { tag: "em", text: "More → Less likely" },
          ", never narrows c₀).",
        ];
    noteEl.replaceChildren(PogConstellation.buildTooltipElement(document, noteSegs));
  }

  function updateSpoofVerdict(spoofEval) {
    const el = document.getElementById("spoof-verdict");
    if (!spoofEval) {
      el.classList.add("hidden");
      return;
    }
    el.classList.remove("hidden");
    const lbl = state.spoofClaim?.label || fmtCoord(spoofEval.claimLat, spoofEval.claimLon);
    const worst = spoofEval.caught && spoofEval.violations[0] ? spoofEval.violations[0] : null;
    el.className = spoofEval.caught ? "verdict-card bad" : "verdict-card warn";
    el.replaceChildren(
      PogConstellation.buildSpoofVerdictElement(document, {
        caught: spoofEval.caught,
        tierLabel: PogGeo.TIERS[state.tier].label,
        claimLabel: lbl,
        violationCount: spoofEval.violations.length,
        totalCount: spoofEval.results.length,
        byzantineF: spoofEval.byzantineF,
        worst: worst
          ? {
              city: worst.anchor.city,
              rttText: `${worst.rttMs.toFixed(1)} ms`,
              maxDistText: fmtDist(worst.maxKm),
              claimDistText: fmtDist(worst.distKm),
              cMultipleText: worst.cMultiple.toFixed(2),
            }
          : null,
      })
    );
  }

  // --- Deterministic QA & Held-Out Scenarios ---
  function buildQaScenario(presetKey) {
    if (presetKey === "repro150") {
      // Production v6 repro: SJ, FRA, NRT @ 150 ms each -> Whole Earth (20,015 km, 100% of Earth)!
      const anchors = [
        { id: "qa-sjc", city: "San Jose, CA", cloud: "aws", defaultTee: "SoftwareDev", lat: 37.4, lon: -121.9 },
        { id: "qa-fra", city: "Frankfurt, DE", cloud: "gcp", defaultTee: "SoftwareDev", lat: 50.1, lon: 8.7 },
        { id: "qa-nrt", city: "Tokyo, JP", cloud: "aws", defaultTee: "SoftwareDev", lat: 35.7, lon: 139.7 },
      ];
      return {
        title: "150 ms Whole-Earth Repro (SJ / FRA / NRT)",
        subtitle: "Vacuum c₀ = 20,015 km (100% Earth · No Verified Constraint)",
        noteSegments: [
          { tag: "strong", text: "Whole-Earth Invariant Verified:" },
          " At 150 ms RTT, light travels 22,484 km one-way (> 20,015 km antipodal half-circumference). Every point on Earth — including the antipodal test server in Auckland, NZ — is strictly feasible and contained inside the cyan outer region!",
        ],
        measurements: anchors.map((a) => ({ anchor: a, rttMs: 150.0, minMs: 150.0, medianMs: 150.0, jitterMs: 0.0 })),
        truePin: Object.assign([-36.8485, 174.7633], { label: "Auckland, NZ (Antipodal)" }),
        byzantineF: 0,
        fitToWholeWorld: true,
        disableLikelihood: true,
      };
    }

    if (presetKey === "dateline") {
      // Pacific Dateline (±180°) crossing around Suva, Fiji (-18.14, 178.44)
      const anchors = [
        { id: "dl-syd", city: "Sydney, AU", cloud: "aws", defaultTee: "SoftwareDev", lat: -33.8688, lon: 151.2093 },
        { id: "dl-nrt", city: "Tokyo, JP", cloud: "aws", defaultTee: "SoftwareDev", lat: 35.6895, lon: 139.6917 },
        { id: "dl-hnl", city: "Honolulu, HI", cloud: "gcp", defaultTee: "SoftwareDev", lat: 21.3069, lon: -157.8583 },
        { id: "dl-sjc", city: "San Jose, CA", cloud: "aws", defaultTee: "SoftwareDev", lat: 37.3382, lon: -121.8863 },
        { id: "dl-scl", city: "Santiago, CL", cloud: "azure", defaultTee: "SoftwareDev", lat: -33.4489, lon: -70.6693 },
      ];
      const tgt = [-18.1416, 178.4419];
      const meas = anchors.map((a) => {
        const dKm = PogGeo.haversineKm(tgt[0], tgt[1], a.lat, a.lon);
        const rtt = Math.max(4.0, 2.0 + (2.0 * dKm) / 138.0);
        return { anchor: a, rttMs: rtt, minMs: rtt, medianMs: rtt + 0.1, jitterMs: 0.1 };
      });
      return {
        title: "Pacific Dateline (±180° Crossing)",
        subtitle: "Synthetic Dateline QA · Zero Mercator Tear",
        noteSegments: [
          { tag: "strong", text: "Dateline Continuity Verified:" },
          " Both the cyan Vacuum c₀ outer bound and the empirical spatial likelihood heatmap wrap seamlessly across ±180° longitude and contain Suva, Fiji.",
        ],
        measurements: meas,
        truePin: Object.assign(tgt, { label: "Suva, Fiji (±180°)" }),
        byzantineF: 0,
        fitToWholeWorld: false,
      };
    }

    if (presetKey === "polar") {
      // Arctic Polar Cap around Tromsø, Norway (69.65, 18.96)
      const anchors = [
        { id: "pl-anc", city: "Anchorage, AK", cloud: "gcp", defaultTee: "SoftwareDev", lat: 61.2181, lon: -149.9003 },
        { id: "pl-hel", city: "Helsinki, FI", cloud: "gcp", defaultTee: "SoftwareDev", lat: 60.1699, lon: 24.9384 },
        { id: "pl-arn", city: "Stockholm, SE", cloud: "aws", defaultTee: "SoftwareDev", lat: 59.3293, lon: 18.0686 },
        { id: "pl-dub", city: "Dublin, IE", cloud: "aws", defaultTee: "SoftwareDev", lat: 53.3498, lon: -6.2603 },
        { id: "pl-yul", city: "Montreal, CA", cloud: "aws", defaultTee: "SoftwareDev", lat: 45.5017, lon: -73.5673 },
      ];
      const tgt = [69.6492, 18.9553];
      const meas = anchors.map((a) => {
        const dKm = PogGeo.haversineKm(tgt[0], tgt[1], a.lat, a.lon);
        const rtt = Math.max(4.0, 2.0 + (2.0 * dKm) / 136.0);
        return { anchor: a, rttMs: rtt, minMs: rtt, medianMs: rtt + 0.1, jitterMs: 0.1 };
      });
      return {
        title: "Arctic Polar Cap (High-Latitude QA)",
        subtitle: "Synthetic Polar QA · Zero Hemisphere Inversion",
        noteSegments: [
          { tag: "strong", text: "Polar Geometry Verified:" },
          " Pixel-exact spherical rendering eliminates Mercator pole-wrapping inversions while strictly containing Tromsø, Norway inside the cyan outer bound.",
        ],
        measurements: meas,
        truePin: Object.assign(tgt, { label: "Tromsø, NO (69.6°N)" }),
        byzantineF: 0,
        fitToWholeWorld: false,
      };
    }

    if (presetKey === "multipeak") {
      // 2 symmetric equatorial anchors -> 2 supported peaks (North & South of Equator)!
      const anchors = [
        { id: "mp-w", city: "West Atlantic Anchor", cloud: "aws", defaultTee: "SoftwareDev", lat: 0.0, lon: -15.0 },
        { id: "mp-e", city: "East Atlantic Anchor", cloud: "gcp", defaultTee: "SoftwareDev", lat: 0.0, lon: 15.0 },
      ];
      return {
        title: "Multi-Peak Ambiguity (2 Symmetric Anchors)",
        subtitle: "2 Supported Likelihood Peaks Inside Single Vacuum Lens",
        noteSegments: [
          { tag: "strong", text: "Multi-Peak Support Verified:" },
          " Two equidistant anchors leave a North/South mirror ambiguity. The empirical likelihood heatmap displays BOTH supported peaks (amber & pink diamonds) without manufacturing false certainty.",
        ],
        measurements: anchors.map((a) => ({ anchor: a, rttMs: 35.0, minMs: 34.8, medianMs: 35.0, jitterMs: 0.2 })),
        truePin: null,
        byzantineF: 0,
        fitToWholeWorld: false,
      };
    }

    if (presetKey === "chicago" || presetKey === "seoul") {
      const vmId = presetKey === "chicago" ? "azure-northcentralus-chicago" : "azure-koreacentral-seoul";
      const rec = state.qaHeldoutData?.targets?.[vmId];
      if (!rec) return null;
      const meas = rec.measurements.map((m) => ({
        anchor: {
          id: m.anchor_id,
          city: m.city,
          cloud: m.cloud,
          defaultTee: "SoftwareDev",
          lat: m.lat,
          lon: m.lon,
        },
        rttMs: m.min_ms,
        minMs: m.min_ms,
        medianMs: m.median_ms,
        jitterMs: m.jitter_ms,
      }));
      return {
        title: `Held-Out Server: ${rec.target.city} (T2)`,
        subtitle: `${meas.length} Non-Self Anchors · Unverified Software Diagnostic (NOT HW Proof)`,
        noteSegments: [
          { tag: "strong", text: "Real Held-Out Known Server (Diagnostic — NOT Hardware Proof):" },
          " Self-excluded 12-round UDP measurement from Azure ",
          { tag: "code", text: vmId },
          ` (${rec.failures.length} probe failures preserved). Solid cyan outline = conservative Vacuum c₀ outer bound containing ${rec.target.city}; heatmap = correlated empirical estimate (More → Less likely).`,
        ],
        measurements: meas,
        truePin: Object.assign([rec.target.lat, rec.target.lon], { label: `${rec.target.city} (Held-Out Target)` }),
        byzantineF: 0,
        fitToWholeWorld: false,
      };
    }

    return null;
  }

  // --- Mode 2: Cloud Mesh & QA Diagnostics ---
  async function loadMeshData() {
    try {
      const resp = await fetch("/data/live_mesh_summary.json");
      if (resp.ok) state.meshData = await resp.json();
    } catch (_) {}
    try {
      const qaResp = await fetch("/data/qa_heldout_targets.json?v=10");
      if (qaResp.ok) state.qaHeldoutData = await qaResp.json();
    } catch (_) {}
    renderMeshPicker();
    applyUrlPresetIfAny();
  }

  function renderMeshPicker() {
    const el = document.getElementById("mesh-prover-picker");
    const frag = document.createDocumentFragment();
    for (const a of LEGACY_MESH_ANCHORS) {
      const tb = teeBadge(a);
      const isActive = !state.activeQaPreset && state.selectedMeshProver === a.id;
      const btn = PogConstellation.buildMeshPickerButtonElement(document, { anchor: a, badge: tb, isActive });
      btn.addEventListener("click", () => {
        state.activeQaPreset = null;
        state.selectedMeshProver = btn.dataset.prover;
        document.querySelectorAll(".qa-preset").forEach((c) => c.classList.remove("active"));
        renderMeshPicker();
        redrawActiveScene(true);
      });
      frag.appendChild(btn);
    }
    el.replaceChildren(frag);
  }

  function renderMeshAnchorList(measurements = null, sol = null) {
    const el = document.getElementById("mesh-anchor-list");
    // Always exclude the selected prover itself (never show self-probe as a peer measurement!)
    const list = (
      measurements ||
      LEGACY_MESH_ANCHORS.filter((a) => a.id !== state.selectedMeshProver).map((a) => ({
        anchor: a,
        rttMs: state.meshData?.provers?.[state.selectedMeshProver]?.rtts_ms?.[a.id],
      }))
    ).filter((item) => item.anchor && item.anchor.id !== state.selectedMeshProver);
    const circleById = Object.fromEntries((sol?.circles || []).map((c) => [c.anchor.id, c]));

    const frag = document.createDocumentFragment();
    for (const item of list.slice(0, 18)) {
      const a = item.anchor;
      const tb = teeBadge(a);
      const rtt = item.minMs ?? item.rttMs;
      const rad = circleById[a.id]?.radiusKm;
      const row = PogConstellation.buildAnchorRowElement(document, {
        anchor: a,
        badge: tb,
        rttText: rtt !== undefined ? `${rtt.toFixed(2)} ms` : "—",
        rttColor: null,
        metaText: rad !== undefined ? `Cap ≤ ${fmtDist(rad)}` : a.id,
        isFocused: state.focusedAnchorId === a.id,
      });
      row.addEventListener("click", () => {
        const id = row.dataset.anchor;
        state.focusedAnchorId = state.focusedAnchorId === id ? null : id;
        redrawActiveScene(false);
      });
      frag.appendChild(row);
    }
    el.replaceChildren(frag);
  }

  function renderMeshScene(fitCamera) {
    const noteEl = document.getElementById("mesh-note");

    if (state.activeQaPreset && state.activeQaPreset !== "frankfurt") {
      const qa = buildQaScenario(state.activeQaPreset);
      if (!qa) return;
      const res = renderGeoScene({
        measurements: qa.measurements,
        isBrowserProbe: false,
        byzantineF: qa.byzantineF,
        truePin: qa.truePin,
        fitCamera,
        fitToWholeWorld: qa.fitToWholeWorld,
        disableLikelihood: !!qa.disableLikelihood,
      });
      if (!res) return;
      const sol = res.solution;
      const like = sol.likelihood;
      document.getElementById("mesh-name").textContent = qa.title;
      document.getElementById("mesh-tee").textContent = qa.subtitle;
      document.getElementById("mesh-best").textContent = sol.wholeEarth ? "20,015 km (Whole Earth)" : `≤ ${fmtDist(sol.maxRadiusKm)}`;
      document.getElementById("mesh-best-sub").textContent = `${fmtArea(sol.areaKm2)} (f=${sol.byzantineF})`;
      if (like && like.peaks.length > 0 && !sol.wholeEarth) {
        const pk = like.peaks[0];
        document.getElementById("mesh-peak").textContent = fmtCoord(pk.lat, pk.lon);
        document.getElementById("mesh-peak-sub").textContent = `${like.peaks.length} peak(s) · k_eff=${like.effectiveIndependentAnchors.toFixed(1)} (estimate)`;
        document.getElementById("mesh-like-area").textContent = fmtArea(like.moreLikelyAreaKm2);
        document.getElementById("mesh-like-sub").textContent = `Plausible: ${fmtArea(like.plausibleAreaKm2)}`;
      } else {
        document.getElementById("mesh-peak").textContent = sol.wholeEarth ? "Whole Earth" : "—";
        document.getElementById("mesh-peak-sub").textContent = "No constraint";
        document.getElementById("mesh-like-area").textContent = fmtArea(sol.areaKm2);
        document.getElementById("mesh-like-sub").textContent = "Empirical estimate disabled on whole Earth";
      }
      noteEl.classList.remove("hidden");
      noteEl.replaceChildren(PogConstellation.buildTooltipElement(document, qa.noteSegments));
      renderMeshAnchorList(qa.measurements, sol);
      return;
    }

    // Historical 9x9 Cloud Mesh Fixture (preserving all 9 legacy anchor coords!)
    const proverAnchor = LEGACY_BY_ID[state.selectedMeshProver] || ANCHOR_BY_ID[state.selectedMeshProver];
    const proverData = state.meshData?.provers?.[state.selectedMeshProver];
    if (!proverAnchor || !proverData) return;

    const measurements = Object.entries(proverData.rtts_ms || {})
      .filter(([aid]) => aid !== state.selectedMeshProver && (LEGACY_BY_ID[aid] || ANCHOR_BY_ID[aid]))
      .map(([aid, rttMs]) => ({
        anchor: LEGACY_BY_ID[aid] || ANCHOR_BY_ID[aid],
        rttMs,
        minMs: rttMs,
        medianMs: rttMs,
        jitterMs: 0,
      }))
      .sort((a, b) => a.rttMs - b.rttMs);

    const res = renderGeoScene({
      measurements,
      isBrowserProbe: false,
      byzantineF: 1,
      truePin: Object.assign([proverAnchor.lat, proverAnchor.lon], { label: `${proverAnchor.city} (Known Target)` }),
      fitCamera,
    });
    if (!res) return;
    const sol = res.solution;
    const like = sol.likelihood;

    document.getElementById("mesh-name").textContent = proverAnchor.city;
    document.getElementById("mesh-tee").textContent = `Historical 9×9 Fixture · Self-Excluded (${measurements.length} Peers)`;
    document.getElementById("mesh-best").textContent = sol.wholeEarth ? "Whole Earth" : `≤ ${fmtDist(sol.maxRadiusKm)}`;
    document.getElementById("mesh-best-sub").textContent = `${fmtArea(sol.areaKm2)} (${PogGeo.TIERS[state.tier].id}, f=1)`;
    if (like && like.peaks.length > 0) {
      const pk = like.peaks[0];
      const errKm = PogGeo.haversineKm(proverAnchor.lat, proverAnchor.lon, pk.lat, pk.lon);
      document.getElementById("mesh-peak").textContent = fmtCoord(pk.lat, pk.lon);
      document.getElementById("mesh-peak-sub").textContent = `${like.peaks.length} peak(s) · ${Math.round(errKm)} km from target (est.)`;
      document.getElementById("mesh-like-area").textContent = fmtArea(like.moreLikelyAreaKm2);
      document.getElementById("mesh-like-sub").textContent = `Plausible: ${fmtArea(like.plausibleAreaKm2)} (estimate, not proof)`;
    }
    const selfRtt = proverData.rtts_ms?.[state.selectedMeshProver];
    const meshNoteSegs = [
      { tag: "strong", text: "Historical Diagnostic Fixture (Not Live Hardware Proof):" },
      " Solid cyan outline = conservative ",
      { tag: "strong", text: PogGeo.TIERS[state.tier].label },
      ` containing ${proverAnchor.city}.`,
    ];
    if (typeof selfRtt === "number") {
      meshNoteSegs.push(
        " Self-probe (",
        { tag: "code", text: `${selfRtt.toFixed(2)} ms` },
        ") is strictly excluded for independent validation."
      );
    }
    meshNoteSegs.push(
      " Heatmap = empirical spatial likelihood estimate (",
      { tag: "em", text: "More → Less likely" },
      ")."
    );
    noteEl.classList.remove("hidden");
    noteEl.replaceChildren(PogConstellation.buildTooltipElement(document, meshNoteSegs));
    renderMeshAnchorList(measurements, sol);
  }

  // --- Mode 2B: 72-Node Rim-Surrounded Global Grid Explorer ---
  async function loadGrid72Data() {
    try {
      const resp = await fetch("/data/grid_72.json");
      if (resp.ok) state.grid72Data = await resp.json();
    } catch (_) {}
  }

  function bearingQuadrant(fromLat, fromLon, toLat, toLon) {
    const dLat = toLat - fromLat;
    let dLon = toLon - fromLon;
    while (dLon > 180) dLon -= 360;
    while (dLon < -180) dLon += 360;
    if (dLat >= 0 && dLon >= 0) return "NE";
    if (dLat < 0 && dLon >= 0) return "SE";
    if (dLat < 0 && dLon < 0) return "SW";
    return "NW";
  }

  function selectGrid72Committee(lat, lon) {
    const all = state.grid72Data?.anchors || [];
    if (!all.length) return { selected: [], quads: new Set() };
    const scored = all
      .map((a) => ({
        anchor: a,
        distKm: PogGeo.haversineKm(lat, lon, a.lat, a.lon),
        quad: bearingQuadrant(lat, lon, a.lat, a.lon),
      }))
      .sort((a, b) => a.distKm - b.distKm);

    const picked = [];
    const usedIds = new Set();
    const usedClouds = new Set();
    const quads = new Set();
    for (const s of scored) {
      if (s.distKm > 150 || picked.length >= 2) break;
      if (!usedClouds.has(s.anchor.cloud)) {
        picked.push(s); usedIds.add(s.anchor.id); usedClouds.add(s.anchor.cloud); quads.add(s.quad);
      }
    }
    for (const q of ["NE", "SE", "SW", "NW"]) {
      const cand = scored.find((s) => !usedIds.has(s.anchor.id) && s.quad === q && s.distKm > 40 && s.distKm < 6500);
      if (cand && picked.length < 6) {
        picked.push(cand); usedIds.add(cand.anchor.id); usedClouds.add(cand.anchor.cloud); quads.add(q);
      }
    }
    for (const s of scored) {
      if (picked.length >= 6) break;
      if (!usedIds.has(s.anchor.id)) {
        picked.push(s); usedIds.add(s.anchor.id); quads.add(s.quad);
      }
    }
    return { selected: picked, quads };
  }

  function renderGrid72Scene(fitCamera) {
    grid72Layer.clearLayers();
    const all = state.grid72Data?.anchors || [];
    if (!all.length) return;
    const tgt = state.grid72Target;
    const { selected, quads } = selectGrid72Committee(tgt.lat, tgt.lon);
    const selIds = new Set(selected.map((s) => s.anchor.id));

    const theaterColor = (a) => {
      if (a.theater === "eu_rim" || a.theater === "na_rim") return "#f472b6";
      if (a.cloud === "aws") return "#f59e0b";
      if (a.cloud === "gcp") return "#38bdf8";
      return "#a78bfa";
    };

    for (const a of all) {
      const isSel = selIds.has(a.id);
      const col = theaterColor(a);
      for (const shift of [-360, 0, 360]) {
        L.circleMarker([a.lat, a.lon + shift], {
          radius: isSel ? 7 : 4,
          color: isSel ? "#ffffff" : "#050914",
          weight: isSel ? 2.2 : 1.2,
          fillColor: col,
          fillOpacity: isSel ? 1 : 0.65,
        }).addTo(grid72Layer);
      }
    }

    const measurements = selected.map((s) => {
      const rttMs = Math.max(1.5, (2.0 * s.distKm * 1.38) / 204.0 + 1.2);
      return {
        anchor: { id: s.anchor.id, city: s.anchor.city, cloud: s.anchor.cloud, defaultTee: s.anchor.tee, lat: s.anchor.lat, lon: s.anchor.lon, color: theaterColor(s.anchor) },
        rttMs, minMs: rttMs, medianMs: rttMs, jitterMs: 0, quad: s.quad, role: s.anchor.role,
      };
    });

    const solVac = PogGeo.solveLocation(measurements, "vacuum", { byzantineF: 1, refLatLon: [tgt.lat, tgt.lon], skipLikelihood: true });
    const solFib = PogGeo.solveLocation(measurements, "fiber", { byzantineF: 1, refLatLon: [tgt.lat, tgt.lon], skipLikelihood: true });
    document.getElementById("g72-city").textContent = tgt.label;
    document.getElementById("g72-quads").textContent = `Simulated · Quadrants: ${quads.size}/4 (${Array.from(quads).sort().join("·")})`;
    document.getElementById("g72-cal").textContent = `c₀ ≤ ${fmtDist(solVac.maxRadiusKm)}`;
    document.getElementById("g72-fib").textContent = `Fiber: ≤ ${fmtDist(solFib.maxRadiusKm)}`;

    const g72List = document.getElementById("g72-committee-list");
    const g72Frag = document.createDocumentFragment();
    for (const m of measurements) {
      g72Frag.appendChild(
        PogConstellation.buildAnchorRowElement(document, {
          anchor: m.anchor,
          badge: {
            label: `${m.quad} · ${String(m.anchor.cloud || "").toUpperCase()}`,
            cls: "tee-tdx",
            color: m.anchor.color,
          },
          rttText: `${m.rttMs.toFixed(1)} ms`,
          rttColor: null,
          metaText: `${String(m.role || "")} (simulated)`,
          interactive: false,
        })
      );
    }
    g72List.replaceChildren(g72Frag);

    renderGeoScene({
      measurements,
      isBrowserProbe: false,
      byzantineF: 1,
      truePin: Object.assign([tgt.lat, tgt.lon], { label: `${tgt.label} (Simulated)` }),
      fitCamera,
    });
  }

  // --- Mode 3: Verify X-PoG-Proof Header ---
  async function verifyHeaderInput() {
    const headerVal = document.getElementById("verify-input").value.trim();
    const verdictEl = document.getElementById("verify-verdict");
    const jsonEl = document.getElementById("verify-json");
    if (!headerVal) return;

    verdictEl.className = "verdict-card ok";
    verdictEl.classList.remove("hidden");
    verdictEl.textContent = "Inspecting bundle & querying verifier API…";

    let decodedBundle = null;
    try {
      const b64 = headerVal.replace(/-/g, "+").replace(/_/g, "/");
      const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
      decodedBundle = JSON.parse(atob(padded));
    } catch (_) {}

    try {
      const resp = await fetch("/v1/verify-header", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ header_value: headerVal }),
      });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data = await resp.json();
      jsonEl.classList.remove("hidden");
      jsonEl.textContent = JSON.stringify(data, null, 2);

      if (data.overall_valid && data.hardware_attested !== false) {
        const vacKm = data.tier1a_vacuum?.proven_max_radius_km;
        verdictEl.className = "verdict-card ok";
        verdictEl.replaceChildren(
          PogConstellation.buildVerifyVerdictElement(document, {
            status: "verified",
            vacDistText: vacKm ? fmtDist(vacKm) : "—",
          })
        );
      } else {
        verdictEl.className = "verdict-card bad";
        verdictEl.replaceChildren(
          PogConstellation.buildVerifyVerdictElement(document, {
            status: "rejected",
            failureReasons: Array.isArray(data.failure_reasons)
              ? data.failure_reasons
              : [data.error || "Rejected by fail-closed policy"],
          })
        );
      }
    } catch (_) {
      // Static local preview mode (no backend API running): inspect decoded bundle honestly!
      if (decodedBundle) {
        jsonEl.classList.remove("hidden");
        jsonEl.textContent = JSON.stringify({
          local_preview_note: "Static preview has no backend verifier API; showing decoded bundle inspection (UNVERIFIED).",
          prover_tee_vendor: decodedBundle.prover_quote?.vendor,
          receipt_count: decodedBundle.receipts?.length || 0,
          target_location: decodedBundle.target_location,
        }, null, 2);
        verdictEl.className = "verdict-card warn";
        verdictEl.replaceChildren(
          PogConstellation.buildVerifyVerdictElement(document, {
            status: "local_decoded",
            localVendor: decodedBundle.prover_quote?.vendor || "unknown",
            receiptCount: decodedBundle.receipts?.length || 0,
          })
        );
      } else {
        verdictEl.className = "verdict-card bad";
        verdictEl.replaceChildren(
          PogConstellation.buildVerifyVerdictElement(document, {
            status: "invalid",
            invalidMessage: "Invalid base64url X-PoG-Proof bundle.",
          })
        );
      }
    }

    if (decodedBundle?.receipts) {
      state.verifyBundleData = decodedBundle;
      redrawActiveScene(true);
    }
  }

  function renderVerifyScene(fitCamera) {
    const b = state.verifyBundleData;
    if (!b || !b.receipts) return;
    const measurements = b.receipts
      .filter((r) => LEGACY_BY_ID[r.anchor_id] || ANCHOR_BY_ID[r.anchor_id])
      .map((r) => ({
        anchor: LEGACY_BY_ID[r.anchor_id] || ANCHOR_BY_ID[r.anchor_id],
        rttMs: r.rtt_min_us / 1000.0,
        minMs: r.rtt_min_us / 1000.0,
        medianMs: (r.rtt_p50_us || r.rtt_min_us) / 1000.0,
        jitterMs: Math.max(0, ((r.rtt_p50_us || r.rtt_min_us) - r.rtt_min_us) / 1000.0),
      }));
    const tgt = b.target_location
      ? Object.assign([b.target_location.lat, b.target_location.lon], { label: "Bundle Claimed Target" })
      : null;
    renderGeoScene({ measurements, isBrowserProbe: false, byzantineF: 1, truePin: tgt, fitCamera });
  }

  // --- Central Redraw Dispatcher ---
  function redrawActiveScene(fitCamera = false) {
    if (state.tab !== "grid72") grid72Layer.clearLayers();
    if (state.tab === "live") {
      const res = renderGeoScene({
        measurements: state.liveMeasurements,
        isBrowserProbe: true,
        spoofClaim: state.spoofMode ? state.spoofClaim : null,
        fitCamera,
      });
      renderLiveAnchorList(state.liveMeasurements, res?.spoofEval || null, res?.solution || null);
      updateLiveSummary(state.liveMeasurements, res);
      updateSpoofVerdict(res?.spoofEval || null);
    } else if (state.tab === "mesh") {
      renderMeshScene(fitCamera);
    } else if (state.tab === "grid72") {
      renderGrid72Scene(fitCamera);
    } else if (state.tab === "verify") {
      renderVerifyScene(fitCamera);
    }
  }

  function switchTab(tabName, fit = false) {
    state.tab = tabName;
    document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t.dataset.tab === tabName));
    document.querySelectorAll(".tab-pane").forEach((p) => p.classList.toggle("active", p.id === `pane-${tabName}`));
    state.focusedAnchorId = null;
    redrawActiveScene(fit);
  }

  function applyUrlPresetIfAny() {
    const params = new URLSearchParams(window.location.search);
    if (params.get("panel") === "collapsed") {
      document.getElementById("panel").classList.add("collapsed");
    }
    const tierParam = params.get("tier");
    if (tierParam === "vacuum" || tierParam === "fiber") {
      state.tier = tierParam;
      document.querySelectorAll("#tier-switcher .seg-btn").forEach((b) => b.classList.toggle("active", b.dataset.tier === tierParam));
    }
    const circlesParam = params.get("circles");
    if (circlesParam === "top5" || circlesParam === "all" || circlesParam === "none") {
      state.circleMode = circlesParam;
      document.querySelectorAll("#circle-switcher .seg-btn").forEach((b) => b.classList.toggle("active", b.dataset.circles === circlesParam));
    }
    const qa = params.get("qa");
    if (qa) {
      state.activeQaPreset = qa;
      if (qa === "frankfurt") {
        state.selectedMeshProver = "gcp-europe-west3-frankfurt";
        state.activeQaPreset = null;
      } else if (qa === "frankfurt_aws") {
        state.selectedMeshProver = "aws-eu-central-1-frankfurt";
        state.activeQaPreset = null;
      }
      document.querySelectorAll(".qa-preset").forEach((c) => c.classList.toggle("active", c.dataset.qa === qa));
      renderMeshPicker();
      switchTab("mesh", true);
    }
  }

  // --- Event Wiring ---
  document.querySelectorAll(".tab").forEach((btn) => {
    btn.addEventListener("click", () => {
      switchTab(btn.dataset.tab, btn.dataset.tab === "mesh" || btn.dataset.tab === "grid72");
    });
  });

  function togglePanel() {
    document.getElementById("panel").classList.toggle("collapsed");
  }
  document.getElementById("panel-toggle").addEventListener("click", togglePanel);
  const mobileBtn = document.getElementById("mobile-panel-btn");
  if (mobileBtn) mobileBtn.addEventListener("click", togglePanel);

  document.getElementById("btn-probe-live").addEventListener("click", runLiveProbe);

  document.getElementById("btn-spoof-toggle").addEventListener("click", async () => {
    state.spoofMode = !state.spoofMode;
    document.getElementById("btn-spoof-toggle").classList.toggle("active", state.spoofMode);
    document.getElementById("spoof-box").classList.toggle("hidden", !state.spoofMode);
    if (state.spoofMode && state.liveMeasurements.length === 0) await runLiveProbe();
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

  document.querySelectorAll(".qa-preset").forEach((btn) => {
    btn.addEventListener("click", () => {
      const qa = btn.dataset.qa;
      document.querySelectorAll(".qa-preset").forEach((c) => c.classList.toggle("active", c === btn));
      if (qa === "frankfurt") {
        state.activeQaPreset = null;
        state.selectedMeshProver = "gcp-europe-west3-frankfurt";
        renderMeshPicker();
      } else {
        state.activeQaPreset = qa;
        renderMeshPicker();
      }
      redrawActiveScene(true);
    });
  });

  map.on("click", (ev) => {
    let lon = ev.latlng.lng;
    while (lon > 180) lon -= 360;
    while (lon < -180) lon += 360;
    if (state.tab === "live" && state.spoofMode && state.liveMeasurements.length > 0) {
      state.spoofClaim = { lat: ev.latlng.lat, lon, label: `Clicked (${fmtCoord(ev.latlng.lat, lon)})` };
      redrawActiveScene(false);
    } else if (state.tab === "grid72") {
      state.grid72Target = { lat: ev.latlng.lat, lon, label: fmtCoord(ev.latlng.lat, lon) };
      redrawActiveScene(false);
    }
  });

  document.querySelectorAll(".grid72-city").forEach((btn) => {
    btn.addEventListener("click", () => {
      const [latStr, lonStr, ...labelParts] = btn.dataset.city.split(",");
      state.grid72Target = { lat: parseFloat(latStr), lon: parseFloat(lonStr), label: labelParts.join(",") };
      redrawActiveScene(true);
    });
  });

  document.querySelectorAll("#tier-switcher .seg-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      state.tier = btn.dataset.tier;
      document.querySelectorAll("#tier-switcher .seg-btn").forEach((b) => b.classList.toggle("active", b === btn));
      redrawActiveScene(false);
    });
  });

  document.querySelectorAll("#likelihood-switcher .seg-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      state.showLikelihood = btn.dataset.likelihood === "on";
      document.querySelectorAll("#likelihood-switcher .seg-btn").forEach((b) => b.classList.toggle("active", b === btn));
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
      if (!sample) return;
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

  // Expose read-only scene/map handles for deterministic Leaflet pixel verification tests
  window.__pogDebug = {
    map,
    circlesLayer,
    regionCanvasLayer,
    renderGeoScene,
    getState: () => ({ tab: state.tab, tier: state.tier, wholeEarthBannerVisible: !document.getElementById("whole-earth-banner")?.classList.contains("hidden") }),
  };

  // --- Boot ---
  (async () => {
    await loadLiveAnchorsList();
    renderAnchorMarkers();
    renderLiveAnchorList([], null, null);
    await loadMeshData();
    loadGrid72Data();
    refreshAnchorInfos();
  })();
})();
