/* Proof of Geography — Isolated Official vs. External Constellation Manager & Safe DOM Renderers
 *
 * Security & Governance Invariants:
 * 1. The official Proof of Geography constellation (`web/data/anchors.json`) contains ONLY
 *    nodes operated by Proof of Geography. External registries NEVER merge into, mutate,
 *    or alter the official roster, official counts, or official hardware TEE counts.
 * 2. `?registry=<url>` selects a SEPARATE, independently operated constellation rather than
 *    merging it with the official constellation.
 * 3. Optional per-anchor `https_url` lets independent operators serve their own HTTPS
 *    `/info` and `/ping` endpoints; external anchors NEVER fall back to `*.a.proofofgeography.com`.
 * 4. Hardware TEE verification (Intel TDX, AMD SEV-SNP, AWS Nitro) is counted strictly within
 *    the selected constellation and NEVER confers official Proof of Geography membership.
 * 5. ALL independent registry fields, verifier failure reasons, and decoded proof vendor strings
 *    are untrusted data: colors and URLs are strictly validated, and all DOM rendering uses
 *    `createElement` + `textContent` + `dataset` (zero `innerHTML`).
 */
(function (root) {
  "use strict";

  const OFFICIAL_NETWORK_ID = "proofofgeography.com";
  const OFFICIAL_OPERATOR_NAME = "Proof of Geography";
  const DEFAULT_ANCHORS_URL = "/data/anchors.json";
  const HEX_COLOR_RE = /^#[0-9a-fA-F]{3}([0-9a-fA-F]{3})?$/;
  const DNS_LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;
  const ALLOWED_BADGE_CLASSES = new Set(["tee-tdx", "tee-snp", "tee-aws", "tee-dev"]);

  function sanitizeHexColor(rawColor, fallback = "#a78bfa") {
    const safeFallback =
      typeof fallback === "string" && HEX_COLOR_RE.test(fallback.trim())
        ? fallback.trim()
        : "#a78bfa";
    if (typeof rawColor !== "string") return safeFallback;
    const trimmed = rawColor.trim();
    return HEX_COLOR_RE.test(trimmed) ? trimmed : safeFallback;
  }

  function safeBadgeClass(cls) {
    return ALLOWED_BADGE_CLASSES.has(cls) ? cls : "tee-dev";
  }

  function cloudColor(cloud) {
    const c = String(cloud || "").toLowerCase();
    if (c === "gcp") return "#38bdf8";
    if (c === "aws") return "#f59e0b";
    if (c === "azure") return "#10b981";
    return "#a78bfa";
  }

  function teeBadgeForVendor(vendor, cloud) {
    const v = String(vendor || "SoftwareDev");
    if (v === "IntelTdx" || v === "Intel TDX") {
      return { label: "Intel TDX", cls: "tee-tdx", color: "#38bdf8", isHw: true, vendor: "IntelTdx" };
    }
    if (v === "AmdSevSnp" || v === "AMD SEV-SNP") {
      return { label: "AMD SEV-SNP", cls: "tee-snp", color: "#818cf8", isHw: true, vendor: "AmdSevSnp" };
    }
    if (v === "AwsNitro" || v === "AWS Nitro") {
      return { label: "AWS Nitro", cls: "tee-aws", color: "#f59e0b", isHw: true, vendor: "AwsNitro" };
    }
    const rawCloud = cloud ? String(cloud).trim() : "";
    const prefix = rawCloud ? rawCloud.toUpperCase().slice(0, 24) : "DEV";
    return {
      label: `${prefix} SoftwareDev`,
      cls: "tee-dev",
      color: sanitizeHexColor(cloudColor(cloud)),
      isHw: false,
      vendor: "SoftwareDev",
    };
  }

  function isLoopbackHost(hostname) {
    return hostname === "127.0.0.1" || hostname === "localhost" || hostname === "::1" || hostname === "[::1]";
  }

  function validateHttpsOrLocalUrl(rawUrl, pageOrigin) {
    if (typeof rawUrl !== "string") return null;
    const trimmed = rawUrl.trim();
    if (!trimmed || /[\u0000-\u001f\u007f]/.test(trimmed)) return null;
    let parsed;
    try {
      parsed = pageOrigin ? new URL(trimmed, pageOrigin) : new URL(trimmed);
    } catch (_) {
      return null;
    }
    if (parsed.username || parsed.password) return null;
    if (parsed.protocol === "https:") {
      return parsed.href.replace(/\/+$/, "");
    }
    if (parsed.protocol === "http:" && isLoopbackHost(parsed.hostname)) {
      if (!pageOrigin) return parsed.href.replace(/\/+$/, "");
      try {
        const orig = new URL(pageOrigin);
        if (isLoopbackHost(orig.hostname)) {
          return parsed.href.replace(/\/+$/, "");
        }
      } catch (_) {}
    }
    return null;
  }

  function normalizeAnchor(raw, { isOfficial, pageOrigin } = {}) {
    if (!raw || typeof raw !== "object") return null;
    const id = String(raw.id || raw.anchor_id || "").trim();
    const lat = Number(raw.lat ?? raw.location?.lat);
    const lon = Number(raw.lon ?? raw.location?.lon);
    if (!id || !Number.isFinite(lat) || !Number.isFinite(lon) || lat < -90 || lat > 90 || lon < -180 || lon > 180) {
      return null;
    }
    const cloud = String(raw.cloud || raw.cloud_provider || "custom").trim().toLowerCase();
    const rawTee = raw.defaultTee || raw.tee_vendor || "SoftwareDev";
    const normTee =
      rawTee === "IntelTdx" || rawTee === "Intel TDX" ? "IntelTdx"
      : rawTee === "AmdSevSnp" || rawTee === "AMD SEV-SNP" ? "AmdSevSnp"
      : rawTee === "AwsNitro" || rawTee === "AWS Nitro" ? "AwsNitro"
      : "SoftwareDev";

    const rawHttps = raw.https_url || raw.httpsUrl || null;
    const validatedHttps = rawHttps ? validateHttpsOrLocalUrl(rawHttps, pageOrigin) : null;
    const rawSlug = raw.slug ? String(raw.slug).trim() : null;
    const slug = rawSlug && DNS_LABEL_RE.test(rawSlug) ? rawSlug : null;

    return Object.freeze({
      id,
      slug,
      city: String(raw.city ?? id),
      cloud,
      region: String(raw.region || ""),
      lat,
      lon,
      defaultTee: normTee,
      color: sanitizeHexColor(raw.color, cloudColor(cloud)),
      https_url: validatedHttps,
      public_key_hex: raw.public_key_hex ? String(raw.public_key_hex) : null,
      endpoint_tcp: raw.endpoint_tcp ? String(raw.endpoint_tcp) : null,
      failure_domain: raw.failure_domain ? String(raw.failure_domain) : null,
      asn: Number.isInteger(Number(raw.asn)) && Number(raw.asn) > 0 ? Number(raw.asn) : null,
      diagnostic_only: Boolean(raw.diagnostic_only || normTee === "SoftwareDev"),
      os: raw.os ? String(raw.os) : null,
      kernel: raw.kernel ? String(raw.kernel) : null,
      officialMember: Boolean(isOfficial),
    });
  }

  function resolveAnchorBaseUrl(anchor, constellation, pageOrigin) {
    if (!anchor) return null;
    if (anchor.https_url) {
      return validateHttpsOrLocalUrl(anchor.https_url, pageOrigin);
    }
    if (constellation && constellation.isOfficial && anchor.slug && DNS_LABEL_RE.test(anchor.slug)) {
      return `https://${anchor.slug}.a.proofofgeography.com`;
    }
    // External anchors MUST supply their own https_url and NEVER silently fall back to proofofgeography.com!
    return null;
  }

  function parseConstellationPayload(payload, { isOfficial = false, registryUrl = DEFAULT_ANCHORS_URL, pageOrigin = null } = {}) {
    if (!payload || typeof payload !== "object") {
      throw new Error("Invalid constellation registry JSON");
    }
    const isSignedShape = !!(payload.grid && Array.isArray(payload.grid.anchors));
    const rawAnchors = isSignedShape ? payload.grid.anchors : payload.anchors;
    if (!Array.isArray(rawAnchors) || rawAnchors.length === 0) {
      throw new Error("Constellation registry contains no anchors");
    }
    const seen = new Set();
    const anchors = [];
    for (const r of rawAnchors) {
      const norm = normalizeAnchor(r, { isOfficial, pageOrigin });
      if (norm && !seen.has(norm.id)) {
        seen.add(norm.id);
        anchors.push(norm);
      }
    }
    if (anchors.length === 0) {
      throw new Error("Constellation registry contains no valid anchors");
    }

    let fallbackHost = "external-operator";
    try {
      fallbackHost = new URL(registryUrl, pageOrigin || "https://proofofgeography.com").host || fallbackHost;
    } catch (_) {}

    const networkId = isOfficial
      ? OFFICIAL_NETWORK_ID
      : String(payload.network_id || payload.grid?.grid_name || fallbackHost);
    const operatorName = isOfficial
      ? OFFICIAL_OPERATOR_NAME
      : String(payload.operator_name || payload.operator || fallbackHost);

    return Object.freeze({
      isOfficial: Boolean(isOfficial),
      isExternal: !isOfficial,
      officialMembership: Boolean(isOfficial),
      networkId,
      operatorName,
      registryUrl: String(registryUrl),
      rootPublicKeyHex: payload.root_public_key_hex ? String(payload.root_public_key_hex) : null,
      hasOperatorSignature: Boolean(payload.operator_signature_hex),
      signedRegistry: isSignedShape ? payload : null,
      anchors: Object.freeze(anchors),
    });
  }

  function computeConstellationAudit(constellation, liveInfoById, publishedRegistry) {
    const anchors = constellation?.anchors || [];
    const total = anchors.length;
    const pubAnchors =
      constellation?.signedRegistry?.grid?.anchors ||
      (constellation?.isOfficial ? publishedRegistry?.grid?.anchors : null) ||
      [];
    const pubById = Object.fromEntries(pubAnchors.map((a) => [a.anchor_id || a.id, a]));

    let reachable = 0;
    let hwTee = 0;
    let keyMatched = 0;
    let attestedAndEnrolled = 0;
    const hardwareByVendor = { IntelTdx: 0, AmdSevSnp: 0, AwsNitro: 0, SoftwareDev: 0 };

    for (const a of anchors) {
      const info = liveInfoById ? liveInfoById[a.id] : null;
      if (!info) continue;
      reachable++;
      const badge = teeBadgeForVendor(info.tee_vendor || "SoftwareDev", a.cloud);
      if (badge.isHw && !a.diagnostic_only) {
        hwTee++;
        hardwareByVendor[badge.vendor] = (hardwareByVendor[badge.vendor] || 0) + 1;
      } else {
        hardwareByVendor.SoftwareDev++;
      }
      const pub = pubById[a.id];
      const expectedPk = pub?.public_key_hex || a.public_key_hex || null;
      const pkMatch = !!(expectedPk && info.public_key_hex && info.public_key_hex.toLowerCase() === expectedPk.toLowerCase());
      const endMatch = !!(
        info.operator_endorsement &&
        info.operator_endorsement.anchor_public_key_hex &&
        info.public_key_hex &&
        info.operator_endorsement.anchor_public_key_hex.toLowerCase() === info.public_key_hex.toLowerCase()
      );
      if (pkMatch) keyMatched++;
      if (badge.isHw && !a.diagnostic_only && pkMatch && endMatch) attestedAndEnrolled++;
    }

    return Object.freeze({
      constellationId: constellation?.networkId || OFFICIAL_NETWORK_ID,
      isOfficial: Boolean(constellation?.isOfficial),
      isExternal: Boolean(constellation?.isExternal),
      configured: total,
      reachable,
      hwTee,
      keyMatched,
      proofEligible: attestedAndEnrolled,
      // Hardware verification on an external constellation NEVER confers official membership!
      officialProofEligible: constellation?.isOfficial ? attestedAndEnrolled : 0,
      officialHwTee: constellation?.isOfficial ? hwTee : 0,
      hardwareByVendor: Object.freeze(hardwareByVendor),
    });
  }

  function createConstellationStore(officialPayload, { pageOrigin = null } = {}) {
    const official = parseConstellationPayload(officialPayload, {
      isOfficial: true,
      registryUrl: DEFAULT_ANCHORS_URL,
      pageOrigin,
    });
    let active = official;
    let officialLiveInfo = {};
    let activeLiveInfo = {};

    return {
      getOfficial() {
        return official;
      },
      getActive() {
        return active;
      },
      selectOfficial() {
        active = official;
        activeLiveInfo = Object.assign({}, officialLiveInfo);
        return active;
      },
      selectExternal(externalPayload, registryUrl) {
        const validated = validateHttpsOrLocalUrl(registryUrl, pageOrigin);
        if (!validated) {
          throw new Error(`External registry URL must use HTTPS: ${registryUrl}`);
        }
        // Strictly replace active constellation; NEVER merge into or mutate `official`!
        active = parseConstellationPayload(externalPayload, {
          isOfficial: false,
          registryUrl: validated,
          pageOrigin,
        });
        activeLiveInfo = {};
        return active;
      },
      recordLiveInfo(anchorId, info) {
        // Ignore unknown anchors so external nodes can NEVER pollute official state (or vice versa)
        if (!active.anchors.some((a) => a.id === anchorId)) return false;
        activeLiveInfo[anchorId] = info;
        if (active.isOfficial) {
          officialLiveInfo[anchorId] = info;
        }
        return true;
      },
      getActiveAudit(publishedRegistry) {
        return computeConstellationAudit(active, activeLiveInfo, publishedRegistry);
      },
      getOfficialAudit(publishedRegistry) {
        return computeConstellationAudit(official, officialLiveInfo, publishedRegistry);
      },
    };
  }

  // --- Safe DOM Builders (Zero innerHTML; all untrusted strings written via textContent/dataset) ---
  function appendSegments(doc, parent, segments) {
    for (const seg of segments || []) {
      if (seg === null || seg === undefined) continue;
      if (typeof seg === "string") {
        parent.appendChild(doc.createTextNode(seg));
      } else if (seg.tag === "br") {
        parent.appendChild(doc.createElement("br"));
      } else if (seg.tag === "strong" || seg.tag === "code" || seg.tag === "em" || seg.tag === "span") {
        const node = doc.createElement(seg.tag);
        if (seg.className) node.className = seg.className;
        if (seg.style) Object.assign(node.style, seg.style);
        node.textContent = String(seg.text ?? "");
        parent.appendChild(node);
      } else {
        parent.appendChild(doc.createTextNode(String(seg.text ?? "")));
      }
    }
    return parent;
  }

  function buildTooltipElement(doc, segments) {
    const span = doc.createElement("span");
    return appendSegments(doc, span, segments);
  }

  function buildAnchorRowElement(
    doc,
    {
      anchor,
      badge,
      rttText = "ready",
      rttColor = "var(--cyan)",
      metaText = "",
      barPct = null,
      barColor = null,
      isViolated = false,
      isFocused = false,
      interactive = true,
    }
  ) {
    const row = doc.createElement("div");
    row.className = `anchor-row${isViolated ? " violated" : ""}${isFocused ? " focused" : ""}`;
    if (interactive && anchor && anchor.id !== undefined) {
      row.dataset.anchor = String(anchor.id);
    }

    const top = doc.createElement("div");
    top.className = "anchor-top";

    const nameDiv = doc.createElement("div");
    nameDiv.className = "anchor-name";
    const dot = doc.createElement("i");
    dot.className = "dot";
    const dotColor = sanitizeHexColor(isViolated ? "#f43f5e" : badge?.color || anchor?.color);
    dot.style.background = dotColor;
    const citySpan = doc.createElement("span");
    citySpan.textContent = String(anchor?.city ?? "");
    nameDiv.appendChild(dot);
    nameDiv.appendChild(citySpan);

    const rttDiv = doc.createElement("div");
    rttDiv.className = "anchor-rtt";
    if (rttColor) {
      rttDiv.style.color = rttColor === "var(--cyan)" ? "var(--cyan)" : sanitizeHexColor(rttColor, "#2dd4bf");
    }
    rttDiv.textContent = String(rttText ?? "");

    top.appendChild(nameDiv);
    top.appendChild(rttDiv);
    row.appendChild(top);

    const meta = doc.createElement("div");
    meta.className = "anchor-meta";
    const tagSpan = doc.createElement("span");
    tagSpan.className = `tee-tag ${safeBadgeClass(badge?.cls)}`;
    tagSpan.textContent = String(badge?.label ?? "");
    const metaSpan = doc.createElement("span");
    metaSpan.textContent = String(metaText ?? "");
    meta.appendChild(tagSpan);
    meta.appendChild(metaSpan);
    row.appendChild(meta);

    if (typeof barPct === "number" && Number.isFinite(barPct)) {
      const clamped = Math.min(100, Math.max(0, barPct));
      const track = doc.createElement("div");
      track.className = "rtt-bar-track";
      const fill = doc.createElement("div");
      fill.className = "rtt-bar-fill";
      fill.style.width = `${clamped}%`;
      fill.style.background = sanitizeHexColor(isViolated ? "#f43f5e" : barColor || dotColor);
      track.appendChild(fill);
      row.appendChild(track);
    }

    return row;
  }

  function buildMeshPickerButtonElement(doc, { anchor, badge, isActive = false }) {
    const btn = doc.createElement("button");
    btn.type = "button";
    btn.className = `mesh-btn${isActive ? " active" : ""}`;
    btn.dataset.prover = String(anchor?.id ?? "");

    const cityDiv = doc.createElement("div");
    cityDiv.className = "mesh-btn-city";
    cityDiv.textContent = String(anchor?.city ?? "");

    const subDiv = doc.createElement("div");
    subDiv.className = "mesh-btn-sub";
    subDiv.textContent = String(badge?.label ?? "");

    btn.appendChild(cityDiv);
    btn.appendChild(subDiv);
    return btn;
  }

  function buildAnchorPopupElement(
    doc,
    { anchor, active, badge, baseUrl, online, pkMatchesPub, prodEligible, pkShort }
  ) {
    const wrap = doc.createElement("div");
    wrap.style.minWidth = "245px";

    const title = doc.createElement("div");
    title.style.fontWeight = "800";
    title.style.fontSize = "13px";
    title.style.marginBottom = "3px";
    title.textContent = String(anchor?.city ?? "");
    wrap.appendChild(title);

    const idDiv = doc.createElement("div");
    idDiv.style.color = "#94a3b8";
    idDiv.style.fontFamily = "var(--mono)";
    idDiv.style.fontSize = "10.5px";
    idDiv.style.marginBottom = "6px";
    idDiv.textContent = String(anchor?.id ?? "");
    wrap.appendChild(idDiv);

    const addLine = (label, segments) => {
      const row = doc.createElement("div");
      const strong = doc.createElement("strong");
      strong.textContent = `${label}: `;
      row.appendChild(strong);
      appendSegments(doc, row, segments);
      wrap.appendChild(row);
    };

    addLine("Constellation", [
      active?.isExternal
        ? `Independently Operated (${String(active.networkId ?? "")})`
        : "Official (proofofgeography.com)",
    ]);
    addLine("TEE", [{ tag: "span", className: `tee-tag ${safeBadgeClass(badge?.cls)}`, text: String(badge?.label ?? "") }]);
    addLine("HTTPS Endpoint", [{ tag: "code", style: { fontSize: "10px" }, text: String(baseUrl || "none configured") }]);
    addLine("Reachable", [online ? "✅ Live HTTPS" : "⏳ Pending / Offline"]);
    addLine("Key vs Registry", [!online ? "—" : pkMatchesPub ? "✅ Matches constellation key" : "⚠️ Mismatch / Unenrolled"]);
    if (active?.isExternal) {
      addLine("Official Membership", [
        `🚫 No (Independently operated by ${String(active.operatorName ?? "")}; HW TEE ≠ official membership)`,
      ]);
    } else {
      addLine("Production Eligible", [prodEligible ? "✅ Yes (HW TEE + Enrolled)" : "🚫 No (Diagnostic only)"]);
    }
    addLine("Live Ed25519 Key", [{ tag: "code", style: { fontSize: "10px" }, text: String(pkShort ?? "not queried") }]);

    return wrap;
  }

  function buildExternalBannerElement(doc, { active, officialCount = 0, errorMessage = null }) {
    const frag = doc.createDocumentFragment();
    if (errorMessage) {
      const strong = doc.createElement("strong");
      strong.textContent = "⚠️ External Registry Not Loaded (Showing Official Constellation)";
      const body = doc.createElement("div");
      body.appendChild(doc.createTextNode(`${String(errorMessage)} — `));
      const link = doc.createElement("a");
      link.setAttribute("href", "/");
      link.textContent = "Clear ?registry";
      body.appendChild(link);
      frag.appendChild(strong);
      frag.appendChild(body);
      return frag;
    }
    if (active && active.isExternal) {
      const strong = doc.createElement("strong");
      strong.textContent = "🌐 Independently Operated External Constellation · NOT Official Proof of Geography";
      const body = doc.createElement("div");
      appendSegments(doc, body, [
        "Operator: ",
        { tag: "strong", text: String(active.operatorName ?? "") },
        " (",
        { tag: "code", text: String(active.networkId ?? "") },
        ")",
        { tag: "br" },
        "Registry: ",
        { tag: "code", style: { wordBreak: "break-all" }, text: String(active.registryUrl ?? "") },
        { tag: "br" },
        "Selected separately (",
        { tag: "strong", text: String(active.anchors.length) },
        " nodes; official ",
        { tag: "strong", text: String(officialCount) },
        "-node roster & hardware counts are untouched). Hardware TEE verification on this constellation is ",
        { tag: "strong", text: "not" },
        " official Proof of Geography membership.",
      ]);
      const retWrap = doc.createElement("div");
      retWrap.style.marginTop = "6px";
      const link = doc.createElement("a");
      link.setAttribute("href", "/");
      link.textContent = "← Return to Official Constellation";
      retWrap.appendChild(link);
      body.appendChild(retWrap);
      frag.appendChild(strong);
      frag.appendChild(body);
    }
    return frag;
  }

  function buildSpoofVerdictElement(
    doc,
    { caught, tierLabel, claimLabel, violationCount, totalCount, byzantineF, worst }
  ) {
    const frag = doc.createDocumentFragment();
    const safeTier = String(tierLabel ?? "");
    const safeClaim = String(claimLabel ?? "");
    if (caught) {
      appendSegments(doc, frag, [
        { tag: "strong", text: `🚫 EXCLUDED BY ${safeTier.toUpperCase()}` },
        { tag: "br" },
        "Claiming ",
        { tag: "strong", text: safeClaim },
        " violates ",
        { tag: "strong", text: `${violationCount}/${totalCount}` },
        ` outer caps (exceeds Byzantine f=${byzantineF}).`,
      ]);
      if (worst) {
        appendSegments(doc, frag, [
          { tag: "br" },
          "Worst: ",
          { tag: "strong", text: String(worst.city ?? "") },
          ` (${worst.rttText} → cap ${worst.maxDistText}, claim is ${worst.claimDistText} away; ${worst.cMultipleText}× c₀).`,
        ]);
      }
    } else {
      appendSegments(doc, frag, [
        { tag: "strong", text: "⚠️ CONSISTENT WITH OUTER BOUND (OVERLAP ≠ PROOF)" },
        { tag: "br" },
        { tag: "strong", text: safeClaim },
        ` is not excluded under ${safeTier} (${violationCount} cap violations ≤ f=${byzantineF}). Overlap alone does NOT prove the target is at ${safeClaim}.`,
      ]);
    }
    return frag;
  }

  function buildVerifyVerdictElement(
    doc,
    { status, vacDistText = "—", failureReasons = [], localVendor = "unknown", receiptCount = 0, invalidMessage = "Invalid base64url X-PoG-Proof bundle." }
  ) {
    const frag = doc.createDocumentFragment();
    if (status === "verified") {
      appendSegments(doc, frag, [
        { tag: "strong", text: "✅ CRYPTOGRAPHICALLY VERIFIED (HARDWARE TEE)" },
        { tag: "br" },
        "Vacuum c₀ outer bound: ",
        { tag: "code", text: String(vacDistText) },
      ]);
      return frag;
    }
    if (status === "rejected") {
      const reasons = Array.isArray(failureReasons) && failureReasons.length > 0
        ? failureReasons.map((r) => String(r ?? "")).join("; ")
        : "Rejected by fail-closed policy";
      appendSegments(doc, frag, [
        { tag: "strong", text: "🚫 NOT PRODUCTION-VERIFIED" },
        { tag: "br" },
        reasons,
      ]);
      return frag;
    }
    if (status === "local_decoded") {
      appendSegments(doc, frag, [
        { tag: "strong", text: "⚠️ DECODED LOCALLY (UNVERIFIED — NO BACKEND API)" },
        { tag: "br" },
        "Prover TEE: ",
        { tag: "code", text: String(localVendor || "unknown") },
        " · Receipts: ",
        { tag: "code", text: String(Number.isFinite(Number(receiptCount)) ? Number(receiptCount) : 0) },
        ". Run ",
        { tag: "code", text: "pog-cli" },
        " or the Rust verifier backend for full cryptographic verification.",
      ]);
      return frag;
    }
    frag.appendChild(doc.createTextNode(String(invalidMessage)));
    return frag;
  }

  const api = Object.freeze({
    OFFICIAL_NETWORK_ID,
    OFFICIAL_OPERATOR_NAME,
    DEFAULT_ANCHORS_URL,
    sanitizeHexColor,
    safeBadgeClass,
    cloudColor,
    teeBadgeForVendor,
    validateHttpsOrLocalUrl,
    normalizeAnchor,
    resolveAnchorBaseUrl,
    parseConstellationPayload,
    computeConstellationAudit,
    createConstellationStore,
    buildTooltipElement,
    buildAnchorRowElement,
    buildMeshPickerButtonElement,
    buildAnchorPopupElement,
    buildExternalBannerElement,
    buildSpoofVerdictElement,
    buildVerifyVerdictElement,
  });

  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }
  if (root) {
    root.PogConstellation = api;
  }
})(typeof window !== "undefined" ? window : globalThis);
