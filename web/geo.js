// Exact spherical geometry & Proof of Geography speed-of-light solver
// Zero-artifact Mercator geodesic circles + Joint TDOA-MLE Wi-Fi/ISP overhead estimator

(function (global) {
  const EARTH_RADIUS_KM = 6371.0088;
  const KM_TO_MI = 0.621371;
  const DEG2RAD = Math.PI / 180;
  const RAD2DEG = 180 / Math.PI;

  const TIERS = {
    vacuum: {
      id: "vacuum",
      label: "Tier 1A Vacuum (c₀)",
      velocityKmPerMs: 299.792458,
      overheadMs: 0.0,
      minRadiusKm: 15,
    },
    fiber: {
      id: "fiber",
      label: "Tier 1B Optical Fiber",
      velocityKmPerMs: 204.0,
      overheadMs: 0.0,
      minRadiusKm: 15,
    },
    calibrated: {
      id: "calibrated",
      label: "Tier 2B Calibrated Internet",
      velocityKmPerMs: 130.271,
      overheadMs: 0.65,
      minRadiusKm: 35,
    },
  };

  function haversineKm(lat1, lon1, lat2, lon2) {
    const dLat = (lat2 - lat1) * DEG2RAD;
    const dLon = (lon2 - lon1) * DEG2RAD;
    const a =
      Math.sin(dLat / 2) ** 2 +
      Math.cos(lat1 * DEG2RAD) * Math.cos(lat2 * DEG2RAD) * Math.sin(dLon / 2) ** 2;
    return 2 * EARTH_RADIUS_KM * Math.asin(Math.min(1, Math.sqrt(a)));
  }

  function rttToRadiusKm(rttMs, tierId, extraOverheadMs = 0) {
    const t = TIERS[tierId] || TIERS.calibrated;
    const effectiveRtt = Math.max(0, rttMs - t.overheadMs - extraOverheadMs);
    if (tierId === "calibrated") {
      // Empirical distance-dependent internet velocity from our live 9x9 multi-cloud mesh:
      // Regional/metro routes ~102 km/ms (fiber stretch + peering) -> long subsea cables ~166 km/ms
      const vKmPerMs = 102.0 + 64.0 * Math.min(1.0, effectiveRtt / 95.0);
      return Math.max(t.minRadiusKm, (effectiveRtt / 2.0) * vKmPerMs);
    }
    return Math.max(t.minRadiusKm, (effectiveRtt / 2.0) * t.velocityKmPerMs);
  }

  function destPoint(latDeg, lonDeg, bearingRad, distKm) {
    const ang = Math.min(distKm / EARTH_RADIUS_KM, Math.PI * 0.99);
    const lat1 = latDeg * DEG2RAD;
    const lon1 = lonDeg * DEG2RAD;
    const sinLat1 = Math.sin(lat1);
    const cosLat1 = Math.cos(lat1);
    const sinAng = Math.sin(ang);
    const cosAng = Math.cos(ang);

    const lat2 = Math.asin(
      Math.max(-1, Math.min(1, sinLat1 * cosAng + cosLat1 * sinAng * Math.cos(bearingRad)))
    );
    const lon2 =
      lon1 +
      Math.atan2(
        Math.sin(bearingRad) * sinAng * cosLat1,
        cosAng - sinLat1 * Math.sin(lat2)
      );
    let lonNorm = lon2 * RAD2DEG;
    while (lonNorm > 180) lonNorm -= 360;
    while (lonNorm < -180) lonNorm += 360;
    return [lat2 * RAD2DEG, lonNorm];
  }

  /**
   * Build Mercator-safe geodesic circle geometry centered on (anchorLat, anchorLon).
   * Exact spherical topology check:
   *   - Circle encloses North Pole IFF anchorLat + radiusDeg >= 89.8
   *   - Circle encloses South Pole IFF anchorLat - radiusDeg <= -89.8
   *   - Otherwise it is ALWAYS a simple closed loop (never sorted by lon -> zero vertical zig-zag chords!).
   *   - For true polar-enclosing circles, trace monotonically by bearing and split at the single
   *     antimeridian crossing so the boundary wave runs cleanly from -180 to +180.
   */
  function geodesicCircleGeometry(anchorLat, anchorLon, radiusKm, steps = 160, lonShift = 0) {
    const clampedKm = Math.min(radiusKm, 19000);
    const radiusDeg = (clampedKm / EARTH_RADIUS_KM) * RAD2DEG;
    const enclosesNorth = anchorLat + radiusDeg >= 90.0;
    const enclosesSouth = anchorLat - radiusDeg <= -90.0;
    const enclosesBothPoles = enclosesNorth && enclosesSouth;
    const enclosesExactlyOnePole = enclosesNorth !== enclosesSouth;

    if (enclosesExactlyOnePole) {
      // Trace boundary monotonically by bearing (enclosing exactly 1 pole crosses +/-180 deg ONCE!)
      const raw = [];
      for (let i = 0; i < steps; i++) {
        const brg = (2 * Math.PI * i) / steps;
        const [lat, lon] = destPoint(anchorLat, anchorLon, brg, clampedKm);
        raw.push([Math.max(-84.5, Math.min(84.5, lat)), lon]);
      }
      // Find the single antimeridian jump (> 180 deg between adjacent bearing samples)
      let cutIdx = 0;
      for (let i = 0; i < raw.length; i++) {
        const next = (i + 1) % raw.length;
        if (Math.abs(raw[next][1] - raw[i][1]) > 180) {
          cutIdx = next;
          break;
        }
      }
      const ordered = [];
      for (let k = 0; k < raw.length; k++) {
        ordered.push(raw[(cutIdx + k) % raw.length]);
      }
      if (ordered[0][1] > ordered[ordered.length - 1][1]) {
        ordered.reverse();
      }
      const edgeLat = (ordered[0][0] + ordered[ordered.length - 1][0]) / 2;
      const stroke = [[edgeLat, -180 + lonShift]];
      for (const [lat, lon] of ordered) {
        stroke.push([lat, lon + lonShift]);
      }
      stroke.push([edgeLat, 180 + lonShift]);

      const poleLat = enclosesNorth ? 85.0 : -85.0;
      const fill = stroke.concat([
        [poleLat, 180 + lonShift],
        [poleLat, -180 + lonShift],
      ]);
      return { polar: true, stroke, fill };
    }

    // Standard closed loop (0 poles -> around anchor; 2 poles -> closed loop around antipode!)
    const refLon = enclosesBothPoles
      ? (anchorLon > 0 ? anchorLon - 180 : anchorLon + 180) + lonShift
      : anchorLon + lonShift;
    const pts = [];
    let prevLon = refLon;
    for (let i = 0; i <= steps; i++) {
      const brg = (2 * Math.PI * i) / steps;
      const [rawLat, rawLon] = destPoint(anchorLat, anchorLon, brg, clampedKm);
      let lon = rawLon;
      while (lon - prevLon > 180) lon -= 360;
      while (lon - prevLon < -180) lon += 360;
      prevLon = lon;
      pts.push([Math.max(-84.5, Math.min(84.5, rawLat)), lon]);
    }
    return { polar: enclosesBothPoles, stroke: pts, fill: enclosesBothPoles ? [] : pts };
  }

  function greatCircleArc(lat1, lon1, lat2, lon2, steps = 36) {
    const p1 = toVec3(lat1, lon1);
    const p2 = toVec3(lat2, lon2);
    const dot = Math.max(-1, Math.min(1, p1[0] * p2[0] + p1[1] * p2[1] + p1[2] * p2[2]));
    const omega = Math.acos(dot);
    if (omega < 1e-6) return [[lat1, lon1], [lat2, lon2]];
    const sinOmega = Math.sin(omega);
    const pts = [];
    let prevLon = lon1;
    for (let i = 0; i <= steps; i++) {
      const t = i / steps;
      const a = Math.sin((1 - t) * omega) / sinOmega;
      const b = Math.sin(t * omega) / sinOmega;
      const x = a * p1[0] + b * p2[0];
      const y = a * p1[1] + b * p2[1];
      const z = a * p1[2] + b * p2[2];
      const lat = Math.atan2(z, Math.sqrt(x * x + y * y)) * RAD2DEG;
      let lon = Math.atan2(y, x) * RAD2DEG;
      while (lon - prevLon > 180) lon -= 360;
      while (lon - prevLon < -180) lon += 360;
      prevLon = lon;
      pts.push([lat, lon]);
    }
    return pts;
  }

  function toVec3(latDeg, lonDeg) {
    const lat = latDeg * DEG2RAD;
    const lon = lonDeg * DEG2RAD;
    return [Math.cos(lat) * Math.cos(lon), Math.cos(lat) * Math.sin(lon), Math.sin(lat)];
  }

  function vec3ToLatLon(v) {
    const n = Math.hypot(v[0], v[1], v[2]) || 1;
    const x = v[0] / n, y = v[1] / n, z = v[2] / n;
    return [Math.atan2(z, Math.sqrt(x * x + y * y)) * RAD2DEG, Math.atan2(y, x) * RAD2DEG];
  }

  function convexHull(points) {
    if (points.length <= 3) return points;
    const sorted = points.slice().sort((a, b) => (a[1] !== b[1] ? a[1] - b[1] : a[0] - b[0]));
    const cross = (o, a, b) => (a[1] - o[1]) * (b[0] - o[0]) - (a[0] - o[0]) * (b[1] - o[1]);
    const lower = [];
    for (const p of sorted) {
      while (lower.length >= 2 && cross(lower[lower.length - 2], lower[lower.length - 1], p) <= 0) {
        lower.pop();
      }
      lower.push(p);
    }
    const upper = [];
    for (let i = sorted.length - 1; i >= 0; i--) {
      const p = sorted[i];
      while (upper.length >= 2 && cross(upper[upper.length - 2], upper[upper.length - 1], p) <= 0) {
        upper.pop();
      }
      upper.push(p);
    }
    upper.pop();
    lower.pop();
    return lower.concat(upper);
  }

  /**
   * Joint (lat, lon, delta_ms) TDOA-MLE loss:
   * Solves in closed form for the visitor's unknown local Wi-Fi + ISP + TLS overhead delta >= 0!
   * Even if a laptop on Wi-Fi has 25-40 ms of last-mile overhead, relative Anchor timing (TDOA)
   * accurately recovers BOTH the visitor's true location AND their local Wi-Fi overhead!
   */
  function tdoaMleFit(lat, lon, measurements) {
    let wSum = 0;
    let wDelta = 0;
    const diffs = new Array(measurements.length);
    const weights = new Array(measurements.length);
    let minRtt = Infinity;

    for (let i = 0; i < measurements.length; i++) {
      const m = measurements[i];
      if (m.rttMs < minRtt) minRtt = m.rttMs;
      const d = haversineKm(lat, lon, m.anchor.lat, m.anchor.lon);
      // Empirical distance-dependent internet speed for propagation estimate
      const vEst = 102.0 + 48.0 * Math.min(1.0, d / 7500.0);
      const expectedPropMs = (2.0 * d) / vEst;
      const resid = m.rttMs - expectedPropMs;
      const w = 1.0 / Math.max(12.0, m.rttMs);
      diffs[i] = resid;
      weights[i] = w;
      wSum += w;
      wDelta += w * resid;
    }

    // Clamp delta to [0, minRtt] — local overhead cannot exceed the shortest measured RTT!
    const deltaMs = Math.max(0, Math.min(minRtt, wDelta / (wSum || 1)));
    let sse = 0;
    for (let i = 0; i < measurements.length; i++) {
      const err = diffs[i] - deltaMs;
      sse += weights[i] * err * err;
    }
    return { loss: sse, deltaMs };
  }

  /**
   * Estimate the visitor's best-fit (lat, lon) AND local Wi-Fi/ISP overhead deltaMs
   * purely from relative arrival times across all Anchors.
   */
  function estimateTdoaAndOverhead(measurements) {
    const sorted = measurements.slice().sort((a, b) => a.rttMs - b.rttMs);
    let bestPt = [sorted[0].anchor.lat, sorted[0].anchor.lon];
    let best = tdoaMleFit(bestPt[0], bestPt[1], sorted);

    // Coarse global scan + dense anchor-adjacent samples
    for (let lat = -58; lat <= 72; lat += 3.0) {
      for (let lon = -180; lon < 180; lon += 3.0) {
        const res = tdoaMleFit(lat, lon, sorted);
        if (res.loss < best.loss) {
          best = res;
          bestPt = [lat, lon];
        }
      }
    }
    for (const m of sorted.slice(0, 3)) {
      for (const distKm of [0, 80, 220, 500, 1000]) {
        const n = distKm === 0 ? 1 : 12;
        for (let k = 0; k < n; k++) {
          const pt = distKm === 0 ? [m.anchor.lat, m.anchor.lon] : destPoint(m.anchor.lat, m.anchor.lon, (2 * Math.PI * k) / n, distKm);
          const res = tdoaMleFit(pt[0], pt[1], sorted);
          if (res.loss < best.loss) {
            best = res;
            bestPt = pt;
          }
        }
      }
    }
    // Fine local refinement around winning seed
    for (let step of [1.0, 0.25]) {
      const center = bestPt.slice();
      for (let dLat = -step * 3; dLat <= step * 3; dLat += step) {
        for (let dLon = -step * 3; dLon <= step * 3; dLon += step) {
          const lat = Math.max(-82, Math.min(82, center[0] + dLat));
          let lon = center[1] + dLon;
          while (lon > 180) lon -= 360;
          while (lon < -180) lon += 360;
          const res = tdoaMleFit(lat, lon, sorted);
          if (res.loss < best.loss) {
            best = res;
            bestPt = [lat, lon];
          }
        }
      }
    }
    return { mle: bestPt, deltaMs: best.deltaMs };
  }

  /**
   * Compute exact calibrated overhead to apply in `calibrated` mode for browser/Wi-Fi probes.
   * For raw datacenter UDP meshes (`extraOverheadMs === 0`), returns 0.
   */
  function computeCalibratedOverheadMs(measurements, tierId, extraOverheadMs, tdoaDeltaMs) {
    if (tierId !== "calibrated" || extraOverheadMs <= 0 || measurements.length < 3) {
      return extraOverheadMs;
    }
    const minRtt = Math.min(...measurements.map((m) => m.rttMs));
    // Use the joint TDOA-estimated Wi-Fi/ISP overhead, conservatively discounted by 15%
    // and leaving at least 2.0 ms of propagation margin on the closest Anchor so the true
    // location stays safely inside the calibrated intersection!
    const conservativeDelta = Math.max(extraOverheadMs, tdoaDeltaMs * 0.85);
    return Math.min(Math.max(extraOverheadMs, minRtt - 2.0), conservativeDelta);
  }

  /**
   * Compute smooth polar-ray intersection boundary around `center` for all circles!
   * Traces 72 rays outward from `center` and binary-searches the exact distance where
   * the point exits the intersection of >= `minInside` circles -> ALWAYS produces a
   * razor-smooth curved intersection lens (NEVER a square sampling-grid artifact!).
   */
  function traceIntersectionBoundary(center, circles, minInside) {
    const numRays = 96;
    const pts = [];
    let maxRadiusKm = 0;

    // Upper bound on ray length = largest circle radius
    const maxSearchKm = Math.min(
      12000,
      Math.max(...circles.map((c) => c.radiusKm), 200) * 1.15
    );

    const isInside = (lat, lon) => {
      let cnt = 0;
      for (const c of circles) {
        if (haversineKm(lat, lon, c.lat, c.lon) <= c.radiusKm) cnt++;
      }
      return cnt >= minInside;
    };

    if (!isInside(center[0], center[1])) {
      return { hull: [], maxRadiusKm: 0 };
    }

    for (let i = 0; i < numRays; i++) {
      const brg = (2 * Math.PI * i) / numRays;
      let lo = 0;
      let hi = maxSearchKm;
      for (let iter = 0; iter < 18; iter++) {
        const mid = (lo + hi) * 0.5;
        const [lt, ln] = destPoint(center[0], center[1], brg, mid);
        if (isInside(lt, ln)) {
          lo = mid;
        } else {
          hi = mid;
        }
      }
      if (lo > maxRadiusKm) maxRadiusKm = lo;
      const [lt, rawLon] = destPoint(center[0], center[1], brg, lo);
      let lon = rawLon;
      while (lon - center[1] > 180) lon -= 360;
      while (lon - center[1] < -180) lon += 360;
      pts.push([Math.max(-84.5, Math.min(84.5, lt)), lon]);
    }
    return { hull: pts, maxRadiusKm };
  }

  /**
   * Full solver: Joint TDOA-MLE + exact curved intersection lens + Byzantine (K-f)-core bound.
   */
  function solveLocation(measurements, tierId, extraOverheadMs = 0, byzantineF = 1) {
    if (!measurements || measurements.length === 0) return null;
    const K = measurements.length;
    const required = Math.max(1, K - (K >= 4 ? byzantineF : 0));

    const tdoa = estimateTdoaAndOverhead(measurements);
    const appliedOverheadMs = computeCalibratedOverheadMs(
      measurements,
      tierId,
      extraOverheadMs,
      tdoa.deltaMs
    );

    const circles = measurements
      .map((m) => ({
        anchor: m.anchor,
        lat: m.anchor.lat,
        lon: m.anchor.lon,
        rttMs: m.rttMs,
        radiusKm: rttToRadiusKm(m.rttMs, tierId, appliedOverheadMs),
      }))
      .sort((a, b) => a.rttMs - b.rttMs);

    // Find best interior seed (maximizing circles satisfied, breaking ties by TDOA-MLE)
    const seeds = [tdoa.mle, [circles[0].lat, circles[0].lon]];
    for (const c of circles.slice(0, 3)) {
      for (const frac of [0.2, 0.5, 0.8]) {
        for (let k = 0; k < 12; k++) {
          seeds.push(destPoint(c.lat, c.lon, (2 * Math.PI * k) / 12, Math.min(c.radiusKm, 5000) * frac));
        }
      }
    }
    let maxIn = 0;
    let bestSeed = tdoa.mle;
    let bestSeedLoss = Infinity;
    for (const pt of seeds) {
      let inside = 0;
      for (const c of circles) {
        if (haversineKm(pt[0], pt[1], c.lat, c.lon) <= c.radiusKm) inside++;
      }
      const { loss } = tdoaMleFit(pt[0], pt[1], circles);
      if (inside > maxIn || (inside === maxIn && loss < bestSeedLoss)) {
        maxIn = inside;
        bestSeedLoss = loss;
        bestSeed = pt;
      }
    }

    // Visual intersection lens: trace exact smooth boundary where ALL `maxIn` overlapping circles meet!
    // (When 9/9 overlap, this draws the exact smooth curved intersection of all 9 circles — NEVER a square!)
    const lens = traceIntersectionBoundary(bestSeed, circles, maxIn);

    // Also compute Byzantine (K-f)-core bound radius for adversarial security metric
    const byzMin = Math.min(required, maxIn);
    const byz = traceIntersectionBoundary(bestSeed, circles, byzMin);

    const floorKm = TIERS[tierId]?.minRadiusKm || 20;
    const maxRadiusKm = Math.max(floorKm, lens.maxRadiusKm || byz.maxRadiusKm);
    const byzRadiusKm = Math.max(floorKm, byz.maxRadiusKm);

    return {
      tierId,
      circles,
      feasibleCount: maxIn,
      requiredCount: required,
      strictFeasible: maxIn >= required,
      centroid: bestSeed,
      mle: bestSeed,
      estOverheadMs: tdoa.deltaMs,
      appliedOverheadMs,
      maxRadiusKm,
      maxRadiusMi: maxRadiusKm * KM_TO_MI,
      byzRadiusKm,
      byzRadiusMi: byzRadiusKm * KM_TO_MI,
      hull: lens.hull,
      nearest: circles[0],
    };
  }

  function evaluateSpoofClaim(claimLat, claimLon, measurements, tierId, extraOverheadMs = 0) {
    const tdoa = estimateTdoaAndOverhead(measurements);
    const appliedOverheadMs = computeCalibratedOverheadMs(
      measurements,
      tierId,
      extraOverheadMs,
      tdoa.deltaMs
    );
    const results = measurements.map((m) => {
      const distKm = haversineKm(claimLat, claimLon, m.anchor.lat, m.anchor.lon);
      const maxKm = rttToRadiusKm(m.rttMs, tierId, appliedOverheadMs);
      const vacKm = rttToRadiusKm(m.rttMs, "vacuum", 0);
      const violated = distKm > maxKm;
      const violatedVacuum = distKm > vacKm;
      const impliedVelocityKmPerMs = m.rttMs > 0 ? (2 * distKm) / m.rttMs : Infinity;
      const cMultiple = impliedVelocityKmPerMs / 299.792458;
      return {
        anchor: m.anchor,
        rttMs: m.rttMs,
        distKm,
        distMi: distKm * KM_TO_MI,
        maxKm,
        maxMi: maxKm * KM_TO_MI,
        excessKm: Math.max(0, distKm - maxKm),
        excessMi: Math.max(0, distKm - maxKm) * KM_TO_MI,
        violated,
        violatedVacuum,
        cMultiple,
      };
    });
    const violations = results.filter((r) => r.violated).sort((a, b) => b.excessKm - a.excessKm);
    const vacViolations = results.filter((r) => r.violatedVacuum);
    return {
      claimLat,
      claimLon,
      results,
      violations,
      vacViolations,
      caught: violations.length > 0,
      caughtByVacuum: vacViolations.length > 0,
    };
  }

  global.PogGeo = {
    EARTH_RADIUS_KM,
    KM_TO_MI,
    TIERS,
    haversineKm,
    rttToRadiusKm,
    destPoint,
    geodesicCircleGeometry,
    greatCircleArc,
    solveLocation,
    evaluateSpoofClaim,
  };
})(typeof window !== "undefined" ? window : globalThis);
