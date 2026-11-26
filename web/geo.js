// Exact spherical geometry & Proof of Geography speed-of-light solver
// Calibrated to match crates/pog-geo/src/lib.rs (Tier 1A Vacuum, Tier 1B Fiber, Tier 2B Calibrated)

(function (global) {
  const EARTH_RADIUS_KM = 6371.0088;
  const KM_TO_MI = 0.621371;
  const DEG2RAD = Math.PI / 180;
  const RAD2DEG = 180 / Math.PI;

  const TIERS = {
    vacuum: {
      id: "vacuum",
      label: "Tier 1A Vacuum (c₀)",
      velocityKmPerMs: 299.792458, // exact speed of light in vacuum
      overheadMs: 0.0,
      minRadiusKm: 15,
    },
    fiber: {
      id: "fiber",
      label: "Tier 1B Optical Fiber",
      velocityKmPerMs: 204.0, // c₀ / 1.468 in silica optical fiber
      overheadMs: 0.0,
      minRadiusKm: 15,
    },
    calibrated: {
      id: "calibrated",
      label: "Tier 2B Calibrated Internet",
      velocityKmPerMs: 130.271, // distance-calibrated empirical internet curve (102–166 km/ms)
      overheadMs: 0.65,
      minRadiusKm: 25,
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
      // Empirical distance-dependent internet velocity learned from our 9x9 multi-cloud mesh:
      // Regional/metro routes experience higher fiber stretch (~102 km/ms), converging toward
      // straight subsea optical corridors (~166 km/ms) at long distances.
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
   * Properly distinguishes:
   *   - Standard closed loops (neither pole enclosed) -> unwrapped continuous polygon
   *   - North/South polar-cap circles (circle encloses a pole!) -> smooth open boundary curve
   *     from -180..+180 + polar-edge fill polygon (ZERO horizontal wrap-around chords!)
   */
  function geodesicCircleGeometry(anchorLat, anchorLon, radiusKm, steps = 144, lonShift = 0) {
    const clampedKm = Math.min(radiusKm, 19000);
    const radiusDeg = (clampedKm / EARTH_RADIUS_KM) * RAD2DEG;
    const enclosesNorth = anchorLat + radiusDeg >= 84.5;
    const enclosesSouth = anchorLat - radiusDeg <= -84.5;

    if (enclosesNorth || enclosesSouth) {
      // Polar-enclosing circle: boundary is a single-valued wave lat(lon) over [-180, +180]
      const raw = [];
      for (let i = 0; i < steps; i++) {
        const brg = (2 * Math.PI * i) / steps;
        const [lat, lon] = destPoint(anchorLat, anchorLon, brg, clampedKm);
        raw.push([Math.max(-84.5, Math.min(84.5, lat)), lon]);
      }
      raw.sort((a, b) => a[1] - b[1]);
      // Extend smoothly to exact +/-180 edge so adjacent world copies join seamlessly
      const first = raw[0];
      const last = raw[raw.length - 1];
      const edgeLat = (first[0] + last[0]) / 2;
      const stroke = [[edgeLat, -180 + lonShift]];
      for (const [lat, lon] of raw) {
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

    // Standard closed circle: unwrap continuously around anchorLon + lonShift
    const pts = [];
    let prevLon = null;
    for (let i = 0; i <= steps; i++) {
      const brg = (2 * Math.PI * i) / steps;
      const [lat, rawLon] = destPoint(anchorLat, anchorLon, brg, clampedKm);
      let lon = rawLon;
      if (prevLon === null) {
        const target = anchorLon + lonShift;
        while (lon - target > 180) lon -= 360;
        while (lon - target < -180) lon += 360;
      } else {
        while (lon - prevLon > 180) lon -= 360;
        while (lon - prevLon < -180) lon += 360;
      }
      prevLon = lon;
      pts.push([Math.max(-84.5, Math.min(84.5, lat)), lon]);
    }
    return { polar: false, stroke: pts, fill: pts };
  }

  /**
   * Compute spherical great-circle arc between two points (unwrapped continuously from lon1).
   */
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
   * Joint (lat, lon, delta_ms) TDOA-MLE loss for a candidate point:
   * Automatically solves for unknown local Wi-Fi/ISP/HTTPS overhead delta >= 0 in closed form!
   * Model: rtt_i ≈ delta + 2 * d_i / v_emp   (v_emp = 136 km/ms typical empirical internet speed)
   */
  function tdoaMleLoss(lat, lon, circles) {
    const V_EMP = 136.0; // km/ms typical multi-cloud corridor median
    let wSum = 0;
    let wDelta = 0;
    const diffs = new Array(circles.length);
    const weights = new Array(circles.length);
    let penalty = 0;

    for (let i = 0; i < circles.length; i++) {
      const c = circles[i];
      const d = haversineKm(lat, lon, c.lat, c.lon);
      // Penalize violating hard speed-of-light circle strongly
      if (d > c.radiusKm) {
        const ex = (d - c.radiusKm) / 200.0;
        penalty += 500 * ex * ex;
      }
      const expectedPropMs = (2.0 * d) / V_EMP;
      const residDelta = c.rttMs - expectedPropMs;
      const w = 1.0 / Math.max(8.0, c.rttMs);
      diffs[i] = residDelta;
      weights[i] = w;
      wSum += w;
      wDelta += w * residDelta;
    }

    // Optimal non-negative last-mile overhead delta >= 0 (clamped so we don't absorb more than min_rtt)
    const minRtt = circles[0]?.rttMs || 0;
    const delta = Math.max(0, Math.min(minRtt, wDelta / (wSum || 1)));

    let sse = 0;
    for (let i = 0; i < circles.length; i++) {
      const errMs = diffs[i] - delta;
      sse += weights[i] * errMs * errMs;
    }
    return { loss: sse + penalty, deltaMs: delta };
  }

  /**
   * Two-stage spherical Byzantine (K-f)-core intersection solver + Joint TDOA-MLE estimator.
   */
  function solveLocation(measurements, tierId, extraOverheadMs = 0, byzantineF = 1) {
    if (!measurements || measurements.length === 0) return null;
    const K = measurements.length;
    const required = Math.max(1, K - (K >= 4 ? byzantineF : 0));

    // In Calibrated mode for browser/ISP visitors (extraOverheadMs > 0), also estimate
    // local last-mile/TLS overhead conservatively (up to 65% of nearest RTT) so circles
    // reflect real calibrated internet geometry instead of inflated lightcones!
    let appliedOverheadMs = extraOverheadMs;
    if (tierId === "calibrated" && extraOverheadMs > 0 && measurements.length >= 3) {
      const minRtt = Math.min(...measurements.map((m) => m.rttMs));
      if (minRtt > 4.0) {
        appliedOverheadMs = Math.min(minRtt * 0.65, Math.max(extraOverheadMs, minRtt - 2.5));
      }
    }

    const circles = measurements
      .map((m) => ({
        anchor: m.anchor,
        lat: m.anchor.lat,
        lon: m.anchor.lon,
        rttMs: m.rttMs,
        radiusKm: rttToRadiusKm(m.rttMs, tierId, appliedOverheadMs),
      }))
      .sort((a, b) => a.rttMs - b.rttMs);

    // Stage 1: Coarse global scan + dense rings around the 3 closest Anchors
    const candidates = [];
    for (let lat = -60; lat <= 74; lat += 2.5) {
      for (let lon = -180; lon < 180; lon += 2.5) {
        candidates.push([lat, lon]);
      }
    }
    for (const c of circles.slice(0, 3)) {
      candidates.push([c.lat, c.lon]);
      for (const frac of [0.15, 0.35, 0.6, 0.85]) {
        for (let k = 0; k < 12; k++) {
          candidates.push(destPoint(c.lat, c.lon, (2 * Math.PI * k) / 12, Math.min(c.radiusKm, 6000) * frac));
        }
      }
    }

    let maxIn = 0;
    let bestSeed = [circles[0].lat, circles[0].lon];
    let bestLoss = Infinity;

    for (const [lat, lon] of candidates) {
      let inside = 0;
      for (const c of circles) {
        if (haversineKm(lat, lon, c.lat, c.lon) <= c.radiusKm) inside++;
      }
      if (inside < maxIn - 1) continue;
      const { loss } = tdoaMleLoss(lat, lon, circles);
      if (inside > maxIn || (inside === maxIn && loss < bestLoss)) {
        maxIn = inside;
        bestLoss = loss;
        bestSeed = [lat, lon];
      }
    }

    // Stage 2: Fine local spherical refinement around bestSeed
    const tightKm = circles[0].radiusKm;
    const spanDeg = Math.min(36, Math.max(1.8, (tightKm / 111.0) * 1.45));
    const stepDeg = spanDeg / 28;
    const corePoints = [];
    let bestMle = bestSeed;
    let bestMleScore = Infinity;
    let estOverheadMs = 0;

    const targetCount = Math.min(required, maxIn);

    for (let dLat = -spanDeg; dLat <= spanDeg; dLat += stepDeg) {
      const lat = Math.max(-82, Math.min(82, bestSeed[0] + dLat));
      const cosLat = Math.max(0.22, Math.cos(lat * DEG2RAD));
      const lonStep = stepDeg / cosLat;
      const lonSpan = Math.min(85, spanDeg / cosLat);
      for (let dLon = -lonSpan; dLon <= lonSpan; dLon += lonStep) {
        let lon = bestSeed[1] + dLon;
        while (lon > 180) lon -= 360;
        while (lon < -180) lon += 360;

        let inside = 0;
        for (const c of circles) {
          if (haversineKm(lat, lon, c.lat, c.lon) <= c.radiusKm) inside++;
        }
        if (inside >= targetCount) {
          corePoints.push([lat, lon]);
          const { loss, deltaMs } = tdoaMleLoss(lat, lon, circles);
          if (loss < bestMleScore) {
            bestMleScore = loss;
            bestMle = [lat, lon];
            estOverheadMs = deltaMs;
          }
        }
      }
    }

    // Compute spherical centroid + proven maximum radius of the feasible intersection zone
    let cx = 0, cy = 0, cz = 0;
    const ptsForStats = corePoints.length > 0 ? corePoints : [bestMle];
    for (const [lat, lon] of ptsForStats) {
      const v = toVec3(lat, lon);
      cx += v[0]; cy += v[1]; cz += v[2];
    }
    const centroid = vec3ToLatLon([cx, cy, cz]);

    let maxRadiusKm = 0;
    for (const [lat, lon] of ptsForStats) {
      const d = haversineKm(centroid[0], centroid[1], lat, lon);
      if (d > maxRadiusKm) maxRadiusKm = d;
    }
    const floorKm = TIERS[tierId]?.minRadiusKm || 20;
    maxRadiusKm = Math.max(floorKm, maxRadiusKm);

    // Unwrap core points around centroid longitude before computing hull polygon
    const unwrapped = ptsForStats.map(([lat, lon]) => {
      let l = lon;
      while (l - centroid[1] > 180) l -= 360;
      while (l - centroid[1] < -180) l += 360;
      return [lat, l];
    });
    const hull = unwrapped.length >= 3 ? convexHull(unwrapped) : [];

    return {
      tierId,
      circles,
      feasibleCount: maxIn,
      requiredCount: required,
      strictFeasible: maxIn >= required,
      centroid,
      mle: bestMle,
      estOverheadMs,
      maxRadiusKm,
      maxRadiusMi: maxRadiusKm * KM_TO_MI,
      hull,
      nearest: circles[0],
    };
  }

  function evaluateSpoofClaim(claimLat, claimLon, measurements, tierId, extraOverheadMs = 0) {
    let appliedOverheadMs = extraOverheadMs;
    if (tierId === "calibrated" && extraOverheadMs > 0 && measurements.length >= 3) {
      const minRtt = Math.min(...measurements.map((m) => m.rttMs));
      if (minRtt > 4.0) {
        appliedOverheadMs = Math.min(minRtt * 0.65, Math.max(extraOverheadMs, minRtt - 2.5));
      }
    }
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
})(window);
