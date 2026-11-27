// Exact Spherical Geometry, Conservative Speed-of-Light Outer Bounds &
// Correlated Spatial Likelihood Surface for Proof of Geography.
//
// Core invariants:
// 1. Vacuum (Tier 1A) & Optical Fiber (Tier 1B) are strictly conservative outer bounds:
//    - ZERO empirical RTT deductions.
//    - Conservatively fold in clock resolution, slew, anchor-coordinate uncertainty,
//      and WGS84 3D straight-line chord vs surface arc (M_0 = 6335.439327 km).
//    - NO artificial radius cap (expands smoothly to whole-Earth 20,015.114 km).
//    - NEVER use best-fit points, sampling, or discarded anchors to claim hard exclusions.
// 2. Correlated Spatial Likelihood Surface is strictly an EMPIRICAL ESTIMATE (never a proof),
//    evaluated strictly inside the raw Vacuum c0 outer region (never narrows raw Vacuum c0),
//    with full KxK shared-path covariance Cholesky whitening so correlated anchors do not
//    produce false certainty, and multi-peak detection when data supports multiple modes.

(function (global) {
  const EARTH_RADIUS_KM = 6371.0088;
  const WGS84_MIN_CURVATURE_RADIUS_KM = 6335.439327;
  const HALF_CIRCUMFERENCE_KM = Math.PI * EARTH_RADIUS_KM;
  const EARTH_SURFACE_KM2 = 4.0 * Math.PI * EARTH_RADIUS_KM * EARTH_RADIUS_KM;
  const KM_TO_MI = 0.621371;
  const DEG2RAD = Math.PI / 180;
  const RAD2DEG = 180 / Math.PI;
  const MERCATOR_LAT_LIMIT = Math.atan(Math.sinh(Math.PI)) * RAD2DEG;
  const C_VACUUM_KM_PER_MS = 299.792458;
  const C_FIBER_KM_PER_MS = 204.0;

  const TIERS = {
    vacuum: {
      id: "vacuum",
      label: "Tier 1A Vacuum (c₀ Outer Bound)",
      velocityKmPerMs: C_VACUUM_KM_PER_MS,
      isConservativeOuterBound: true,
    },
    fiber: {
      id: "fiber",
      label: "Tier 1B Optical Fiber (Conservative)",
      velocityKmPerMs: C_FIBER_KM_PER_MS,
      isConservativeOuterBound: true,
    },
  };

  // Frozen correlated spatial likelihood parameters fit strictly on disjoint Fit-T1 split
  // (self-excluded, reciprocal-excluded, verified via LOCO-CV & held-out multi-window eval).
  const DEFAULT_LIKELIHOOD_CONFIG = {
    t0Ms: 2.0,
    v0KmMs: 80.0,
    v1KmMs: 143.0,
    dKneeKm: 3500.0,
    sigmaBaseMs: 1.837,
    sigmaRel: 0.1267,
    sigmaJit: 1.5,
    rho: 0.85,
    lCorrKm: 2200.0,
    asymSlow: 1.65,
    studentTNu: 4.0,
    tauMoreLikely: 1.752,
    tauPlausible: 3.911,
    gridPoints: 2500,
    peakSeparationKm: 700.0,
  };

  function toVec3(latDeg, lonDeg) {
    const lat = latDeg * DEG2RAD;
    const lon = lonDeg * DEG2RAD;
    const cl = Math.cos(lat);
    return [cl * Math.cos(lon), cl * Math.sin(lon), Math.sin(lat)];
  }

  function vec3ToLatLon(v) {
    const n = Math.hypot(v[0], v[1], v[2]) || 1;
    const x = v[0] / n, y = v[1] / n, z = v[2] / n;
    return [Math.asin(Math.max(-1, Math.min(1, z))) * RAD2DEG, Math.atan2(y, x) * RAD2DEG];
  }

  function dot3(a, b) {
    return a[0] * b[0] + a[1] * b[1] + a[2] * b[2];
  }

  function cross3(a, b) {
    return [
      a[1] * b[2] - a[2] * b[1],
      a[2] * b[0] - a[0] * b[2],
      a[0] * b[1] - a[1] * b[0],
    ];
  }

  function norm3(a) {
    return Math.hypot(a[0], a[1], a[2]);
  }

  function normalize3(a) {
    const n = norm3(a);
    return n < 1e-15 ? null : [a[0] / n, a[1] / n, a[2] / n];
  }

  function anyOrthogonal(u) {
    const basis = Math.abs(u[0]) < 0.9 ? [1, 0, 0] : [0, 1, 0];
    return normalize3(cross3(u, basis)) || [0, 0, 1];
  }

  function geodesicKmVec(a, b) {
    return Math.acos(Math.max(-1, Math.min(1, dot3(a, b)))) * EARTH_RADIUS_KM;
  }

  function haversineKm(lat1, lon1, lat2, lon2) {
    return geodesicKmVec(toVec3(lat1, lon1), toVec3(lat2, lon2));
  }

  /**
   * Conservative outer-bound radius (km) for Tier 1A Vacuum or Tier 1B Optical Fiber.
   * ZERO empirical speed and ZERO empirical RTT/delay deductions! Never caps below whole Earth.
   *
   * Physical assumptions (see docs/PHYSICAL_BOUNDS_MODEL.md):
   * - Same-clock RTT (never one-way timestamps): inter-host clock offsets cancel; symmetric-path
   *   Sagnac cancels to first order, and worst-case asymmetric-loop Sagnac (<= 0.21 us) is
   *   strictly absorbed by the clockResolutionMs margin (0.05 ms server / 1.0 ms browser).
   * - Tier 1A Vacuum uses the 3D WGS84 straight-line chord (M_0 = 6335.439327 km), bounding
   *   both terrestrial and LEO/MEO/GEO satellite relays for surface provers (h << R_E).
   */
  function rttToRadiusKm(rttMs, tierId = "vacuum", opts = {}) {
    const isBrowser = !!opts.isBrowserProbe;
    const clockResMs = opts.clockResolutionMs ?? (isBrowser ? 1.0 : 0.05);
    const slewPpm = opts.clockSlewPpm ?? 500;
    const anchorUncKm = opts.anchorUncertaintyKm ?? 35.0;
    const accountForChord = opts.accountForChord ?? true;
    const accountForWgs84 = opts.accountForWgs84 ?? true;

    const rttEffMs = Math.max(0, rttMs) * (1 + slewPpm * 1e-6) + clockResMs;
    const m0 = accountForWgs84 ? WGS84_MIN_CURVATURE_RADIUS_KM : EARTH_RADIUS_KM;

    if (tierId === "fiber") {
      const oneWaySurfaceKm = 0.5 * rttEffMs * C_FIBER_KM_PER_MS;
      const theta = Math.min(Math.PI, oneWaySurfaceKm / m0 + anchorUncKm / EARTH_RADIUS_KM);
      return theta * EARTH_RADIUS_KM;
    }

    // Default: Tier 1A Vacuum (c0) — exact 3D WGS84 straight-line chord to surface arc!
    const oneWayChordKm = 0.5 * rttEffMs * C_VACUUM_KM_PER_MS;
    let theta;
    if (accountForChord) {
      if (oneWayChordKm >= 2.0 * m0) {
        theta = Math.PI;
      } else {
        theta = 2.0 * Math.asin(Math.min(1.0, oneWayChordKm / (2.0 * m0)));
      }
    } else {
      theta = Math.min(Math.PI, oneWayChordKm / m0);
    }
    theta = Math.min(Math.PI, theta + anchorUncKm / EARTH_RADIUS_KM);
    return theta * EARTH_RADIUS_KM;
  }

  function destPoint(latDeg, lonDeg, bearingRad, distKm) {
    const ang = Math.min(distKm / EARTH_RADIUS_KM, Math.PI * 0.999);
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
   * Exact Mercator scan-strip fill for a spherical cap of angular radius `angleRad`.
   * Returns a single flat simple `[lat, lon][]` polygon ring in one unwrapped world
   * centered on `anchorLon` (draw shifted copies at -360, 0, +360 with stroke: false;
   * render the true geodesic outline separately via `stroke`, and NEVER stroke whole Earth!).
   * Handles 0 poles, 1 pole (North/South), dateline, >hemisphere, near-global, and whole Earth.
   */
  function capFillMercator(anchorLat, anchorLon, angleRad, stepDeg = 0.25) {
    if (
      ![anchorLat, anchorLon, angleRad, stepDeg].every(Number.isFinite) ||
      Math.abs(anchorLat) > 90 ||
      angleRad < 0 ||
      stepDeg <= 0 ||
      stepDeg > 5
    ) {
      throw new RangeError("Invalid spherical cap arguments");
    }
    const lim = MERCATOR_LAT_LIMIT;
    if (angleRad >= Math.PI - 1e-12) {
      return [
        [-lim, anchorLon - 180],
        [-lim, anchorLon + 180],
        [lim, anchorLon + 180],
        [lim, anchorLon - 180],
      ];
    }
    const angleDeg = angleRad * RAD2DEG;
    const lo = Math.max(-lim, anchorLat - angleDeg);
    const hi = Math.min(lim, anchorLat + angleDeg);
    if (lo >= hi) return [];

    const n = Math.ceil((hi - lo) / stepDeg);
    const levels = new Array(n + 1);
    for (let i = 0; i <= n; i++) levels[i] = i === n ? hi : lo + ((hi - lo) * i) / n;

    const sin0 = Math.sin(anchorLat * DEG2RAD);
    const cos0 = Math.cos(anchorLat * DEG2RAD);
    const cosR = Math.cos(angleRad);
    const ratio = Math.abs(cosR) > 1e-15 ? sin0 / cosR : NaN;
    const extremum = Number.isFinite(ratio) && Math.abs(ratio) <= 1 ? Math.asin(ratio) * RAD2DEG : NaN;
    const cutoff = (phi) => (cosR - sin0 * Math.sin(phi * DEG2RAD)) / (cos0 * Math.cos(phi * DEG2RAD));

    const widths = new Array(n);
    for (let i = 0; i < n; i++) {
      const a = levels[i];
      const b = levels[i + 1];
      if (Math.abs(anchorLat) >= 90 - 1e-12) {
        widths[i] = 180;
        continue;
      }
      let m = Math.min(cutoff(a), cutoff(b));
      if (extremum > a && extremum < b) m = Math.min(m, cutoff(extremum));
      widths[i] = Math.acos(Math.max(-1, Math.min(1, m - 1e-12))) * RAD2DEG;
    }

    const left = [];
    const right = [];
    for (let i = 0; i < n; i++) {
      if (i === 0 || widths[i] !== widths[i - 1]) {
        left.push([levels[i], anchorLon - widths[i]]);
        right.push([levels[i], anchorLon + widths[i]]);
      }
      if (i === n - 1 || widths[i] !== widths[i + 1]) {
        left.push([levels[i + 1], anchorLon - widths[i]]);
        right.push([levels[i + 1], anchorLon + widths[i]]);
      }
    }
    return left.concat(right.reverse());
  }

  /**
   * Mercator-safe geodesic circle geometry with NO 19,000 km cap!
   * - `fill` is ALWAYS a single flat `[lat, lon][]` polygon ring (passes Mercator
   *   point-in-polygon & Leaflet canvas fill for 0 poles, 1 pole, dateline, >hemisphere,
   *   near-global, and whole Earth; render with `stroke: false`).
   * - `stroke` is the true geodesic boundary polyline, and is ALWAYS `[]` on whole Earth
   *   so there is NEVER a false outline around the world!
   */
  function geodesicCircleGeometry(anchorLat, anchorLon, radiusKm, steps = 160, lonShift = 0) {
    const clampedKm = Math.min(Math.max(0, radiusKm), HALF_CIRCUMFERENCE_KM);
    const angleRad = Math.min(Math.PI, clampedKm / EARTH_RADIUS_KM);
    const isWholeEarth = clampedKm >= HALF_CIRCUMFERENCE_KM - 0.5 || angleRad >= Math.PI - 1e-4;
    const fill = capFillMercator(anchorLat, anchorLon + lonShift, isWholeEarth ? Math.PI : angleRad, 0.25);

    if (isWholeEarth) {
      return { wholeEarth: true, polar: true, stroke: [], fill };
    }

    const radiusDeg = angleRad * RAD2DEG;
    const enclosesNorth = anchorLat + radiusDeg >= 89.99;
    const enclosesSouth = anchorLat - radiusDeg <= -89.99;
    const enclosesBothPoles = enclosesNorth && enclosesSouth;
    const enclosesExactlyOnePole = enclosesNorth !== enclosesSouth;

    if (enclosesExactlyOnePole) {
      const raw = [];
      for (let i = 0; i < steps; i++) {
        const brg = (2 * Math.PI * i) / steps;
        const [lat, lon] = destPoint(anchorLat, anchorLon, brg, clampedKm);
        raw.push([Math.max(-MERCATOR_LAT_LIMIT, Math.min(MERCATOR_LAT_LIMIT, lat)), lon]);
      }
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
      if (ordered[0][1] > ordered[ordered.length - 1][1]) ordered.reverse();
      const edgeLat = (ordered[0][0] + ordered[ordered.length - 1][0]) / 2;
      const stroke = [[edgeLat, -180 + lonShift]];
      for (const [lat, lon] of ordered) stroke.push([lat, lon + lonShift]);
      stroke.push([edgeLat, 180 + lonShift]);
      return { wholeEarth: false, polar: true, stroke, fill };
    }

    if (enclosesBothPoles) {
      // Exact geodesic boundary is the small circle around the antipode (excluded cap)!
      const antiLat = -anchorLat;
      const antiLon = anchorLon > 0 ? anchorLon - 180 : anchorLon + 180;
      const holeKm = Math.max(1.0, HALF_CIRCUMFERENCE_KM - clampedKm);
      const hole = [];
      let prevLon = antiLon + lonShift;
      for (let i = 0; i <= steps; i++) {
        const brg = (2 * Math.PI * i) / steps;
        const [rawLat, rawLon] = destPoint(antiLat, antiLon, brg, holeKm);
        let lon = rawLon + lonShift;
        while (lon - prevLon > 180) lon -= 360;
        while (lon - prevLon < -180) lon += 360;
        prevLon = lon;
        hole.push([Math.max(-MERCATOR_LAT_LIMIT, Math.min(MERCATOR_LAT_LIMIT, rawLat)), lon]);
      }
      return { wholeEarth: false, polar: true, stroke: hole, fill };
    }

    const pts = [];
    let prevLon = anchorLon + lonShift;
    for (let i = 0; i <= steps; i++) {
      const brg = (2 * Math.PI * i) / steps;
      const [rawLat, rawLon] = destPoint(anchorLat, anchorLon, brg, clampedKm);
      let lon = rawLon + lonShift;
      while (lon - prevLon > 180) lon -= 360;
      while (lon - prevLon < -180) lon += 360;
      prevLon = lon;
      pts.push([Math.max(-MERCATOR_LAT_LIMIT, Math.min(MERCATOR_LAT_LIMIT, rawLat)), lon]);
    }
    return { wholeEarth: false, polar: false, stroke: pts, fill };
  }

  function greatCircleArc(lat1, lon1, lat2, lon2, steps = 36) {
    const p1 = toVec3(lat1, lon1);
    const p2 = toVec3(lat2, lon2);
    const d = Math.max(-1, Math.min(1, dot3(p1, p2)));
    const omega = Math.acos(d);
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

  // Exact spherical circle-circle intersection using cross-product norm (safe down to 1 m spacing!)
  function circleIntersections(u1, c1, u2, c2) {
    const d = dot3(u1, u2);
    const n = cross3(u1, u2);
    const nNormSq = dot3(n, n);
    if (nNormSq < 1e-24) return [];
    const a = (c1 - c2 * d) / nNormSq;
    const b = (c2 - c1 * d) / nNormSq;
    const x0 = [a * u1[0] + b * u2[0], a * u1[1] + b * u2[1], a * u1[2] + b * u2[2]];
    const rem = 1.0 - dot3(x0, x0);
    if (rem < -1e-9) return [];
    const t = Math.sqrt(Math.max(0, rem) / nNormSq);
    const p1 = normalize3([x0[0] + t * n[0], x0[1] + t * n[1], x0[2] + t * n[2]]);
    const p2 = normalize3([x0[0] - t * n[0], x0[1] - t * n[1], x0[2] - t * n[2]]);
    const out = [];
    if (p1) out.push(p1);
    if (p2) out.push(p2);
    return out;
  }

  function furthestPointsOnCircle(u, theta, refU) {
    const sinT = Math.sin(theta);
    const cosT = Math.cos(theta);
    if (sinT < 1e-12) return [u];
    const d = dot3(refU, u);
    const tang = [refU[0] - d * u[0], refU[1] - d * u[1], refU[2] - d * u[2]];
    const tNorm = norm3(tang);
    if (tNorm < 1e-12) {
      const e1 = anyOrthogonal(u);
      const e2 = normalize3(cross3(u, e1)) || [0, 0, 1];
      return [
        [cosT * u[0] + sinT * e1[0], cosT * u[1] + sinT * e1[1], cosT * u[2] + sinT * e1[2]],
        [cosT * u[0] - sinT * e1[0], cosT * u[1] - sinT * e1[1], cosT * u[2] - sinT * e1[2]],
        [cosT * u[0] + sinT * e2[0], cosT * u[1] + sinT * e2[1], cosT * u[2] + sinT * e2[2]],
        [cosT * u[0] - sinT * e2[0], cosT * u[1] - sinT * e2[1], cosT * u[2] - sinT * e2[2]],
      ];
    }
    const dir = [tang[0] / tNorm, tang[1] / tNorm, tang[2] / tNorm];
    return [
      [cosT * u[0] - sinT * dir[0], cosT * u[1] - sinT * dir[1], cosT * u[2] - sinT * dir[2]],
      [cosT * u[0] + sinT * dir[0], cosT * u[1] + sinT * dir[1], cosT * u[2] + sinT * dir[2]],
    ];
  }

  let _cachedFib2500 = null;
  function getFibonacciSphere(n = 2500) {
    if (n === 2500 && _cachedFib2500) return _cachedFib2500;
    const ga = Math.PI * (3 - Math.sqrt(5));
    const pts = new Array(n);
    for (let i = 0; i < n; i++) {
      const y = 1 - (2 * i + 1) / n;
      const r = Math.sqrt(Math.max(0, 1 - y * y));
      const phi = ga * i;
      pts[i] = [Math.cos(phi) * r, Math.sin(phi) * r, y];
    }
    if (n === 2500) _cachedFib2500 = pts;
    return pts;
  }

  /**
   * Exact dual whole-Earth check:
   * Every point on S^2 lies in >= (K - f) caps IFF NO point lies in >= (f + 1) open complement caps!
   */
  function isWholeEarthCore(disks, byzantineF) {
    const k = disks.length;
    if (k === 0) return true;
    const neededComp = byzantineF + 1;
    // Open complement caps: dot(x, -u_i) > -cosTheta_i  (only non-empty when theta_i < pi)
    const comps = [];
    for (const d of disks) {
      if (d.theta < Math.PI - 1e-12) {
        comps.push({ u: [-d.u[0], -d.u[1], -d.u[2]], cosTheta: -d.cosTheta });
      }
    }
    if (comps.length < neededComp) return true;

    const violates = (p) => {
      let c = 0;
      for (const cd of comps) {
        if (dot3(p, cd.u) > cd.cosTheta + 1e-11) c++;
      }
      return c >= neededComp;
    };

    for (const cd of comps) {
      if (violates(cd.u)) return false;
    }
    for (let i = 0; i < comps.length; i++) {
      for (let j = i + 1; j < comps.length; j++) {
        for (const p of circleIntersections(comps[i].u, comps[i].cosTheta, comps[j].u, comps[j].cosTheta)) {
          // Slightly nudge along bisector of the two complement centers to check open interior
          const mid = normalize3([
            p[0] + 1e-6 * (comps[i].u[0] + comps[j].u[0]),
            p[1] + 1e-6 * (comps[i].u[1] + comps[j].u[1]),
            p[2] + 1e-6 * (comps[i].u[2] + comps[j].u[2]),
          ]);
          if (mid && violates(mid)) return false;
          if (violates(p)) return false;
        }
      }
    }
    const fib = getFibonacciSphere(2500);
    for (let i = 0; i < fib.length; i++) {
      if (violates(fib[i])) return false;
    }
    return true;
  }

  /**
   * Exact O(K^3) Byzantine (K-f)-core spherical cap solver with exact whole-Earth detection
   * and uniform Fibonacci surface area integration. Zero artificial caps!
   */
  function solveByzantineCore(circles, byzantineF = 1, refLatLon = null) {
    const k = circles.length;
    if (k === 0) {
      return {
        feasible: true,
        wholeEarth: true,
        feasibleState: "no_verified_constraint",
        requiredCount: 0,
        provenMaxRadiusKm: HALF_CIRCUMFERENCE_KM,
        provenMaxRadiusMi: HALF_CIRCUMFERENCE_KM * KM_TO_MI,
        areaKm2: EARTH_SURFACE_KM2,
        areaFraction: 1.0,
        witnessCentroid: refLatLon || [0, 0],
        disks: [],
      };
    }

    const f = Math.min(byzantineF, Math.max(0, k - 1));
    const required = Math.max(1, k - f);
    const disks = circles.map((c) => {
      const theta = Math.min(Math.PI, Math.max(0, c.radiusKm / EARTH_RADIUS_KM));
      return {
        anchor: c.anchor,
        lat: c.lat,
        lon: c.lon,
        rttMs: c.rttMs,
        radiusKm: theta * EARTH_RADIUS_KM,
        u: toVec3(c.lat, c.lon),
        theta,
        cosTheta: Math.cos(theta),
      };
    });

    if (isWholeEarthCore(disks, f)) {
      return {
        feasible: true,
        wholeEarth: true,
        feasibleState: "whole_earth",
        requiredCount: required,
        provenMaxRadiusKm: HALF_CIRCUMFERENCE_KM,
        provenMaxRadiusMi: HALF_CIRCUMFERENCE_KM * KM_TO_MI,
        areaKm2: EARTH_SURFACE_KM2,
        areaFraction: 1.0,
        witnessCentroid: refLatLon || [disks[0].lat, disks[0].lon],
        disks,
      };
    }

    const inCore = (p) => {
      let cnt = 0;
      for (let i = 0; i < k; i++) {
        if (dot3(p, disks[i].u) >= disks[i].cosTheta - 1e-11) cnt++;
      }
      return cnt >= required;
    };

    // Exact candidate boundary vertices
    const cands = [];
    for (let i = 0; i < k; i++) cands.push(disks[i].u);
    for (let i = 0; i < k; i++) {
      for (let j = i + 1; j < k; j++) {
        const pts = circleIntersections(disks[i].u, disks[i].cosTheta, disks[j].u, disks[j].cosTheta);
        for (const p of pts) cands.push(p);
      }
    }

    // Fibonacci sphere integration for exact area + interior witnesses
    const fib = getFibonacciSphere(2500);
    let fibInside = 0;
    const feasiblePts = [];
    for (let i = 0; i < fib.length; i++) {
      if (inCore(fib[i])) {
        fibInside++;
        feasiblePts.push(fib[i]);
      }
    }
    for (const p of cands) {
      if (inCore(p)) feasiblePts.push(p);
    }

    if (feasiblePts.length === 0) {
      return {
        feasible: false,
        wholeEarth: false,
        feasibleState: "inconsistent",
        requiredCount: required,
        provenMaxRadiusKm: 0,
        provenMaxRadiusMi: 0,
        areaKm2: 0,
        areaFraction: 0,
        witnessCentroid: refLatLon || [disks[0].lat, disks[0].lon],
        disks,
      };
    }

    // Witness centroid guaranteed to lie INSIDE the core!
    let sx = 0, sy = 0, sz = 0;
    for (const p of feasiblePts) {
      sx += p[0]; sy += p[1]; sz += p[2];
    }
    let centroidU = normalize3([sx, sy, sz]);
    if (!centroidU || !inCore(centroidU)) {
      centroidU = feasiblePts[0];
    }

    const refU = refLatLon ? toVec3(refLatLon[0], refLatLon[1]) : centroidU;
    // Also add exact furthest boundary points on every cap relative to refU!
    for (let i = 0; i < k; i++) {
      for (const p of furthestPointsOnCircle(disks[i].u, disks[i].theta, refU)) {
        if (inCore(p)) feasiblePts.push(p);
      }
    }

    let maxKm = 0;
    for (const p of feasiblePts) {
      const d = geodesicKmVec(refU, p);
      if (d > maxKm) maxKm = d;
    }

    const areaFraction = Math.max(fibInside / fib.length, feasiblePts.length > 0 ? 1 / (fib.length * 4) : 0);
    return {
      feasible: true,
      wholeEarth: false,
      feasibleState: "bounded",
      requiredCount: required,
      provenMaxRadiusKm: Math.min(HALF_CIRCUMFERENCE_KM, maxKm),
      provenMaxRadiusMi: Math.min(HALF_CIRCUMFERENCE_KM, maxKm) * KM_TO_MI,
      areaKm2: areaFraction * EARTH_SURFACE_KM2,
      areaFraction,
      witnessCentroid: vec3ToLatLon(centroidU),
      disks,
    };
  }

  // --- Correlated Spatial Likelihood Surface (Cholesky shared-path whitening) ---
  function choleskyLower(mat) {
    const n = mat.length;
    const L = Array.from({ length: n }, () => new Float64Array(n));
    for (let i = 0; i < n; i++) {
      for (let j = 0; j <= i; j++) {
        let s = 0;
        for (let k = 0; k < j; k++) s += L[i][k] * L[j][k];
        L[i][j] = i === j ? Math.sqrt(Math.max(1e-12, mat[i][i] - s)) : (mat[i][j] - s) / L[j][j];
      }
    }
    return L;
  }

  function solveLower(L, b, outBuf) {
    const n = b.length;
    const y = outBuf || new Float64Array(n);
    for (let i = 0; i < n; i++) {
      let s = b[i];
      const row = L[i];
      for (let k = 0; k < i; k++) s -= row[k] * y[k];
      y[i] = s / row[i];
    }
    return y;
  }

  function quantileType7Sorted(sorted, q) {
    if (!sorted || sorted.length === 0) return 0;
    const i = (sorted.length - 1) * Math.max(0, Math.min(1, q));
    const lo = Math.floor(i);
    const hi = Math.ceil(i);
    return sorted[lo] + (sorted[hi] - sorted[lo]) * (i - lo);
  }

  /**
   * Robust full-sample route-instability spread (ms) from multi-round RTT samples.
   * Detects slow-tail spikes, multimodal/ECMP flapping, and isolated-fast anomalies
   * so unstable routes show less certainty in the empirical likelihood surface,
   * while remaining ~0 ms on tight datacenter routes. Never modifies the physical Vacuum c0 bound.
   */
  function routeInstabilitySpreadMs(samplesMs) {
    if (!Array.isArray(samplesMs) || samplesMs.length < 2) return 0;
    const s = samplesMs.filter((x) => Number.isFinite(x) && x > 0).sort((a, b) => a - b);
    if (s.length < 2) return 0;
    const n = s.length;
    const mn = s[0];
    const p10 = quantileType7Sorted(s, 0.1);
    const p25 = quantileType7Sorted(s, 0.25);
    const med = quantileType7Sorted(s, 0.5);
    const p75 = quantileType7Sorted(s, 0.75);
    const p90 = quantileType7Sorted(s, 0.9);
    const legacyJitter = Math.max(0, med - mn);
    const p90p10 = Math.max(0, p90 - p10);
    const iqr = Math.max(0, p75 - p25);

    let isoGap = 0;
    let cleanStart = 0;
    if (n >= 4) {
      const bodySpread = Math.max(0.15, med - s[1]);
      const gap0 = s[1] - s[0];
      if (gap0 > Math.max(2.0, 4.0 * bodySpread)) {
        isoGap = gap0;
        cleanStart = 1;
      }
    }
    const clean = cleanStart ? s.slice(cleanStart) : s;
    let bimodalGap = 0;
    if (clean.length >= 4) {
      const m = clean.length;
      let bestG = 0;
      let bestI = -1;
      for (let idx = 1; idx < m - 2; idx++) {
        const g = clean[idx + 1] - clean[idx];
        if (g > bestG) {
          bestG = g;
          bestI = idx;
        }
      }
      if (bestI >= 0) {
        const leftSpan = clean[bestI] - clean[0];
        const rightSpan = clean[m - 1] - clean[bestI + 1];
        const localScale = Math.max(0.25, Math.min(leftSpan, rightSpan));
        if (bestG > Math.max(3.0, 3.0 * localScale)) {
          bimodalGap = bestG;
        }
      }
    }
    return Math.max(legacyJitter, 0.5 * p90p10, 0.6 * iqr, 0.75 * bimodalGap, 0.5 * isoGap);
  }

  /**
   * Prepare & evaluate the correlated spatial likelihood surface strictly inside
   * the raw Vacuum c0 outer bound. Returns peaks (1 or multiple), areas, kEff,
   * and a fast pixel evaluator `evalDeltaNllUnit(u)` for the canvas heatmap layer!
   */
  function computeSpatialLikelihoodSurface(measurements, opts = {}) {
    const cfg = Object.assign({}, DEFAULT_LIKELIHOOD_CONFIG, opts.config || {});
    const byzF = opts.byzantineF ?? 0;
    const isBrowser = !!opts.isBrowserProbe;
    if (!measurements || measurements.length === 0) return null;

    const k = measurements.length;
    const units = measurements.map((m) => toVec3(m.anchor.lat, m.anchor.lon));

    // Raw Vacuum c0 outer mask (NEVER narrowed by calibration or browser offset!)
    const vacRadiiKm = measurements.map((m) =>
      rttToRadiusKm(m.minMs ?? m.rttMs, "vacuum", {
        isBrowserProbe: isBrowser,
        anchorUncertaintyKm: m.anchorUncertaintyKm ?? 35.0,
      })
    );
    const vacCos = vacRadiiKm.map((r) => Math.cos(Math.min(Math.PI, r / EARTH_RADIUS_KM)));
    const reqVac = Math.max(1, k - Math.min(byzF, k - 1));

    // Representative RTT per anchor (frozen median winner if available, else rttMs) + full route-instability spread
    const repRtts = measurements.map((m) => {
      if (Array.isArray(m.samples) && m.samples.length > 0 && m.medianMs === undefined) {
        const s = m.samples.filter((x) => Number.isFinite(x) && x > 0).sort((a, b) => a - b);
        if (s.length > 0) return quantileType7Sorted(s, 0.5);
      }
      return m.medianMs ?? m.rttMs;
    });
    const jitters = measurements.map((m) => {
      const baseJit = Math.max(0, m.jitterMs ?? (m.medianMs && m.minMs ? m.medianMs - m.minMs : 0));
      if (Array.isArray(m.samples) && m.samples.length >= 2) {
        return Math.max(baseJit, routeInstabilitySpreadMs(m.samples));
      }
      return baseJit;
    });

    // For noisy browser Wi-Fi/cellular probes ONLY, estimate a non-negative shared last-mile overhead
    // strictly inside the empirical likelihood surface (NEVER touches Vacuum c0 or Fiber!).
    let browserOffsetMs = 0;
    if (isBrowser && k >= 3) {
      const minObs = Math.min(...repRtts);
      // Conservative estimate: 0 if datacenter-fast (<12ms), else bounded non-negative TDOA profile
      if (minObs > 12.0) {
        browserOffsetMs = Math.min(minObs - 4.0, Math.max(0, minObs * 0.45));
      }
    }

    const sigmas = repRtts.map((r, i) => {
      const base = isBrowser ? Math.max(cfg.sigmaBaseMs, 4.0) : cfg.sigmaBaseMs;
      return Math.max(0.35, Math.hypot(base, cfg.sigmaRel * Math.max(0, r), cfg.sigmaJit * jitters[i]));
    });

    const rho = Math.max(0, Math.min(0.99, cfg.rho));
    const lCorr = Math.max(1, cfg.lCorrKm);
    const Sigma = Array.from({ length: k }, () => new Float64Array(k));
    const Corr = Array.from({ length: k }, () => new Float64Array(k));
    for (let i = 0; i < k; i++) {
      for (let j = i; j < k; j++) {
        const c = i === j ? 1.0 : rho * Math.exp(-geodesicKmVec(units[i], units[j]) / lCorr);
        Corr[i][j] = Corr[j][i] = c;
        Sigma[i][j] = Sigma[j][i] = sigmas[i] * sigmas[j] * c;
      }
    }

    const LSig = choleskyLower(Sigma);
    const LCor = choleskyLower(Corr);
    const ones = new Float64Array(k).fill(1);
    const onesW = solveLower(LCor, ones);
    let kEff = 0;
    for (let i = 0; i < k; i++) kEff += onesW[i] * onesW[i];

    const rBuf = new Float64Array(k);
    const zBuf = new Float64Array(k);

    const evalNllUnit = (pt) => {
      for (let i = 0; i < k; i++) {
        const dKm = geodesicKmVec(pt, units[i]);
        const v = cfg.v0KmMs + (cfg.v1KmMs - cfg.v0KmMs) * (1 - Math.exp(-dKm / cfg.dKneeKm));
        const pred = cfg.t0Ms + browserOffsetMs + (2.0 * dKm) / Math.max(1.0, v);
        let diff = repRtts[i] - pred;
        if (diff > 0 && cfg.asymSlow > 1.0) diff /= cfg.asymSlow;
        rBuf[i] = diff;
      }
      solveLower(LSig, rBuf, zBuf);
      let quad = 0;
      for (let i = 0; i < k; i++) quad += zBuf[i] * zBuf[i];
      if (cfg.studentTNu !== null && cfg.studentTNu > 0) {
        const nu = Math.max(0.5, cfg.studentTNu);
        return 0.5 * (nu + kEff) * Math.log(1 + quad / nu);
      }
      return 0.5 * quad;
    };

    const inVacuum = (pt) => {
      let c = 0;
      for (let i = 0; i < k; i++) {
        if (dot3(pt, units[i]) >= vacCos[i] - 1e-11) c++;
      }
      return c >= reqVac;
    };

    const fib = getFibonacciSphere(cfg.gridPoints);
    const feasible = [];
    let bestNll = Infinity;
    let bestU = units[0];
    for (let i = 0; i < fib.length; i++) {
      const pt = fib[i];
      if (!inVacuum(pt)) continue;
      const nll = evalNllUnit(pt);
      if (nll < bestNll) {
        bestNll = nll;
        bestU = pt;
      }
      feasible.push({ pt, nll });
    }

    if (feasible.length === 0) {
      return {
        isEmpiricalEstimate: true,
        isHardProof: false,
        qualitativeScale: "more_likely_to_less_likely",
        effectiveIndependentAnchors: kEff,
        anchorCount: k,
        peaks: [],
        moreLikelyAreaKm2: 0,
        moreLikelyAreaFraction: 0,
        plausibleAreaKm2: 0,
        plausibleAreaFraction: 0,
        vacuumOuterAreaKm2: 0,
        vacuumOuterAreaFraction: 0,
        tauMoreLikely: cfg.tauMoreLikely,
        tauPlausible: cfg.tauPlausible,
        browserOffsetMs,
        evalDeltaNllUnit: () => Infinity,
      };
    }

    // Local polish around primary peak (staying strictly inside Vacuum c0!)
    let bestLL = vec3ToLatLon(bestU);
    for (const step of [1.5, 0.4, 0.1]) {
      const cLat = bestLL[0], cLon = bestLL[1];
      for (let dl = -2; dl <= 2; dl++) {
        for (let dn = -2; dn <= 2; dn++) {
          const lat = Math.max(-89.5, Math.min(89.5, cLat + dl * step));
          const lon = ((((cLon + dn * step) + 180) % 360) + 360) % 360 - 180;
          const cu = toVec3(lat, lon);
          if (!inVacuum(cu)) continue;
          const cn = evalNllUnit(cu);
          if (cn < bestNll) {
            bestNll = cn;
            bestLL = [lat, lon];
            bestU = cu;
          }
        }
      }
    }

    const mlPts = [];
    let plCount = 0;
    for (const item of feasible) {
      const delta = Math.max(0, item.nll - bestNll);
      if (delta <= cfg.tauPlausible) plCount++;
      if (delta <= cfg.tauMoreLikely) mlPts.push({ delta, pt: item.pt });
    }
    mlPts.sort((a, b) => a.delta - b.delta);

    const peakUnits = [{ delta: 0, pt: bestU }];
    for (const cand of mlPts) {
      if (peakUnits.every((p) => geodesicKmVec(cand.pt, p.pt) >= cfg.peakSeparationKm)) {
        peakUnits.push(cand);
        if (peakUnits.length >= 4) break;
      }
    }

    const peaks = peakUnits.map(({ delta, pt }) => {
      const [lat, lon] = vec3ToLatLon(pt);
      return {
        lat,
        lon,
        deltaNll: delta,
        relativeLikelihood: Math.exp(-delta),
        qualitativeBand: delta <= cfg.tauMoreLikely ? "more_likely" : "plausible",
      };
    });

    const vacFrac = feasible.length / fib.length;
    const mlFrac = Math.max(1, mlPts.length) / fib.length;
    const plFrac = Math.max(1, plCount, mlPts.length) / fib.length;

    return {
      isEmpiricalEstimate: true,
      isHardProof: false,
      qualitativeScale: "more_likely_to_less_likely",
      effectiveIndependentAnchors: kEff,
      anchorCount: k,
      peaks,
      moreLikelyAreaKm2: mlFrac * EARTH_SURFACE_KM2,
      moreLikelyAreaFraction: mlFrac,
      plausibleAreaKm2: plFrac * EARTH_SURFACE_KM2,
      plausibleAreaFraction: plFrac,
      vacuumOuterAreaKm2: vacFrac * EARTH_SURFACE_KM2,
      vacuumOuterAreaFraction: vacFrac,
      tauMoreLikely: cfg.tauMoreLikely,
      tauPlausible: cfg.tauPlausible,
      browserOffsetMs,
      evalDeltaNllUnit: (pt) => Math.max(0, evalNllUnit(pt) - bestNll),
    };
  }

  /**
   * Full scene solver: computes conservative Tier 1A Vacuum outer bound, Tier 1B Fiber bound,
   * and optional correlated spatial likelihood surface strictly inside Vacuum c0.
   */
  function solveLocation(measurements, tierId = "vacuum", opts = {}) {
    if (!measurements || measurements.length === 0) return null;
    const k = measurements.length;
    const byzF = opts.byzantineF ?? (k >= 4 ? 1 : 0);
    const activeTier = tierId === "fiber" ? "fiber" : "vacuum";

    const circles = measurements
      .map((m) => {
        const minRtt = m.minMs ?? m.rttMs;
        return {
          anchor: m.anchor,
          lat: m.anchor.lat,
          lon: m.anchor.lon,
          rttMs: minRtt,
          medianMs: m.medianMs ?? m.rttMs,
          jitterMs: m.jitterMs ?? 0,
          radiusKm: rttToRadiusKm(minRtt, activeTier, {
            isBrowserProbe: !!opts.isBrowserProbe,
            anchorUncertaintyKm: m.anchorUncertaintyKm ?? 35.0,
          }),
        };
      })
      .sort((a, b) => a.rttMs - b.rttMs);

    const core = solveByzantineCore(circles, byzF, opts.refLatLon || null);
    const likelihood =
      opts.skipLikelihood === true
        ? null
        : computeSpatialLikelihoodSurface(measurements, {
            byzantineF: byzF,
            isBrowserProbe: !!opts.isBrowserProbe,
            config: opts.likelihoodConfig,
          });

    return {
      tierId: activeTier,
      circles,
      core,
      feasible: core.feasible,
      wholeEarth: core.wholeEarth,
      feasibleState: core.feasibleState,
      requiredCount: core.requiredCount,
      byzantineF: Math.min(byzF, Math.max(0, k - 1)),
      centroid: core.witnessCentroid,
      maxRadiusKm: core.provenMaxRadiusKm,
      maxRadiusMi: core.provenMaxRadiusMi,
      areaKm2: core.areaKm2,
      areaFraction: core.areaFraction,
      nearest: circles[0],
      likelihood,
    };
  }

  /**
   * Pure closed-form spherical cap inequality check for a claimed coordinate.
   * Uses ONLY conservative outer bounds (NEVER uses best-fit or empirical calibration for hard exclusions!).
   */
  function evaluateSpoofClaim(claimLat, claimLon, measurements, tierId = "vacuum", opts = {}) {
    const activeTier = tierId === "fiber" ? "fiber" : "vacuum";
    const k = measurements.length;
    const byzF = opts.byzantineF ?? (k >= 4 ? 1 : 0);
    const claimU = toVec3(claimLat, claimLon);

    const results = measurements.map((m) => {
      const rttMs = m.minMs ?? m.rttMs;
      const distKm = geodesicKmVec(claimU, toVec3(m.anchor.lat, m.anchor.lon));
      const maxKm = rttToRadiusKm(rttMs, activeTier, opts);
      const vacKm = rttToRadiusKm(rttMs, "vacuum", opts);
      const violated = distKm > maxKm + 1e-6;
      const violatedVacuum = distKm > vacKm + 1e-6;
      const impliedVelocityKmPerMs = rttMs > 0 ? (2 * distKm) / rttMs : Infinity;
      const cMultiple = impliedVelocityKmPerMs / C_VACUUM_KM_PER_MS;
      return {
        anchor: m.anchor,
        rttMs,
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
    // Under Byzantine tolerance f, a claim is strictly excluded ONLY if > f anchors are violated!
    const excludedAtF = violations.length > byzF;
    const excludedVacuumAtF = vacViolations.length > byzF;
    return {
      claimLat,
      claimLon,
      tierId: activeTier,
      byzantineF: byzF,
      results,
      violations,
      vacViolations,
      caught: excludedAtF,
      caughtByAnyAnchor: violations.length > 0,
      caughtByVacuum: excludedVacuumAtF,
    };
  }

  global.PogGeo = {
    EARTH_RADIUS_KM,
    WGS84_MIN_CURVATURE_RADIUS_KM,
    HALF_CIRCUMFERENCE_KM,
    EARTH_SURFACE_KM2,
    KM_TO_MI,
    TIERS,
    DEFAULT_LIKELIHOOD_CONFIG,
    toVec3,
    vec3ToLatLon,
    dot3,
    haversineKm,
    geodesicKmVec,
    rttToRadiusKm,
    destPoint,
    capFillMercator,
    geodesicCircleGeometry,
    greatCircleArc,
    isWholeEarthCore,
    solveByzantineCore,
    routeInstabilitySpreadMs,
    computeSpatialLikelihoodSurface,
    solveLocation,
    evaluateSpoofClaim,
  };
})(typeof window !== "undefined" ? window : globalThis);
