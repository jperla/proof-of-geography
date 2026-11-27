package pog

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"testing"
)

type sdkFixture struct {
	NowUnixS               uint64     `json:"now_unix_s"`
	Grid                   AnchorGrid `json:"grid"`
	HonestTokyoHeader      string     `json:"honest_tokyo_header"`
	SpoofedSingaporeHeader string     `json:"spoofed_singapore_header"`
}

func makeSignedReg(t *testing.T, netID, op string, grid AnchorGrid, now uint64) (SignedNetworkRegistry, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	pubHex := hex.EncodeToString(pub)
	reg := SignedNetworkRegistry{
		Version:          1,
		NetworkID:        netID,
		OperatorName:     op,
		RootPublicKeyHex: pubHex,
		IssuedAtUnixS:    now - 60,
		ExpiresAtUnixS:   now + 86400,
		Grid:             grid,
	}
	digest := SignedRegistryDigest(reg)
	reg.OperatorSignatureHex = hex.EncodeToString(ed25519.Sign(priv, digest[:]))
	return reg, pubHex
}

func TestVerifyRustGeneratedHeaders(t *testing.T) {
	raw, err := os.ReadFile("../testdata/fixture.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var fx sdkFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}

	policy := VerificationPolicy{
		AllowSoftwareDev:   true,
		MaxByzantine:       1,
		MinAnchors:         5,
		MinCloudProviders:  3,
		MaxProofAgeSeconds: 3900,
		EnforceTier:        "vacuum",
	}

	honestBundle, err := DecodeProofHeader(fx.HonestTokyoHeader)
	if err != nil {
		t.Fatalf("decode honest header: %v", err)
	}
	rep := VerifyProof(honestBundle, fx.Grid, policy, fx.NowUnixS)
	if !rep.OverallValid {
		t.Fatalf("expected honest Tokyo bundle valid, got failures: %v", rep.FailureReasons)
	}
	if rep.HardwareAttested {
		t.Fatalf("SoftwareDev bundle MUST NOT report HardwareAttested=true")
	}
	if !rep.HasGpuBinding || rep.Tier1AVacuum.ProvenMaxRadiusMiles >= 186 {
		t.Fatalf("unexpected honest metrics: gpu=%v miles=%.1f", rep.HasGpuBinding, rep.Tier1AVacuum.ProvenMaxRadiusMiles)
	}
	if len(rep.ObservedProverIPs) < 5 || !rep.IPViewConsistent {
		t.Fatalf("unexpected observed IPs: %+v", rep.ObservedProverIPs)
	}

	// Production policy rejects SoftwareDev prover!
	prodRep := VerifyProof(honestBundle, fx.Grid, VerificationPolicy{}, fx.NowUnixS)
	if prodRep.OverallValid || prodRep.HardwareAttested {
		t.Fatalf("production policy MUST reject SoftwareDev prover")
	}

	// Tampered workload_measurement_hex on a receipt MUST fail!
	tampered := honestBundle
	tampered.Receipts = append([]AnchorReceipt(nil), honestBundle.Receipts...)
	tampered.Receipts[0].WorkloadMeasurementHex = "ff"
	tPolicy := policy
	tPolicy.MinAnchors = len(tampered.Receipts)
	tRep := VerifyProof(tampered, fx.Grid, tPolicy, fx.NowUnixS)
	if tRep.OverallValid || len(tRep.UnverifiedReceipts) == 0 {
		t.Fatalf("expected tampered workload_measurement_hex to fail and record unverified receipt")
	}

	spoofBundle, err := DecodeProofHeader(fx.SpoofedSingaporeHeader)
	if err != nil {
		t.Fatalf("decode spoof header: %v", err)
	}
	spoofRep := VerifyProof(spoofBundle, fx.Grid, policy, fx.NowUnixS)
	if spoofRep.OverallValid {
		t.Fatalf("expected Beijing-via-Singapore spoof to FAIL")
	}
	if spoofRep.Tier1AVacuum.ProvenMaxRadiusKm < 4000 {
		t.Fatalf("expected spoof worst-case radius > 4000 km, got %.1f", spoofRep.Tier1AVacuum.ProvenMaxRadiusKm)
	}

	regRaw, err := os.ReadFile("../../config/signed_grid_72_network.json")
	if err != nil {
		t.Fatalf("read signed_grid_72_network.json: %v", err)
	}
	var signed72 SignedNetworkRegistry
	if err := json.Unmarshal(regRaw, &signed72); err != nil {
		t.Fatalf("unmarshal signed72: %v", err)
	}
	if err := VerifySignedRegistry(signed72, signed72.RootPublicKeyHex, signed72.IssuedAtUnixS+10); err != nil {
		t.Fatalf("Rust-signed 72-node registry failed in Go: %v", err)
	}
	// config/signed_grid_72_network.json still lists 4 SoftwareDev AWS anchors -> MUST fail fail-closed production check!
	if err := ValidateProductionRegistry(signed72); err == nil {
		t.Fatalf("expected signed_grid_72_network.json with SoftwareDev AWS anchors to fail ValidateProductionRegistry")
	}
	// A clean all-hardware-TEE registry MUST pass ValidateProductionRegistry:
	cleanHw := signed72
	cleanHw.Grid.Anchors = append([]AnchorDescriptor(nil), signed72.Grid.Anchors...)
	for i := range cleanHw.Grid.Anchors {
		if cleanHw.Grid.Anchors[i].TeeVendor == "SoftwareDev" {
			cleanHw.Grid.Anchors[i].TeeVendor = "AwsNitro"
		}
	}
	if err := ValidateProductionRegistry(cleanHw); err != nil {
		t.Fatalf("unexpected prod registry error on clean hardware-TEE registry: %v", err)
	}
	signed72.Grid.Anchors[0].Location.Lat += 0.5
	if err := VerifySignedRegistry(signed72, signed72.RootPublicKeyHex, signed72.IssuedAtUnixS+10); err == nil {
		t.Fatalf("expected tampered signed registry to FAIL")
	}

	reg1, pk1 := makeSignedReg(t, "proofofgeography.com", "jperla", fx.Grid, fx.NowUnixS)
	reg2, pk2 := makeSignedReg(t, "cloudflare-pog", "Cloudflare", fx.Grid, fx.NowUnixS)
	fed := VerifyFederatedProof(
		[]NetworkProofSubmission{
			{NetworkID: "proofofgeography.com", Bundle: honestBundle},
			{NetworkID: "cloudflare-pog", Bundle: honestBundle},
		},
		[]TrustedNetwork{
			{NetworkID: "proofofgeography.com", PinnedRootPublicKeyHex: pk1, SignedRegistry: reg1},
			{NetworkID: "cloudflare-pog", PinnedRootPublicKeyHex: pk2, SignedRegistry: reg2},
		},
		policy,
		2,
		fx.NowUnixS,
	)
	if !fed.OverallValid || fed.ValidIndependentNetworks != 2 || !fed.ProverPKConsistentAcrossNetworks {
		t.Fatalf("expected federated 2-network proof valid, got: %+v", fed)
	}
}

func TestGeometryRegressions(t *testing.T) {
	r150 := EffectiveOuterRadiusKm(150_000, "vacuum", VerificationPolicy{}, 0, 152000)
	if math.Abs(r150-HalfCircumferenceKm) > 1e-3 {
		t.Fatalf("expected 150ms vacuum to reach whole earth %.2f, got %.2f", HalfCircumferenceKm, r150)
	}
	th := math.Min(math.Pi, r150/EarthRadiusKm)
	res150 := solveByzantineCore([]disk{
		{u: (LatLon{37.4, -121.9}).toUnit(), theta: th, cosTheta: math.Cos(th)},
		{u: (LatLon{50.1, 8.7}).toUnit(), theta: th, cosTheta: math.Cos(th)},
		{u: (LatLon{35.7, 139.7}).toUnit(), theta: th, cosTheta: math.Cos(th)},
	}, 0, LatLon{37.4, -121.9}, 15000)
	if !res150.WholeEarth || res150.ContainedWithinTarget || math.Abs(res150.ProvenMaxRadiusKm-HalfCircumferenceKm) > 1e-2 {
		t.Fatalf("150ms SJ/FRA/NRT repro failed: %+v", res150)
	}

	// Near co-located 1m apart
	th300 := 300.0 / EarthRadiusKm
	near := solveByzantineCore([]disk{
		{u: (LatLon{50.1109, 8.6821}).toUnit(), theta: th300, cosTheta: math.Cos(th300)},
		{u: (LatLon{50.110909, 8.6821}).toUnit(), theta: th300, cosTheta: math.Cos(th300)},
	}, 0, LatLon{50.1109, 8.6821}, 350)
	if !near.Feasible || !near.ContainedWithinTarget || math.Abs(near.ProvenMaxRadiusKm-300) > 1.5 {
		t.Fatalf("near-colocated 1m failed: %+v", near)
	}

	// Disconnected 2-of-4
	th400 := 400.0 / EarthRadiusKm
	disc := solveByzantineCore([]disk{
		{u: (LatLon{40.71, -74.0}).toUnit(), theta: th400, cosTheta: math.Cos(th400)},
		{u: (LatLon{40.8, -74.1}).toUnit(), theta: th400, cosTheta: math.Cos(th400)},
		{u: (LatLon{50.11, 8.68}).toUnit(), theta: th400, cosTheta: math.Cos(th400)},
		{u: (LatLon{50.2, 8.7}).toUnit(), theta: th400, cosTheta: math.Cos(th400)},
	}, 2, LatLon{40.71, -74.0}, 1000)
	if disc.ProvenMaxRadiusKm < 6400 {
		t.Fatalf("disconnected 2-of-4 expected >6400 km, got %.1f", disc.ProvenMaxRadiusKm)
	}

	// Correlated spatial likelihood surface: shared-path de-weighting & multi-peak ambiguity
	cfg := DefaultSpatialLikelihoodConfig()
	cfg.GridPoints = 1200
	base := []LikelihoodObservation{
		{AnchorID: "a1", Lat: 40.71, Lon: -74.0, RttMs: 28.0, RttMinMs: 27.5, JitterMs: 0.5},
		{AnchorID: "a2", Lat: 37.34, Lon: -121.89, RttMs: 52.0, RttMinMs: 51.4, JitterMs: 0.6},
		{AnchorID: "a3", Lat: 43.65, Lon: -79.38, RttMs: 19.0, RttMinMs: 18.6, JitterMs: 0.4},
		{AnchorID: "a4", Lat: 29.42, Lon: -98.49, RttMs: 34.0, RttMinMs: 33.5, JitterMs: 0.5},
	}
	dup := append([]LikelihoodObservation(nil), base...)
	for i := 0; i < 7; i++ {
		c := base[0]
		c.AnchorID = "dup"
		dup = append(dup, c)
	}
	sBase := ComputeSpatialLikelihood(base, cfg, VerificationPolicy{})
	sDup := ComputeSpatialLikelihood(dup, cfg, VerificationPolicy{})
	if !sBase.IsEmpiricalEstimate || sBase.IsHardProof {
		t.Fatalf("expected empirical estimate flag")
	}
	if sDup.EffectiveIndependentAnchors >= 5.0 {
		t.Fatalf("expected correlated duplicates k_eff < 5, got %.2f", sDup.EffectiveIndependentAnchors)
	}
	if sDup.MoreLikelyAreaKm2 < sBase.MoreLikelyAreaKm2*0.45 {
		t.Fatalf("correlated duplicates collapsed area: base=%.0f dup=%.0f", sBase.MoreLikelyAreaKm2, sDup.MoreLikelyAreaKm2)
	}
	sym := ComputeSpatialLikelihood([]LikelihoodObservation{
		{AnchorID: "west", Lat: 0, Lon: -15, RttMs: 35, RttMinMs: 34.8, JitterMs: 0.2},
		{AnchorID: "east", Lat: 0, Lon: 15, RttMs: 35, RttMinMs: 34.8, JitterMs: 0.2},
	}, cfg, VerificationPolicy{})
	if len(sym.Peaks) < 2 {
		t.Fatalf("expected >=2 symmetric peaks, got %d", len(sym.Peaks))
	}
}
