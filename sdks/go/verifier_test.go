package pog

import (
	"encoding/json"
	"os"
	"testing"
)

type sdkFixture struct {
	NowUnixS               uint64     `json:"now_unix_s"`
	Grid                   AnchorGrid `json:"grid"`
	HonestTokyoHeader      string     `json:"honest_tokyo_header"`
	SpoofedSingaporeHeader string     `json:"spoofed_singapore_header"`
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
	if !rep.HasGpuBinding || rep.Tier1AVacuum.ProvenMaxRadiusMiles >= 130 {
		t.Fatalf("unexpected honest metrics: gpu=%v miles=%.1f", rep.HasGpuBinding, rep.Tier1AVacuum.ProvenMaxRadiusMiles)
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
}
