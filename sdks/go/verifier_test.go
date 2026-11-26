package pog

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
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
	if !rep.HasGpuBinding || rep.Tier1AVacuum.ProvenMaxRadiusMiles >= 130 {
		t.Fatalf("unexpected honest metrics: gpu=%v miles=%.1f", rep.HasGpuBinding, rep.Tier1AVacuum.ProvenMaxRadiusMiles)
	}
	if len(rep.ObservedProverIPs) < 5 || !rep.IPViewConsistent {
		t.Fatalf("unexpected observed IPs: %+v", rep.ObservedProverIPs)
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

	// Cross-verify real Rust-signed 72-node registry!
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
	signed72.Grid.Anchors[0].Location.Lat += 0.5
	if err := VerifySignedRegistry(signed72, signed72.RootPublicKeyHex, signed72.IssuedAtUnixS+10); err == nil {
		t.Fatalf("expected tampered signed registry to FAIL")
	}

	// Federated 2-independent-network verification
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
