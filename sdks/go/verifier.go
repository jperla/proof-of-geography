package pog

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strings"
)

const (
	EarthRadiusKm      = 6371.0088
	CVacuumKmPerS      = 299792.458
	CFiberKmPerS       = 204000.0
	HTTPHeaderPoGProof = "X-PoG-Proof"
)

type LatLon struct {
	Lat float64 `json:"lat"`
	Lon float64 `json:"lon"`
}

type AnchorDescriptor struct {
	AnchorID      string `json:"anchor_id"`
	CloudProvider string `json:"cloud_provider"`
	Region        string `json:"region"`
	City          string `json:"city"`
	Location      LatLon `json:"location"`
	EndpointTCP   string `json:"endpoint_tcp"`
	PublicKeyHex  string `json:"public_key_hex"`
}

type AnchorGrid struct {
	Version  string             `json:"version"`
	GridName string             `json:"grid_name"`
	Anchors  []AnchorDescriptor `json:"anchors"`
}

type SignedNetworkRegistry struct {
	Version              uint8      `json:"version"`
	NetworkID            string     `json:"network_id"`
	OperatorName         string     `json:"operator_name"`
	RootPublicKeyHex     string     `json:"root_public_key_hex"`
	IssuedAtUnixS        uint64     `json:"issued_at_unix_s"`
	ExpiresAtUnixS       uint64     `json:"expires_at_unix_s"`
	Grid                 AnchorGrid `json:"grid"`
	OperatorSignatureHex string     `json:"operator_signature_hex"`
}

type AnchorEndorsement struct {
	NetworkID          string  `json:"network_id"`
	AnchorID           string  `json:"anchor_id"`
	AnchorPublicKeyHex string  `json:"anchor_public_key_hex"`
	Lat                float64 `json:"lat"`
	Lon                float64 `json:"lon"`
	IssuedAtUnixS      uint64  `json:"issued_at_unix_s"`
	ExpiresAtUnixS     uint64  `json:"expires_at_unix_s"`
	RootPublicKeyHex   string  `json:"root_public_key_hex"`
	RootSignatureHex   string  `json:"root_signature_hex"`
}

type TrustedNetwork struct {
	NetworkID              string
	PinnedRootPublicKeyHex string
	SignedRegistry         SignedNetworkRegistry
}

type NetworkSource struct {
	NetworkID              string
	RegistryURL            string
	PinnedRootPublicKeyHex string
}

type NetworkProofSubmission struct {
	NetworkID string
	Bundle    GeoProofBundle
}

type AnchorObservedIP struct {
	AnchorID      string
	CloudProvider string
	ObservedIP    string
	RttMinUs      uint64
}

type GpuAttestationBinding struct {
	GpuModel             string `json:"gpu_model"`
	GpuUUID              string `json:"gpu_uuid"`
	SpdmReportHashHex    string `json:"spdm_report_hash_hex"`
	DriverMeasurementHex string `json:"driver_measurement_hex"`
}

type TeeAttestationQuote struct {
	Vendor                 string                 `json:"vendor"`
	PublicKeyHex           string                 `json:"public_key_hex"`
	WorkloadMeasurementHex string                 `json:"workload_measurement_hex"`
	ReportDataHex          string                 `json:"report_data_hex"`
	NonceHex               string                 `json:"nonce_hex"`
	MigrationDisabled      bool                   `json:"migration_disabled"`
	DebugDisabled          bool                   `json:"debug_disabled"`
	SecureTscEnabled       bool                   `json:"secure_tsc_enabled"`
	GpuBinding             *GpuAttestationBinding `json:"gpu_binding"`
	RawQuoteB64            string                 `json:"raw_quote_b64"`
	GeneratedAtUnixS       uint64                 `json:"generated_at_unix_s"`
}

type AnchorReceipt struct {
	AnchorID               string   `json:"anchor_id"`
	CloudProvider          string   `json:"cloud_provider"`
	ProverPKHex            string   `json:"prover_pk_hex"`
	WorkloadMeasurementHex string   `json:"workload_measurement_hex"`
	EpochChallengeHex      string   `json:"epoch_challenge_hex"`
	ProverObservedIP       string   `json:"prover_observed_ip"`
	RttMinUs               uint64   `json:"rtt_min_us"`
	RttP50Us               uint64   `json:"rtt_p50_us"`
	RttSamplesUs           []uint64 `json:"rtt_samples_us"`
	MeasuredAtUnixS        uint64   `json:"measured_at_unix_s"`
	AnchorSignatureHex     string   `json:"anchor_signature_hex"`
}

type GeoProofBundle struct {
	Version                   uint8               `json:"version"`
	EpochChallengeHex         string              `json:"epoch_challenge_hex"`
	ClientNonceHex            *string             `json:"client_nonce_hex"`
	TargetLocation            LatLon              `json:"target_location"`
	RequiredRadiusKm          float64             `json:"required_radius_km"`
	ProverQuote               TeeAttestationQuote `json:"prover_quote"`
	Receipts                  []AnchorReceipt     `json:"receipts"`
	CalibratedVelocityKmPerS  *float64            `json:"calibrated_velocity_km_per_s"`
	PrevChainHashHex          *string             `json:"prev_chain_hash_hex"`
	ChainSeq                  uint64              `json:"chain_seq"`
	CreatedAtUnixS            uint64              `json:"created_at_unix_s"`
}

type VerificationPolicy struct {
	AllowSoftwareDev   bool
	MaxByzantine       int
	MinAnchors         int
	MinCloudProviders  int
	MaxProofAgeSeconds uint64
	EnforceTier        string // "vacuum" | "fiber" | "calibrated"
}

type CoreResult struct {
	ProvenMaxRadiusKm     float64
	ProvenMaxRadiusMiles  float64
	ContainedWithinTarget bool
	WitnessCentroid       LatLon
}

type VerificationReport struct {
	OverallValid           bool
	FailureReasons         []string
	DistinctClouds         int
	VerifiedReceipts       int
	ProverPublicKeyHex     string
	WorkloadMeasurementHex string
	HasGpuBinding          bool
	ObservedProverIPs      []AnchorObservedIP
	DistinctObservedIPs    []string
	IPViewConsistent       bool
	Tier1AVacuum           CoreResult
	Tier1BFiber            CoreResult
	Tier2Calibrated        CoreResult
}

type PerNetworkVerification struct {
	NetworkID              string
	OperatorName           string
	RegistrySignatureValid bool
	ProofValid             bool
	Report                 *VerificationReport
	Error                  string
}

type FederatedVerificationReport struct {
	OverallValid                     bool
	RequiredIndependentNetworks      int
	ValidIndependentNetworks         int
	DistinctOperatorsVerified        []string
	ProverPKConsistentAcrossNetworks bool
	ObservedProverIPsAcrossNetworks  []string
	IPConsistentAcrossNetworks       bool
	ConsensusTier1AVacuumKm          *float64
	ConsensusTier1BFiberKm           *float64
	ConsensusTier2CalibratedKm       *float64
	FailureReasons                   []string
	PerNetwork                       []PerNetworkVerification
}

type vec3 struct{ x, y, z float64 }

func (p LatLon) toUnit() vec3 {
	lat := p.Lat * math.Pi / 180.0
	lon := p.Lon * math.Pi / 180.0
	c := math.Cos(lat)
	return vec3{c * math.Cos(lon), c * math.Sin(lon), math.Sin(lat)}
}

func (v vec3) toLatLon() LatLon {
	n := v.norm()
	if n == 0 {
		return LatLon{}
	}
	x, y, z := v.x/n, v.y/n, v.z/n
	z = math.Max(-1, math.Min(1, z))
	return LatLon{Lat: math.Asin(z) * 180.0 / math.Pi, Lon: math.Atan2(y, x) * 180.0 / math.Pi}
}

func (a vec3) dot(b vec3) float64 { return a.x*b.x + a.y*b.y + a.z*b.z }
func (a vec3) cross(b vec3) vec3 {
	return vec3{a.y*b.z - a.z*b.y, a.z*b.x - a.x*b.z, a.x*b.y - a.y*b.x}
}
func (a vec3) scale(s float64) vec3 { return vec3{a.x * s, a.y * s, a.z * s} }
func (a vec3) add(b vec3) vec3      { return vec3{a.x + b.x, a.y + b.y, a.z + b.z} }
func (a vec3) sub(b vec3) vec3      { return vec3{a.x - b.x, a.y - b.y, a.z - b.z} }
func (a vec3) norm() float64        { return math.Sqrt(a.dot(a)) }
func (a vec3) normalize() (vec3, bool) {
	n := a.norm()
	if n < 1e-15 {
		return vec3{}, false
	}
	return a.scale(1.0 / n), true
}

func geodesicKm(a, b vec3) float64 {
	d := math.Max(-1, math.Min(1, a.dot(b)))
	return math.Acos(d) * EarthRadiusKm
}

type disk struct {
	u        vec3
	theta    float64
	cosTheta float64
}

func intersectTwoCircles(u1 vec3, c1 float64, u2 vec3, c2 float64) []vec3 {
	d := u1.dot(u2)
	denom := 1.0 - d*d
	if denom < 1e-12 {
		return nil
	}
	a := (c1 - c2*d) / denom
	b := (c2 - c1*d) / denom
	p := u1.scale(a).add(u2.scale(b))
	pSq := p.dot(p)
	if pSq > 1.0+1e-11 {
		return nil
	}
	n := u1.cross(u2)
	nSq := n.dot(n)
	if nSq < 1e-15 {
		return nil
	}
	t := math.Sqrt(math.Max(0, 1.0-pSq) / nSq)
	if t < 1e-12 {
		if u, ok := p.normalize(); ok {
			return []vec3{u}
		}
		return nil
	}
	var out []vec3
	if x1, ok := p.add(n.scale(t)).normalize(); ok {
		out = append(out, x1)
	}
	if x2, ok := p.sub(n.scale(t)).normalize(); ok {
		out = append(out, x2)
	}
	return out
}

func furthestOnCircle(u vec3, theta float64, target vec3) vec3 {
	if theta >= math.Pi-1e-12 {
		return target.scale(-1)
	}
	negT := target.scale(-1)
	proj := negT.sub(u.scale(negT.dot(u)))
	dir, ok := proj.normalize()
	if !ok {
		basis := vec3{1, 0, 0}
		if math.Abs(u.x) >= 0.9 {
			basis = vec3{0, 1, 0}
		}
		dir, _ = u.cross(basis).normalize()
	}
	res, _ := u.scale(math.Cos(theta)).add(dir.scale(math.Sin(theta))).normalize()
	return res
}

func solveByzantineCore(disks []disk, maxByzantine int, target LatLon, reqKm float64) CoreResult {
	k := len(disks)
	if k == 0 {
		return CoreResult{ProvenMaxRadiusKm: math.Inf(1), ProvenMaxRadiusMiles: math.Inf(1)}
	}
	f := maxByzantine
	if f >= k {
		f = k - 1
	}
	req := k - f
	const eps = 1e-9
	targetU := target.toUnit()
	countIn := func(x vec3) int {
		c := 0
		for _, d := range disks {
			if d.u.dot(x) >= d.cosTheta-eps {
				c++
			}
		}
		return c
	}

	var pts []vec3
	for i := 0; i < k; i++ {
		for j := i + 1; j < k; j++ {
			for _, p := range intersectTwoCircles(disks[i].u, disks[i].cosTheta, disks[j].u, disks[j].cosTheta) {
				if countIn(p) >= req {
					pts = append(pts, p)
				}
			}
		}
	}
	for i := 0; i < k; i++ {
		far := furthestOnCircle(disks[i].u, disks[i].theta, targetU)
		if countIn(far) >= req {
			pts = append(pts, far)
		}
	}
	anti := targetU.scale(-1)
	if countIn(anti) >= req {
		pts = append(pts, anti)
	}
	if len(pts) == 0 {
		return CoreResult{ProvenMaxRadiusKm: math.Inf(1), ProvenMaxRadiusMiles: math.Inf(1), WitnessCentroid: target}
	}

	worst := 0.0
	var sum vec3
	for _, p := range pts {
		if d := geodesicKm(targetU, p); d > worst {
			worst = d
		}
		sum = sum.add(p)
	}
	cent, ok := sum.normalize()
	if !ok {
		cent = pts[0]
	}
	return CoreResult{
		ProvenMaxRadiusKm:     worst,
		ProvenMaxRadiusMiles:  worst * 0.621371,
		ContainedWithinTarget: worst <= reqKm,
		WitnessCentroid:       cent.toLatLon(),
	}
}

func ReceiptSigningDigest(r AnchorReceipt) [32]byte {
	h := sha256.New()
	h.Write([]byte("pog-anchor-receipt-v1"))
	h.Write([]byte(r.AnchorID))
	h.Write([]byte("|"))
	h.Write([]byte(r.CloudProvider))
	h.Write([]byte("|"))
	h.Write([]byte(r.ProverPKHex))
	h.Write([]byte("|"))
	h.Write([]byte(r.WorkloadMeasurementHex))
	h.Write([]byte("|"))
	h.Write([]byte(r.EpochChallengeHex))
	h.Write([]byte("|"))
	h.Write([]byte(r.ProverObservedIP))
	h.Write([]byte("|"))
	var b8 [8]byte
	var b4 [4]byte
	binary.LittleEndian.PutUint64(b8[:], r.RttMinUs)
	h.Write(b8[:])
	binary.LittleEndian.PutUint64(b8[:], r.RttP50Us)
	h.Write(b8[:])
	binary.LittleEndian.PutUint32(b4[:], uint32(len(r.RttSamplesUs)))
	h.Write(b4[:])
	for _, s := range r.RttSamplesUs {
		binary.LittleEndian.PutUint64(b8[:], s)
		h.Write(b8[:])
	}
	binary.LittleEndian.PutUint64(b8[:], r.MeasuredAtUnixS)
	h.Write(b8[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func DecodeProofHeader(headerValue string) (GeoProofBundle, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(headerValue))
	if err != nil {
		return GeoProofBundle{}, err
	}
	var b GeoProofBundle
	err = json.Unmarshal(raw, &b)
	return b, err
}

func VerifyProof(bundle GeoProofBundle, grid AnchorGrid, policy VerificationPolicy, nowUnixS uint64) VerificationReport {
	if policy.MinAnchors == 0 {
		policy.MinAnchors = 4
	}
	if policy.MinCloudProviders == 0 {
		policy.MinCloudProviders = 2
	}
	if policy.MaxProofAgeSeconds == 0 {
		policy.MaxProofAgeSeconds = 3900
	}
	if policy.EnforceTier == "" {
		policy.EnforceTier = "vacuum"
	}

	var failures []string
	if nowUnixS > bundle.CreatedAtUnixS+policy.MaxProofAgeSeconds {
		failures = append(failures, "proof expired")
	}

	q := bundle.ProverQuote
	if q.Vendor == "SoftwareDev" && !policy.AllowSoftwareDev {
		failures = append(failures, "SoftwareDev TEE quotes forbidden in production policy")
	}
	if !q.MigrationDisabled {
		failures = append(failures, "TEE migration not disabled")
	}
	if !q.DebugDisabled {
		failures = append(failures, "TEE debug mode enabled")
	}

	// Verify hardware SHA-512 report_data binding.
	pkBytes, _ := hex.DecodeString(q.PublicKeyHex)
	epochBytes, _ := hex.DecodeString(bundle.EpochChallengeHex)
	rd := sha512.New()
	rd.Write([]byte("pog-tee-bind-v1"))
	rd.Write(pkBytes)
	rd.Write(epochBytes)
	if q.GpuBinding != nil {
		rd.Write([]byte(q.GpuBinding.GpuUUID))
		rd.Write([]byte(q.GpuBinding.SpdmReportHashHex))
	}
	if hex.EncodeToString(rd.Sum(nil)) != q.ReportDataHex {
		failures = append(failures, "TEE report_data binding mismatch")
	}

	anchors := make(map[string]AnchorDescriptor, len(grid.Anchors))
	for _, a := range grid.Anchors {
		anchors[a.AnchorID] = a
	}

	seenAnchors := make(map[string]bool)
	seenClouds := make(map[string]bool)
	seenIPs := make(map[string]bool)
	var observedIPs []AnchorObservedIP
	var vacDisks, fibDisks, calDisks []disk
	calV := 162000.0
	if bundle.CalibratedVelocityKmPerS != nil {
		calV = *bundle.CalibratedVelocityKmPerS
	}

	for _, r := range bundle.Receipts {
		if seenAnchors[r.AnchorID] {
			failures = append(failures, fmt.Sprintf("duplicate anchor %s", r.AnchorID))
			continue
		}
		seenAnchors[r.AnchorID] = true
		a, ok := anchors[r.AnchorID]
		if !ok {
			failures = append(failures, fmt.Sprintf("unknown anchor %s", r.AnchorID))
			continue
		}
		aPub, err1 := hex.DecodeString(a.PublicKeyHex)
		sig, err2 := hex.DecodeString(r.AnchorSignatureHex)
		digest := ReceiptSigningDigest(r)
		if err1 != nil || err2 != nil || len(aPub) != ed25519.PublicKeySize || !ed25519.Verify(ed25519.PublicKey(aPub), digest[:], sig) {
			failures = append(failures, fmt.Sprintf("invalid Ed25519 signature from %s", r.AnchorID))
			continue
		}
		if r.ProverPKHex != q.PublicKeyHex || r.EpochChallengeHex != bundle.EpochChallengeHex {
			failures = append(failures, fmt.Sprintf("receipt binding mismatch from %s", r.AnchorID))
			continue
		}
		seenClouds[a.CloudProvider] = true
		seenIPs[r.ProverObservedIP] = true
		observedIPs = append(observedIPs, AnchorObservedIP{
			AnchorID:      r.AnchorID,
			CloudProvider: a.CloudProvider,
			ObservedIP:    r.ProverObservedIP,
			RttMinUs:      r.RttMinUs,
		})
		u := a.Location.toUnit()
		mk := func(rKm float64) disk {
			th := math.Min(math.Pi, rKm/EarthRadiusKm)
			return disk{u: u, theta: th, cosTheta: math.Cos(th)}
		}
		rttS := float64(r.RttMinUs) * 1e-6
		calUs := uint64(0)
		if r.RttMinUs > 600 {
			calUs = r.RttMinUs - 600
		}
		vacDisks = append(vacDisks, mk(0.5*CVacuumKmPerS*rttS))
		fibDisks = append(fibDisks, mk(0.5*CFiberKmPerS*rttS))
		calDisks = append(calDisks, mk(0.5*calV*float64(calUs)*1e-6))
	}

	if len(vacDisks) < policy.MinAnchors {
		failures = append(failures, fmt.Sprintf("insufficient anchors: %d < %d", len(vacDisks), policy.MinAnchors))
	}
	if len(seenClouds) < policy.MinCloudProviders {
		failures = append(failures, fmt.Sprintf("insufficient clouds: %d < %d", len(seenClouds), policy.MinCloudProviders))
	}

	t1a := solveByzantineCore(vacDisks, policy.MaxByzantine, bundle.TargetLocation, bundle.RequiredRadiusKm)
	t1b := solveByzantineCore(fibDisks, policy.MaxByzantine, bundle.TargetLocation, bundle.RequiredRadiusKm)
	t2 := solveByzantineCore(calDisks, policy.MaxByzantine, bundle.TargetLocation, bundle.RequiredRadiusKm)

	enforced := t1a
	if policy.EnforceTier == "fiber" {
		enforced = t1b
	} else if policy.EnforceTier == "calibrated" {
		enforced = t2
	}
	if !enforced.ContainedWithinTarget {
		failures = append(failures, fmt.Sprintf("enforced tier (%s) failed: %.1f km > %.1f km", policy.EnforceTier, enforced.ProvenMaxRadiusKm, bundle.RequiredRadiusKm))
	}

	distinctIPs := make([]string, 0, len(seenIPs))
	for ip := range seenIPs {
		distinctIPs = append(distinctIPs, ip)
	}
	sort.Strings(distinctIPs)

	return VerificationReport{
		OverallValid:           len(failures) == 0,
		FailureReasons:         failures,
		DistinctClouds:         len(seenClouds),
		VerifiedReceipts:       len(vacDisks),
		ProverPublicKeyHex:     q.PublicKeyHex,
		WorkloadMeasurementHex: q.WorkloadMeasurementHex,
		HasGpuBinding:          q.GpuBinding != nil,
		ObservedProverIPs:      observedIPs,
		DistinctObservedIPs:    distinctIPs,
		IPViewConsistent:       len(distinctIPs) <= 1,
		Tier1AVacuum:           t1a,
		Tier1BFiber:            t1b,
		Tier2Calibrated:        t2,
	}
}

// SignedRegistryDigest matches `pog_proto::SignedNetworkRegistry::signing_digest()` byte-for-byte.
func SignedRegistryDigest(reg SignedNetworkRegistry) [32]byte {
	h := sha256.New()
	h.Write([]byte("POG-NETWORK-REGISTRY-V1\n"))
	h.Write([]byte(reg.NetworkID + "\n"))
	h.Write([]byte(reg.OperatorName + "\n"))
	h.Write([]byte(reg.RootPublicKeyHex + "\n"))
	h.Write([]byte(fmt.Sprintf("%d\n", reg.IssuedAtUnixS)))
	h.Write([]byte(fmt.Sprintf("%d\n", reg.ExpiresAtUnixS)))
	h.Write([]byte(reg.Grid.GridName + "\n"))

	sorted := append([]AnchorDescriptor(nil), reg.Grid.Anchors...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].AnchorID < sorted[j].AnchorID })
	for _, a := range sorted {
		line := fmt.Sprintf("%s|%s|%s|%.6f|%.6f|%s|%s\n",
			a.AnchorID, a.CloudProvider, a.Region, a.Location.Lat, a.Location.Lon, a.EndpointTCP, a.PublicKeyHex)
		h.Write([]byte(line))
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func VerifySignedRegistry(reg SignedNetworkRegistry, pinnedRootPKHex string, nowUnixS uint64) error {
	if pinnedRootPKHex != "" && !strings.EqualFold(reg.RootPublicKeyHex, pinnedRootPKHex) {
		return fmt.Errorf("root public key mismatch for network %s", reg.NetworkID)
	}
	if nowUnixS > reg.ExpiresAtUnixS {
		return fmt.Errorf("signed registry expired for network %s", reg.NetworkID)
	}
	pub, err := hex.DecodeString(reg.RootPublicKeyHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid root public key for network %s", reg.NetworkID)
	}
	sig, err := hex.DecodeString(reg.OperatorSignatureHex)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("invalid operator signature for network %s", reg.NetworkID)
	}
	digest := SignedRegistryDigest(reg)
	if !ed25519.Verify(ed25519.PublicKey(pub), digest[:], sig) {
		return fmt.Errorf("invalid operator Ed25519 signature on network %s", reg.NetworkID)
	}
	return nil
}

func FetchSignedRegistry(url string, pinnedRootPKHex string, nowUnixS uint64, client *http.Client) (SignedNetworkRegistry, error) {
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Get(url)
	if err != nil {
		return SignedNetworkRegistry{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return SignedNetworkRegistry{}, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}
	var reg SignedNetworkRegistry
	if err := json.NewDecoder(resp.Body).Decode(&reg); err != nil {
		return SignedNetworkRegistry{}, err
	}
	if err := VerifySignedRegistry(reg, pinnedRootPKHex, nowUnixS); err != nil {
		return SignedNetworkRegistry{}, err
	}
	return reg, nil
}

// VerifyFederatedProof verifies proofs obtained from `minIndependentNetworks` distinct operator networks.
func VerifyFederatedProof(
	submissions []NetworkProofSubmission,
	trustedNetworks []TrustedNetwork,
	policy VerificationPolicy,
	minIndependentNetworks int,
	nowUnixS uint64,
) FederatedVerificationReport {
	netByID := make(map[string]TrustedNetwork, len(trustedNetworks))
	for _, n := range trustedNetworks {
		netByID[n.NetworkID] = n
	}
	seenNets := make(map[string]bool)
	seenRoots := make(map[string]bool)
	proverPKs := make(map[string]bool)
	allIPs := make(map[string]bool)
	var distinctOps []string
	var failures []string
	var perNet []PerNetworkVerification
	var minVac, minFib, minCal *float64

	for _, sub := range submissions {
		if seenNets[sub.NetworkID] {
			failures = append(failures, fmt.Sprintf("duplicate network submission: %s", sub.NetworkID))
			continue
		}
		seenNets[sub.NetworkID] = true
		net, ok := netByID[sub.NetworkID]
		if !ok {
			perNet = append(perNet, PerNetworkVerification{
				NetworkID:    sub.NetworkID,
				OperatorName: "unknown",
				Error:        "untrusted network_id",
			})
			continue
		}
		rootNorm := strings.ToLower(net.PinnedRootPublicKeyHex)
		if seenRoots[rootNorm] {
			failures = append(failures, fmt.Sprintf("network %s shares root key with another network (not independent)", sub.NetworkID))
			continue
		}
		seenRoots[rootNorm] = true

		if err := VerifySignedRegistry(net.SignedRegistry, net.PinnedRootPublicKeyHex, nowUnixS); err != nil {
			perNet = append(perNet, PerNetworkVerification{
				NetworkID:    sub.NetworkID,
				OperatorName: net.SignedRegistry.OperatorName,
				Error:        err.Error(),
			})
			continue
		}

		rep := VerifyProof(sub.Bundle, net.SignedRegistry.Grid, policy, nowUnixS)
		if rep.OverallValid {
			distinctOps = append(distinctOps, net.SignedRegistry.OperatorName)
			proverPKs[rep.ProverPublicKeyHex] = true
			for _, ip := range rep.DistinctObservedIPs {
				allIPs[ip] = true
			}
			v, f, c := rep.Tier1AVacuum.ProvenMaxRadiusKm, rep.Tier1BFiber.ProvenMaxRadiusKm, rep.Tier2Calibrated.ProvenMaxRadiusKm
			if minVac == nil || v < *minVac {
				vv := v
				minVac = &vv
			}
			if minFib == nil || f < *minFib {
				ff := f
				minFib = &ff
			}
			if minCal == nil || c < *minCal {
				cc := c
				minCal = &cc
			}
		}
		repCopy := rep
		perNet = append(perNet, PerNetworkVerification{
			NetworkID:              sub.NetworkID,
			OperatorName:           net.SignedRegistry.OperatorName,
			RegistrySignatureValid: true,
			ProofValid:             rep.OverallValid,
			Report:                 &repCopy,
		})
	}

	pkConsistent := len(proverPKs) <= 1
	ipConsistent := len(allIPs) <= 1
	if len(distinctOps) < minIndependentNetworks {
		failures = append(failures, fmt.Sprintf("insufficient independent networks verified: %d < %d", len(distinctOps), minIndependentNetworks))
	}
	if !pkConsistent {
		failures = append(failures, "prover TEE public key mismatch across independent networks")
	}

	ips := make([]string, 0, len(allIPs))
	for ip := range allIPs {
		ips = append(ips, ip)
	}
	sort.Strings(ips)

	return FederatedVerificationReport{
		OverallValid:                     len(failures) == 0 && len(distinctOps) >= minIndependentNetworks,
		RequiredIndependentNetworks:      minIndependentNetworks,
		ValidIndependentNetworks:         len(distinctOps),
		DistinctOperatorsVerified:        distinctOps,
		ProverPKConsistentAcrossNetworks: pkConsistent,
		ObservedProverIPsAcrossNetworks:  ips,
		IPConsistentAcrossNetworks:       ipConsistent,
		ConsensusTier1AVacuumKm:          minVac,
		ConsensusTier1BFiberKm:           minFib,
		ConsensusTier2CalibratedKm:       minCal,
		FailureReasons:                   failures,
		PerNetwork:                       perNet,
	}
}

func QueryFederatedNetworks(
	sources []NetworkSource,
	submissions []NetworkProofSubmission,
	policy VerificationPolicy,
	minIndependentNetworks int,
	nowUnixS uint64,
	client *http.Client,
) FederatedVerificationReport {
	var trusted []TrustedNetwork
	for _, src := range sources {
		if reg, err := FetchSignedRegistry(src.RegistryURL, src.PinnedRootPublicKeyHex, nowUnixS, client); err == nil {
			trusted = append(trusted, TrustedNetwork{
				NetworkID:              src.NetworkID,
				PinnedRootPublicKeyHex: src.PinnedRootPublicKeyHex,
				SignedRegistry:         reg,
			})
		}
	}
	return VerifyFederatedProof(submissions, trusted, policy, minIndependentNetworks, nowUnixS)
}
