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
	EarthRadiusKm              = 6371.0088
	WGS84MinCurvatureRadiusKm  = 6335.439327
	HalfCircumferenceKm        = math.Pi * EarthRadiusKm
	CVacuumKmPerS              = 299792.458
	CFiberKmPerS               = 204000.0
	HTTPHeaderPoGProof         = "X-PoG-Proof"
)

type LatLon struct {
	Lat float64 `json:"lat"`
	Lon float64 `json:"lon"`
}

type CoordinateBasis struct {
	Source                            string  `json:"source"`
	UncertaintyKm                     float64 `json:"uncertainty_km"`
	AuditedAtUnixS                    *uint64 `json:"audited_at_unix_s,omitempty"`
	HardwareIdentityProvesCoordinates bool    `json:"hardware_identity_proves_coordinates"`
	AuditNote                         string  `json:"audit_note,omitempty"`
}

type AnchorDescriptor struct {
	AnchorID        string           `json:"anchor_id"`
	CloudProvider   string           `json:"cloud_provider"`
	Region          string           `json:"region"`
	City            string           `json:"city"`
	TeeVendor       string           `json:"tee_vendor,omitempty"`
	Location        LatLon           `json:"location"`
	EndpointTCP     string           `json:"endpoint_tcp"`
	PublicKeyHex    string           `json:"public_key_hex"`
	CoordinateBasis *CoordinateBasis `json:"coordinate_basis,omitempty"`
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

type UnverifiedReceipt struct {
	AnchorID string
	Reason   string
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
	Version                  uint8               `json:"version"`
	EpochChallengeHex        string              `json:"epoch_challenge_hex"`
	ClientNonceHex           *string             `json:"client_nonce_hex"`
	TargetLocation           LatLon              `json:"target_location"`
	RequiredRadiusKm         float64             `json:"required_radius_km"`
	ProverQuote              TeeAttestationQuote `json:"prover_quote"`
	Receipts                 []AnchorReceipt     `json:"receipts"`
	CalibratedVelocityKmPerS *float64            `json:"calibrated_velocity_km_per_s"`
	PrevChainHashHex         *string             `json:"prev_chain_hash_hex"`
	ChainSeq                 uint64              `json:"chain_seq"`
	CreatedAtUnixS           uint64              `json:"created_at_unix_s"`
}

type VerificationPolicy struct {
	AllowSoftwareDev            bool
	MaxByzantine                int
	MinAnchors                  int
	MinCloudProviders           int
	MaxProofAgeSeconds          uint64
	MaxFutureSkewSeconds        uint64
	EnforceTier                 string // "vacuum" | "fiber" | "calibrated"
	ClockResolutionUs           uint64
	ClockSlewPpm                uint32
	AnchorLocationUncertaintyKm float64
	DisableChordCorrection      bool
}

type CoreResult struct {
	ProvenMaxRadiusKm     float64
	ProvenMaxRadiusMiles  float64
	ContainedWithinTarget bool
	WitnessCentroid       LatLon
	WholeEarth            bool
	Feasible              bool
}

type VerificationReport struct {
	OverallValid           bool
	ProofStatus            string
	HardwareAttested       bool
	FailureReasons         []string
	UnverifiedReceipts     []UnverifiedReceipt
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

func EffectiveOuterRadiusKm(rttUs uint64, tier string, policy VerificationPolicy, anchorUncOverrideKm float64, calV float64) float64 {
	clockRes := policy.ClockResolutionUs
	if clockRes == 0 {
		clockRes = 50
	}
	slew := policy.ClockSlewPpm
	if slew == 0 {
		slew = 500
	}
	uncKm := policy.AnchorLocationUncertaintyKm
	if uncKm <= 0 {
		uncKm = 35.0
	}
	if anchorUncOverrideKm > uncKm {
		uncKm = anchorUncOverrideKm
	}
	if tier == "vacuum" {
		tUpperS := float64(rttUs+clockRes) * (1.0 + float64(slew)*1e-6) * 1e-6
		oneWayKm := 0.5 * CVacuumKmPerS * tUpperS
		refR := WGS84MinCurvatureRadiusKm
		var propAng float64
		if !policy.DisableChordCorrection {
			sinHalf := oneWayKm / (2.0 * refR)
			if sinHalf >= 1.0 {
				propAng = math.Pi
			} else {
				propAng = 2.0 * math.Asin(sinHalf)
			}
		} else {
			propAng = math.Min(math.Pi, oneWayKm/refR)
		}
		return math.Min(math.Pi, propAng+uncKm/refR) * EarthRadiusKm
	}
	if tier == "fiber" {
		tUpperS := float64(rttUs+clockRes) * (1.0 + float64(slew)*1e-6) * 1e-6
		oneWayKm := 0.5 * CFiberKmPerS * tUpperS
		return math.Min(math.Pi, (oneWayKm+uncKm)/WGS84MinCurvatureRadiusKm) * EarthRadiusKm
	}
	adjUs := uint64(0)
	if rttUs > 350 {
		adjUs = rttUs - 350
	}
	v := math.Max(50000.0, math.Min(CVacuumKmPerS, calV))
	return math.Min(HalfCircumferenceKm, 0.5*v*float64(adjUs)*1e-6)
}

func intersectTwoCircles(u1 vec3, c1 float64, u2 vec3, c2 float64) []vec3 {
	n := u1.cross(u2)
	nSq := n.dot(n)
	if nSq < 1e-24 {
		return nil
	}
	d := u1.dot(u2)
	a := (c1 - c2*d) / nSq
	b := (c2 - c1*d) / nSq
	p := u1.scale(a).add(u2.scale(b))
	pSq := p.dot(p)
	if pSq > 1.0+1e-11 {
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

func furthestPointsOnCircle(u vec3, theta float64, target vec3) []vec3 {
	if theta >= math.Pi-1e-12 {
		return []vec3{target.scale(-1)}
	}
	if theta <= 1e-12 {
		return []vec3{u}
	}
	negT := target.scale(-1)
	proj := negT.sub(u.scale(negT.dot(u)))
	if dir, ok := proj.normalize(); ok {
		res, _ := u.scale(math.Cos(theta)).add(dir.scale(math.Sin(theta))).normalize()
		return []vec3{res}
	}
	basis := vec3{1, 0, 0}
	if math.Abs(u.x) >= 0.9 {
		basis = vec3{0, 1, 0}
	}
	e1, _ := u.cross(basis).normalize()
	e2, _ := u.cross(e1).normalize()
	dirs := []vec3{e1, e1.scale(-1), e2, e2.scale(-1)}
	out := make([]vec3, 0, 4)
	for _, dv := range dirs {
		res, _ := u.scale(math.Cos(theta)).add(dv.scale(math.Sin(theta))).normalize()
		out = append(out, res)
	}
	return out
}

func isWholeEarthCore(disks []disk, f int) bool {
	exclReq := f + 1
	const strictEps = 1e-11
	type compCap struct {
		cu     vec3
		cosCth float64
	}
	var comp []compCap
	for _, d := range disks {
		if d.theta < math.Pi-1e-12 {
			cth := math.Pi - d.theta
			comp = append(comp, compCap{cu: d.u.scale(-1), cosCth: math.Cos(cth)})
		}
	}
	if len(comp) < exclReq {
		return true
	}
	countExcl := func(x vec3) int {
		c := 0
		for _, cc := range comp {
			if cc.cu.dot(x) > cc.cosCth+strictEps {
				c++
			}
		}
		return c
	}
	for _, cc := range comp {
		if countExcl(cc.cu) >= exclReq {
			return false
		}
	}
	for i := 0; i < len(comp); i++ {
		for j := i + 1; j < len(comp); j++ {
			if mid, ok := comp[i].cu.add(comp[j].cu).normalize(); ok && countExcl(mid) >= exclReq {
				return false
			}
			for _, pt := range intersectTwoCircles(comp[i].cu, comp[i].cosCth, comp[j].cu, comp[j].cosCth) {
				if inward, ok := comp[i].cu.add(comp[j].cu).normalize(); ok {
					if nudged, ok2 := pt.add(inward.scale(1e-7)).normalize(); ok2 && countExcl(nudged) >= exclReq {
						return false
					}
				}
			}
		}
	}
	return true
}

func solveByzantineCore(disks []disk, maxByzantine int, target LatLon, reqKm float64) CoreResult {
	k := len(disks)
	if k == 0 {
		return CoreResult{ProvenMaxRadiusKm: math.Inf(1), ProvenMaxRadiusMiles: math.Inf(1), WitnessCentroid: target, Feasible: false}
	}
	f := maxByzantine
	if f >= k {
		f = k - 1
	}
	req := k - f
	const eps = 1e-9
	targetU := target.toUnit()
	wholeEarth := isWholeEarthCore(disks, f)
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
		for _, far := range furthestPointsOnCircle(disks[i].u, disks[i].theta, targetU) {
			if countIn(far) >= req {
				pts = append(pts, far)
			}
		}
	}
	anti := targetU.scale(-1)
	if countIn(anti) >= req {
		pts = append(pts, anti)
	}

	interiorCands := make([]vec3, 0, k+2)
	interiorCands = append(interiorCands, targetU)
	for _, d := range disks {
		interiorCands = append(interiorCands, d.u)
	}
	if len(pts) > 0 {
		var s vec3
		for _, p := range pts {
			s = s.add(p)
		}
		if avg, ok := s.normalize(); ok {
			interiorCands = append(interiorCands, avg)
		}
	}
	var witnessU vec3
	hasWitness := false
	for _, c := range interiorCands {
		if countIn(c) >= req {
			witnessU = c
			hasWitness = true
			break
		}
	}
	if !hasWitness && len(pts) > 0 {
		witnessU = pts[0]
		hasWitness = true
	}
	if !hasWitness {
		return CoreResult{ProvenMaxRadiusKm: math.Inf(1), ProvenMaxRadiusMiles: math.Inf(1), WitnessCentroid: target, Feasible: false}
	}
	if len(pts) == 0 {
		if wholeEarth || countIn(anti) >= req {
			pts = append(pts, anti)
		} else {
			pts = append(pts, witnessU)
		}
	}

	worst := 0.0
	if wholeEarth {
		worst = HalfCircumferenceKm
	}
	var sum vec3
	for _, p := range pts {
		if d := geodesicKm(targetU, p); d > worst {
			worst = d
		}
		sum = sum.add(p)
	}
	cent, ok := sum.normalize()
	if !ok || countIn(cent) < req {
		cent = witnessU
	}
	return CoreResult{
		ProvenMaxRadiusKm:     worst,
		ProvenMaxRadiusMiles:  worst * 0.621371,
		ContainedWithinTarget: worst <= reqKm,
		WitnessCentroid:       cent.toLatLon(),
		WholeEarth:            wholeEarth,
		Feasible:              true,
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
	if policy.MaxFutureSkewSeconds == 0 {
		policy.MaxFutureSkewSeconds = 300
	}
	if policy.EnforceTier == "" {
		policy.EnforceTier = "vacuum"
	}

	var failures []string
	var unverified []UnverifiedReceipt
	if nowUnixS > bundle.CreatedAtUnixS+policy.MaxProofAgeSeconds {
		failures = append(failures, "proof expired")
	}
	if bundle.CreatedAtUnixS > nowUnixS+policy.MaxFutureSkewSeconds {
		failures = append(failures, "proof timestamp in future")
	}

	q := bundle.ProverQuote
	proverIsHw := q.Vendor != "SoftwareDev"
	if !proverIsHw && !policy.AllowSoftwareDev {
		failures = append(failures, "SoftwareDev TEE quotes forbidden in production policy")
	}
	if !q.MigrationDisabled {
		failures = append(failures, "TEE migration not disabled")
	}
	if !q.DebugDisabled {
		failures = append(failures, "TEE debug mode enabled")
	}

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
	calV := 152000.0
	if bundle.CalibratedVelocityKmPerS != nil {
		calV = *bundle.CalibratedVelocityKmPerS
	}
	allAnchorsHw := true

	for _, r := range bundle.Receipts {
		if seenAnchors[r.AnchorID] {
			msg := fmt.Sprintf("duplicate anchor %s", r.AnchorID)
			unverified = append(unverified, UnverifiedReceipt{AnchorID: r.AnchorID, Reason: msg})
			failures = append(failures, msg)
			continue
		}
		seenAnchors[r.AnchorID] = true
		a, ok := anchors[r.AnchorID]
		if !ok {
			msg := fmt.Sprintf("unknown anchor %s", r.AnchorID)
			unverified = append(unverified, UnverifiedReceipt{AnchorID: r.AnchorID, Reason: msg})
			failures = append(failures, msg)
			continue
		}
		if a.TeeVendor == "SoftwareDev" {
			allAnchorsHw = false
			if !policy.AllowSoftwareDev {
				msg := fmt.Sprintf("anchor %s reports SoftwareDev (hardware TEE required)", r.AnchorID)
				unverified = append(unverified, UnverifiedReceipt{AnchorID: r.AnchorID, Reason: msg})
				failures = append(failures, msg)
				continue
			}
		}
		aPub, err1 := hex.DecodeString(a.PublicKeyHex)
		sig, err2 := hex.DecodeString(r.AnchorSignatureHex)
		digest := ReceiptSigningDigest(r)
		if err1 != nil || err2 != nil || len(aPub) != ed25519.PublicKeySize || !ed25519.Verify(ed25519.PublicKey(aPub), digest[:], sig) {
			msg := fmt.Sprintf("invalid Ed25519 signature or published key mismatch from %s", r.AnchorID)
			unverified = append(unverified, UnverifiedReceipt{AnchorID: r.AnchorID, Reason: msg})
			failures = append(failures, msg)
			continue
		}
		if r.ProverPKHex != q.PublicKeyHex || r.EpochChallengeHex != bundle.EpochChallengeHex {
			msg := fmt.Sprintf("receipt binding mismatch from %s", r.AnchorID)
			unverified = append(unverified, UnverifiedReceipt{AnchorID: r.AnchorID, Reason: msg})
			failures = append(failures, msg)
			continue
		}
		if r.WorkloadMeasurementHex != q.WorkloadMeasurementHex {
			msg := fmt.Sprintf("receipt workload_measurement_hex mismatch from %s", r.AnchorID)
			unverified = append(unverified, UnverifiedReceipt{AnchorID: r.AnchorID, Reason: msg})
			failures = append(failures, msg)
			continue
		}
		if nowUnixS > r.MeasuredAtUnixS+policy.MaxProofAgeSeconds || r.MeasuredAtUnixS > nowUnixS+policy.MaxFutureSkewSeconds {
			msg := fmt.Sprintf("receipt expired or future-dated from %s", r.AnchorID)
			unverified = append(unverified, UnverifiedReceipt{AnchorID: r.AnchorID, Reason: msg})
			failures = append(failures, msg)
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
		ancUnc := 0.0
		if a.CoordinateBasis != nil {
			ancUnc = a.CoordinateBasis.UncertaintyKm
		}
		mk := func(rKm float64) disk {
			th := math.Min(math.Pi, math.Max(0, rKm/EarthRadiusKm))
			return disk{u: u, theta: th, cosTheta: math.Cos(th)}
		}
		vacDisks = append(vacDisks, mk(EffectiveOuterRadiusKm(r.RttMinUs, "vacuum", policy, ancUnc, calV)))
		fibDisks = append(fibDisks, mk(EffectiveOuterRadiusKm(r.RttMinUs, "fiber", policy, ancUnc, calV)))
		calDisks = append(calDisks, mk(EffectiveOuterRadiusKm(r.RttMinUs, "calibrated", policy, ancUnc, calV)))
	}

	if len(vacDisks) < policy.MinAnchors {
		failures = append(failures, fmt.Sprintf("insufficient verified anchors: %d < %d", len(vacDisks), policy.MinAnchors))
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
	if len(vacDisks) > 0 && !enforced.ContainedWithinTarget {
		failures = append(failures, fmt.Sprintf("enforced tier (%s) failed: %.1f km > %.1f km", policy.EnforceTier, enforced.ProvenMaxRadiusKm, bundle.RequiredRadiusKm))
	}

	proofStatus := "verified"
	if len(vacDisks) < policy.MinAnchors || len(seenClouds) < policy.MinCloudProviders {
		proofStatus = "insufficient_verified_anchors"
	} else if !t1a.Feasible {
		proofStatus = "inconsistent_measurements"
	} else if t1a.WholeEarth && !enforced.ContainedWithinTarget {
		proofStatus = "no_verified_constraint"
	} else if !enforced.ContainedWithinTarget {
		proofStatus = "containment_failed"
	} else if len(failures) > 0 {
		proofStatus = "policy_rejected"
	}

	distinctIPs := make([]string, 0, len(seenIPs))
	for ip := range seenIPs {
		distinctIPs = append(distinctIPs, ip)
	}
	sort.Strings(distinctIPs)

	return VerificationReport{
		OverallValid:           len(failures) == 0,
		ProofStatus:            proofStatus,
		HardwareAttested:       proverIsHw && allAnchorsHw && len(vacDisks) > 0,
		FailureReasons:         failures,
		UnverifiedReceipts:     unverified,
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

func ValidateProductionRegistry(reg SignedNetworkRegistry) error {
	var dev []string
	for _, a := range reg.Grid.Anchors {
		if a.TeeVendor == "SoftwareDev" {
			dev = append(dev, a.AnchorID)
		}
	}
	if len(dev) > 0 {
		return fmt.Errorf("production registry contains SoftwareDev anchors: %s", strings.Join(dev, ", "))
	}
	return nil
}

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
			if rep.Tier2Calibrated.Feasible && (minCal == nil || c < *minCal) {
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

type LikelihoodObservation struct {
	AnchorID            string  `json:"anchor_id"`
	Lat                 float64 `json:"lat"`
	Lon                 float64 `json:"lon"`
	RttMs               float64 `json:"rtt_ms"`
	RttMinMs            float64 `json:"rtt_min_ms"`
	JitterMs            float64 `json:"jitter_ms"`
	AnchorUncertaintyKm float64 `json:"anchor_uncertainty_km"`
}

type SpatialLikelihoodConfig struct {
	T0Ms             float64
	V0KmMs           float64
	V1KmMs           float64
	DKneeKm          float64
	SigmaBaseMs      float64
	SigmaRel         float64
	SigmaJit         float64
	Rho              float64
	LCorrKm          float64
	AsymSlow         float64
	StudentTNu       float64 // <= 0 means Gaussian
	TauMoreLikely    float64
	TauPlausible     float64
	GridPoints       int
	PeakSeparationKm float64
	VacuumByzantineF int
}

func DefaultSpatialLikelihoodConfig() SpatialLikelihoodConfig {
	return SpatialLikelihoodConfig{
		T0Ms:             2.0,
		V0KmMs:           80.0,
		V1KmMs:           143.0,
		DKneeKm:          3500.0,
		SigmaBaseMs:      1.837,
		SigmaRel:         0.1267,
		SigmaJit:         1.5,
		Rho:              0.85,
		LCorrKm:          2200.0,
		AsymSlow:         1.65,
		StudentTNu:       4.0,
		TauMoreLikely:    1.752,
		TauPlausible:     3.911,
		GridPoints:       2000,
		PeakSeparationKm: 700.0,
		VacuumByzantineF: 0,
	}
}

type LikelihoodPeak struct {
	Lat                float64 `json:"lat"`
	Lon                float64 `json:"lon"`
	DeltaNll           float64 `json:"delta_nll"`
	RelativeLikelihood float64 `json:"relative_likelihood"`
	QualitativeBand    string  `json:"qualitative_band"`
}

type SpatialLikelihoodSurface struct {
	IsEmpiricalEstimate         bool             `json:"is_empirical_estimate"`
	IsHardProof                 bool             `json:"is_hard_proof"`
	QualitativeScale            string           `json:"qualitative_scale"`
	EffectiveIndependentAnchors float64          `json:"effective_independent_anchors"`
	AnchorCount                 int              `json:"anchor_count"`
	Peaks                       []LikelihoodPeak `json:"peaks"`
	MoreLikelyAreaKm2           float64          `json:"more_likely_area_km2"`
	MoreLikelyAreaFraction      float64          `json:"more_likely_area_fraction"`
	PlausibleAreaKm2            float64          `json:"plausible_area_km2"`
	PlausibleAreaFraction       float64          `json:"plausible_area_fraction"`
	VacuumOuterAreaKm2          float64          `json:"vacuum_outer_area_km2"`
	VacuumOuterAreaFraction     float64          `json:"vacuum_outer_area_fraction"`
}

func choleskyLower(mat [][]float64) [][]float64 {
	n := len(mat)
	L := make([][]float64, n)
	for i := range L {
		L[i] = make([]float64, n)
	}
	for i := 0; i < n; i++ {
		for j := 0; j <= i; j++ {
			s := 0.0
			for k := 0; k < j; k++ {
				s += L[i][k] * L[j][k]
			}
			if i == j {
				v := mat[i][i] - s
				if v < 1e-12 {
					v = 1e-12
				}
				L[i][j] = math.Sqrt(v)
			} else {
				L[i][j] = (mat[i][j] - s) / L[j][j]
			}
		}
	}
	return L
}

func solveLower(L [][]float64, b []float64) []float64 {
	n := len(b)
	y := make([]float64, n)
	for i := 0; i < n; i++ {
		s := b[i]
		for k := 0; k < i; k++ {
			s -= L[i][k] * y[k]
		}
		y[i] = s / L[i][i]
	}
	return y
}

func ComputeSpatialLikelihood(observations []LikelihoodObservation, cfg SpatialLikelihoodConfig, policy VerificationPolicy) SpatialLikelihoodSurface {
	earthKm2 := 4.0 * math.Pi * EarthRadiusKm * EarthRadiusKm
	if cfg.GridPoints <= 0 {
		cfg = DefaultSpatialLikelihoodConfig()
	}
	if len(observations) == 0 {
		return SpatialLikelihoodSurface{
			IsEmpiricalEstimate:     true,
			IsHardProof:             false,
			QualitativeScale:        "more_likely_to_less_likely",
			MoreLikelyAreaKm2:       earthKm2,
			MoreLikelyAreaFraction:  1.0,
			PlausibleAreaKm2:        earthKm2,
			PlausibleAreaFraction:   1.0,
			VacuumOuterAreaKm2:      earthKm2,
			VacuumOuterAreaFraction: 1.0,
		}
	}
	k := len(observations)
	units := make([]vec3, k)
	vacCos := make([]float64, k)
	sigmas := make([]float64, k)
	for i, o := range observations {
		units[i] = (LatLon{Lat: o.Lat, Lon: o.Lon}).toUnit()
		rMin := o.RttMinMs
		if rMin <= 0 {
			rMin = o.RttMs
		}
		uncKm := o.AnchorUncertaintyKm
		if uncKm <= 0 {
			uncKm = 35.0
		}
		rKm := EffectiveOuterRadiusKm(uint64(math.Ceil(math.Max(0, rMin)*1000.0)), "vacuum", policy, uncKm, 152000.0)
		vacCos[i] = math.Cos(math.Min(math.Pi, rKm/EarthRadiusKm))
		s := math.Sqrt(cfg.SigmaBaseMs*cfg.SigmaBaseMs + math.Pow(cfg.SigmaRel*math.Max(0, o.RttMs), 2) + math.Pow(cfg.SigmaJit*math.Max(0, o.JitterMs), 2))
		if s < 0.25 {
			s = 0.25
		}
		sigmas[i] = s
	}
	reqVac := k - cfg.VacuumByzantineF
	if reqVac < 1 {
		reqVac = 1
	}
	rho := math.Max(0, math.Min(0.99, cfg.Rho))
	lCorr := math.Max(1.0, cfg.LCorrKm)

	Sigma := make([][]float64, k)
	Corr := make([][]float64, k)
	for i := 0; i < k; i++ {
		Sigma[i] = make([]float64, k)
		Corr[i] = make([]float64, k)
	}
	for i := 0; i < k; i++ {
		for j := i; j < k; j++ {
			c := 1.0
			if i != j {
				c = rho * math.Exp(-geodesicKm(units[i], units[j])/lCorr)
			}
			Corr[i][j], Corr[j][i] = c, c
			v := sigmas[i] * sigmas[j] * c
			Sigma[i][j], Sigma[j][i] = v, v
		}
	}
	LSig := choleskyLower(Sigma)
	LCor := choleskyLower(Corr)
	ones := make([]float64, k)
	for i := range ones {
		ones[i] = 1.0
	}
	onesW := solveLower(LCor, ones)
	kEff := 0.0
	for _, x := range onesW {
		kEff += x * x
	}

	evalNll := func(pt vec3) float64 {
		r := make([]float64, k)
		for i, o := range observations {
			dKm := geodesicKm(pt, units[i])
			v := cfg.V0KmMs + (cfg.V1KmMs-cfg.V0KmMs)*(1.0-math.Exp(-dKm/cfg.DKneeKm))
			if v < 1.0 {
				v = 1.0
			}
			pred := cfg.T0Ms + (2.0*dKm)/v
			diff := o.RttMs - pred
			if diff > 0 && cfg.AsymSlow > 1.0 {
				diff /= cfg.AsymSlow
			}
			r[i] = diff
		}
		z := solveLower(LSig, r)
		quad := 0.0
		for _, x := range z {
			quad += x * x
		}
		if cfg.StudentTNu > 0 {
			nu := math.Max(0.5, cfg.StudentTNu)
			return 0.5 * (nu + kEff) * math.Log(1.0+quad/nu)
		}
		return 0.5 * quad
	}

	nPts := cfg.GridPoints
	if nPts < 64 {
		nPts = 64
	}
	ga := math.Pi * (3.0 - math.Sqrt(5.0))
	type gridSample struct {
		pt  vec3
		nll float64
	}
	feasible := make([]gridSample, 0, nPts/4)
	bestNll := math.Inf(1)
	bestU := units[0]
	for i := 0; i < nPts; i++ {
		y := 1.0 - (2.0*float64(i)+1.0)/float64(nPts)
		rr := math.Sqrt(math.Max(0, 1.0-y*y))
		phi := ga * float64(i)
		pt := vec3{math.Cos(phi) * rr, math.Sin(phi) * rr, y}
		inCnt := 0
		for j := 0; j < k; j++ {
			if pt.dot(units[j]) >= vacCos[j]-1e-12 {
				inCnt++
			}
		}
		if inCnt < reqVac {
			continue
		}
		nll := evalNll(pt)
		if nll < bestNll {
			bestNll = nll
			bestU = pt
		}
		feasible = append(feasible, gridSample{pt: pt, nll: nll})
	}
	if len(feasible) == 0 {
		return SpatialLikelihoodSurface{
			IsEmpiricalEstimate:         true,
			IsHardProof:                 false,
			QualitativeScale:            "more_likely_to_less_likely",
			EffectiveIndependentAnchors: kEff,
			AnchorCount:                 k,
		}
	}

	bestLL := bestU.toLatLon()
	for _, step := range []float64{1.5, 0.4, 0.1} {
		cLat, cLon := bestLL.Lat, bestLL.Lon
		for dl := -2; dl <= 2; dl++ {
			for dn := -2; dn <= 2; dn++ {
				lat := math.Max(-89.5, math.Min(89.5, cLat+float64(dl)*step))
				lon := math.Mod(math.Mod(cLon+float64(dn)*step+180.0, 360.0)+360.0, 360.0) - 180.0
				cu := (LatLon{Lat: lat, Lon: lon}).toUnit()
				inCnt := 0
				for j := 0; j < k; j++ {
					if cu.dot(units[j]) >= vacCos[j]-1e-12 {
						inCnt++
					}
				}
				if inCnt < reqVac {
					continue
				}
				cn := evalNll(cu)
				if cn < bestNll {
					bestNll = cn
					bestLL = LatLon{Lat: lat, Lon: lon}
					bestU = cu
				}
			}
		}
	}

	type deltaPt struct {
		delta float64
		pt    vec3
	}
	mlPts := make([]deltaPt, 0)
	plCount := 0
	for _, f := range feasible {
		d := math.Max(0, f.nll-bestNll)
		if d <= cfg.TauPlausible {
			plCount++
		}
		if d <= cfg.TauMoreLikely {
			mlPts = append(mlPts, deltaPt{delta: d, pt: f.pt})
		}
	}
	sort.Slice(mlPts, func(i, j int) bool { return mlPts[i].delta < mlPts[j].delta })

	peakUnits := []deltaPt{{delta: 0, pt: bestU}}
	for _, cand := range mlPts {
		ok := true
		for _, p := range peakUnits {
			if geodesicKm(cand.pt, p.pt) < cfg.PeakSeparationKm {
				ok = false
				break
			}
		}
		if ok {
			peakUnits = append(peakUnits, cand)
			if len(peakUnits) >= 4 {
				break
			}
		}
	}

	peaks := make([]LikelihoodPeak, 0, len(peakUnits))
	for _, p := range peakUnits {
		ll := p.pt.toLatLon()
		band := "more_likely"
		if p.delta > cfg.TauMoreLikely {
			band = "plausible"
		}
		peaks = append(peaks, LikelihoodPeak{
			Lat:                ll.Lat,
			Lon:                ll.Lon,
			DeltaNll:           p.delta,
			RelativeLikelihood: math.Exp(-p.delta),
			QualitativeBand:    band,
		})
	}

	vacFrac := float64(len(feasible)) / float64(nPts)
	mlCnt := len(mlPts)
	if mlCnt < 1 {
		mlCnt = 1
	}
	if plCount < mlCnt {
		plCount = mlCnt
	}
	mlFrac := float64(mlCnt) / float64(nPts)
	plFrac := float64(plCount) / float64(nPts)
	return SpatialLikelihoodSurface{
		IsEmpiricalEstimate:         true,
		IsHardProof:                 false,
		QualitativeScale:            "more_likely_to_less_likely",
		EffectiveIndependentAnchors: kEff,
		AnchorCount:                 k,
		Peaks:                       peaks,
		MoreLikelyAreaKm2:           mlFrac * earthKm2,
		MoreLikelyAreaFraction:      mlFrac,
		PlausibleAreaKm2:            plFrac * earthKm2,
		PlausibleAreaFraction:       plFrac,
		VacuumOuterAreaKm2:          vacFrac * earthKm2,
		VacuumOuterAreaFraction:     vacFrac,
	}
}
