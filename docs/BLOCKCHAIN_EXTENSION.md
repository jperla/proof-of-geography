# Optional Future Extension: Blockchain / Smart Contract Anchoring (Tabled)

> **Status: Deliberately tabled for v1.**
> Proof of Geography works today as a **free, zero-gas, DNS & Certificate Transparency–style public utility** (`pog-log` + signed `AnchorGrid` + offline client verification in < 0.5 ms). No tokens, wallets, gas fees, or consensus delays are required to operate the 24-node Anchor grid or verify trillions of requests.

When (and if) permissionless crypto-economic incentives, DePIN slashing, or smart-contract-native geofencing are needed in the future, the existing architecture plugs into a blockchain cleanly with **zero changes to `pog-geo`, `pog-tee`, or `pog-proto`**:

## 1. Lightweight Signed Tree Head (STH) Anchoring
* Instead of posting individual hourly proofs on-chain, the `pog-log` transparency server posts its 32-byte **Merkle Root (`SignedTreeHead`)** once per hour to an L2 (Base / Arbitrum / Optimism) or Ethereum L1 (< \$0.01/hour).
* Any smart contract or auditor can verify a Prover's complete history via an $O(\log N)$ Merkle inclusion proof (`MerkleInclusionProof`) without paying per-proof gas.

## 2. Optional On-Chain `GeoVerifier` Smart Contract
* Because `crates/pog-geo/src/byzantine.rs` checks exact $(K-f)$-core containment on $\mathbb{S}^2$ using only **3D dot/cross products over at most $K^2 + 1 = 37$ candidate points**, the exact algorithm ports directly to fixed-point Solidity (or an SP1 / RISC Zero Groth16 ZK proof wrapping the Rust `verify_proof_bundle()` function directly!).
* **Cached TEE Key Pattern:** Verify the raw Intel TDX DCAP / AMD SEV-SNP X.509 quote once at enclave boot (via Automata/Phala on-chain verifiers or ZK proof), then refresh hourly PoG records for < 120k L2 gas.

## 3. Staked / Slashed Anchor Operators
* Future Anchor operators could post collateral to `AnchorRegistry`, where any watcher can submit a **Calibration Fraud Proof** from `CalibrationMatrix` (proving an Anchor violated vacuum speed of light against honest peers) to trigger automatic slashing and eviction.
