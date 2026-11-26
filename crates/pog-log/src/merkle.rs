use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// RFC 6962-inspired append-only Merkle Transparency Tree (zero blockchain gas required!).
#[derive(Debug, Default, Clone)]
pub struct MerkleLog {
    leaves: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleInclusionProof {
    pub leaf_index: usize,
    pub tree_size: usize,
    pub leaf_hash_hex: String,
    pub root_hash_hex: String,
    pub audit_path_hex: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTreeHead {
    pub tree_size: usize,
    pub root_hash_hex: String,
    pub timestamp_unix_s: u64,
    pub log_public_key_hex: String,
    pub signature_hex: String,
}

fn hash_leaf(data: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&[0x00]); // Domain separation: leaf
    h.update(data);
    *h.finalize().as_bytes()
}

fn hash_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&[0x01]); // Domain separation: interior node
    h.update(left);
    h.update(right);
    *h.finalize().as_bytes()
}

impl MerkleLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    pub fn append(&mut self, record_bytes: &[u8]) -> usize {
        let leaf = hash_leaf(record_bytes);
        self.leaves.push(leaf);
        self.leaves.len() - 1
    }

    pub fn root(&self) -> [u8; 32] {
        if self.leaves.is_empty() {
            return *blake3::hash(b"pog-empty-tree-v1").as_bytes();
        }
        Self::compute_root(&self.leaves)
    }

    fn compute_root(nodes: &[[u8; 32]]) -> [u8; 32] {
        if nodes.len() == 1 {
            return nodes[0];
        }
        let split = largest_power_of_two_less_than(nodes.len());
        let left = Self::compute_root(&nodes[..split]);
        let right = Self::compute_root(&nodes[split..]);
        hash_node(&left, &right)
    }

    pub fn inclusion_proof(&self, index: usize) -> Option<MerkleInclusionProof> {
        if index >= self.leaves.len() {
            return None;
        }
        let mut path = Vec::new();
        Self::collect_proof(&self.leaves, index, &mut path);
        Some(MerkleInclusionProof {
            leaf_index: index,
            tree_size: self.leaves.len(),
            leaf_hash_hex: hex::encode(self.leaves[index]),
            root_hash_hex: hex::encode(self.root()),
            audit_path_hex: path.into_iter().map(hex::encode).collect(),
        })
    }

    fn collect_proof(nodes: &[[u8; 32]], index: usize, out: &mut Vec<[u8; 32]>) {
        if nodes.len() <= 1 {
            return;
        }
        let split = largest_power_of_two_less_than(nodes.len());
        if index < split {
            Self::collect_proof(&nodes[..split], index, out);
            out.push(Self::compute_root(&nodes[split..]));
        } else {
            Self::collect_proof(&nodes[split..], index - split, out);
            out.push(Self::compute_root(&nodes[..split]));
        }
    }

    pub fn sign_tree_head(&self, key: &SigningKey, timestamp_unix_s: u64) -> SignedTreeHead {
        let root_hex = hex::encode(self.root());
        let msg = sth_signing_bytes(self.len(), &root_hex, timestamp_unix_s);
        let sig = key.sign(&msg);
        SignedTreeHead {
            tree_size: self.len(),
            root_hash_hex: root_hex,
            timestamp_unix_s,
            log_public_key_hex: hex::encode(key.verifying_key().to_bytes()),
            signature_hex: hex::encode(sig.to_bytes()),
        }
    }
}

pub fn verify_inclusion_proof(proof: &MerkleInclusionProof) -> bool {
    if proof.tree_size == 0 || proof.leaf_index >= proof.tree_size {
        return false;
    }
    let Ok(leaf_raw) = hex::decode(&proof.leaf_hash_hex) else {
        return false;
    };
    let Ok(mut cur): Result<[u8; 32], _> = leaf_raw.try_into() else {
        return false;
    };
    let mut path_iter = proof.audit_path_hex.iter();
    let mut steps = Vec::new();
    collect_directions(proof.tree_size, proof.leaf_index, &mut steps);
    if steps.len() != proof.audit_path_hex.len() {
        return false;
    }
    for is_right_sibling in steps {
        let Some(sib_hex) = path_iter.next() else {
            return false;
        };
        let Ok(sib_raw) = hex::decode(sib_hex) else {
            return false;
        };
        let Ok(sib): Result<[u8; 32], _> = sib_raw.try_into() else {
            return false;
        };
        cur = if is_right_sibling {
            hash_node(&cur, &sib)
        } else {
            hash_node(&sib, &cur)
        };
    }
    hex::encode(cur) == proof.root_hash_hex
}

fn collect_directions(n: usize, index: usize, out: &mut Vec<bool>) {
    if n <= 1 {
        return;
    }
    let split = largest_power_of_two_less_than(n);
    if index < split {
        collect_directions(split, index, out);
        out.push(true); // sibling is on the right
    } else {
        collect_directions(n - split, index - split, out);
        out.push(false); // sibling is on the left
    }
}

pub fn verify_signed_tree_head(sth: &SignedTreeHead) -> bool {
    let Ok(pk_raw) = hex::decode(&sth.log_public_key_hex) else {
        return false;
    };
    let Ok(pk_arr): Result<[u8; 32], _> = pk_raw.try_into() else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_bytes(&pk_arr) else {
        return false;
    };
    let Ok(sig_raw) = hex::decode(&sth.signature_hex) else {
        return false;
    };
    let Ok(sig_arr): Result<[u8; 64], _> = sig_raw.try_into() else {
        return false;
    };
    let sig = Signature::from_bytes(&sig_arr);
    let msg = sth_signing_bytes(sth.tree_size, &sth.root_hash_hex, sth.timestamp_unix_s);
    vk.verify(&msg, &sig).is_ok()
}

fn sth_signing_bytes(tree_size: usize, root_hex: &str, timestamp_unix_s: u64) -> Vec<u8> {
    format!("pog-sth-v1|{tree_size}|{root_hex}|{timestamp_unix_s}").into_bytes()
}

fn largest_power_of_two_less_than(n: usize) -> usize {
    let mut p = 1usize;
    while p * 2 < n {
        p *= 2;
    }
    p
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_merkle_inclusion_and_sth() {
        let mut tree = MerkleLog::new();
        for i in 0..13 {
            tree.append(format!("hourly-geo-record-{i}").as_bytes());
        }
        for i in 0..13 {
            let p = tree.inclusion_proof(i).unwrap();
            assert!(verify_inclusion_proof(&p), "Failed proof at index {i}");
        }
        let key = SigningKey::generate(&mut OsRng);
        let sth = tree.sign_tree_head(&key, 1_764_000_000);
        assert!(verify_signed_tree_head(&sth));
    }
}
