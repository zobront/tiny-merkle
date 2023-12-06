use crate::hash::Hasher;

/// Position of a leaf in the tree.
#[derive(Debug, Clone, PartialEq)]
pub enum Position {
	Left,
	Right,
}

impl std::fmt::Display for Position {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Position::Left => write!(f, "Left"),
			Position::Right => write!(f, "Right"),
		}
	}
}

/// pair of hash and position
#[derive(Debug, Clone)]
pub struct Pair<H>
where
	H: Hasher,
{
	pub data: H::Hash,
	pub position: Position,
}

/// Merkle proof for a leaf.
#[derive(Clone)]
pub struct MerkleProof<H>
where
	H: Hasher,
{
	pub proofs: Vec<Pair<H>>,
}

impl<H> std::fmt::Debug for MerkleProof<H>
where
	H: Hasher + std::fmt::Debug,
	H::Hash: std::fmt::Debug,
{
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "MerkleProof {{ proofs: {:?} }}", self.proofs)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{merkle::tests::KeccakHasher, MerkleTree};

	#[test]
	fn test_debug() {
		let leaves = vec!["a", "b", "c", "d", "e", "f"]
			.iter()
			.map(|x| KeccakHasher::hash(x.as_bytes()))
			.collect::<Vec<_>>();
		let mtree = MerkleTree::<KeccakHasher>::new(leaves, None);
		let _root = mtree.root();

		// verify the proof of the first leaf
		let leaf = KeccakHasher::hash("a".as_bytes());
		let proof = mtree.proof(&leaf).unwrap();
		// assert!(mtree.verify(&leaf, &root, &proof));
		format!("{:?}", proof);
	}
}
