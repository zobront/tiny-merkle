// extern crate test;

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use tiny_keccak::{Hasher, Keccak};
use tiny_merkle::MerkleTree;

pub struct KeccakHasher;
impl tiny_merkle::Hasher for KeccakHasher {
	type Hash = [u8; 32];

	fn hash(&self, value: &[u8]) -> Self::Hash {
		keccak256(value)
	}
}

fn keccak256(data: &[u8]) -> [u8; 32] {
	let mut hasher = Keccak::v256();
	let mut hash = [0_u8; 32];
	hasher.update(data);
	hasher.finalize(&mut hash);
	hash
}

criterion_group!(benches, merkle_proof_benchmark);
criterion_main!(benches);

fn merkle_proof_benchmark(c: &mut Criterion) {
	let leaves = vec![
		"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z",
	]
	.iter()
	.map(|x| keccak256(x.as_bytes()))
	.collect::<Vec<_>>();
	let mtree = MerkleTree::<KeccakHasher>::new(KeccakHasher, leaves, None);
	let root = mtree.root();

	// verify the proof of the first leaf
	let leaf = keccak256("a".as_bytes());
	let proof = mtree.proof(&leaf).unwrap();
	assert!(mtree.verify(&leaf, &root, &proof));

	c.bench_function("merkle proof", |b| b.iter(|| mtree.proof(black_box(&leaf))));
}
