<h3 align="center">
  <br />
  <img src="https://user-images.githubusercontent.com/4885186/193118010-2a9f5129-6232-42bd-8efe-dfb29753508e.png" alt="merkletree.js logo" width="600" />
  <br />
  <br />
  <br />
</h3>

# MerkleTree for Ethereum
[![Build status](https://github.com/chiaos/merkletree/actions/workflows/CI.yml/badge.svg?branch=main)](https://github.com/chiaos/merkletree/actions/workflows/CI.yml)
[![Crates.io](https://img.shields.io/crates/v/tiny-merkle)](https://crates.io/crates/tiny-merkle)
[![Documentation](https://docs.rs/tiny-merkle/badge.svg)](https://docs.rs/tiny-merkle)


## Contents

- [Uasge](#usage)
- [Diagrams](#diagrams)
- [License](#license)





## Usage

Add the following to your `Cargo.toml`:

```toml
[dependencies]
tiny-merkle = "0.1"
tiny-keccak = { version = "2.0.2", features = ["keccak"] }
```

Construct tree, generate proof, and verify proof:

```rust
use tiny_merkle::MerkleTree;
use tiny_keccak::{Hasher, Keccak};

#[derive(Clone, Debug)]
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

fn main() {
	let data_raw = vec!["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"];

	let leaves = data_raw
		.iter()
		.map(|s| keccak256(&s.as_bytes()))
		.collect::<Vec<_>>();

	let tree = MerkleTree::new(
		KeccakHasher,
		leaves.clone(),
		Some(tiny_merkle::MerkleOptions {
			sort: Some(true),
			..Default::default()
		}),
	);

	println!("root: {}", hex::encode(tree.root()));

	let proof = tree.proof(&leaves[0]).unwrap();

	let ok = tree.verify(&leaves[0], &tree.root(), &proof);
	println!("verify: {}", ok);
}


```


## Diagrams

▾ Visualization of Merkle Tree

<img src="https://user-images.githubusercontent.com/168240/43616375-15330c32-9671-11e8-9057-6e61c312c856.png" alt="Merkle Tree" width="500">

▾ Visualization of Merkle Tree Proof

<img src="https://user-images.githubusercontent.com/168240/204968384-dbd16f5b-415c-4cc6-b993-5bbd7599ec8b.png" alt="Merkle Tree Proof" width="420">

▾ Visualization of Invalid Merkle Tree Proofs

<img src="https://user-images.githubusercontent.com/168240/204968414-fefedb52-d27f-4b14-bf70-e3f96a50b6a3.png" alt="Merkle Tree Proof" width="420">

▾ Visualization of Bitcoin Merkle Tree

<img src="https://user-images.githubusercontent.com/168240/43616417-46d3293e-9671-11e8-81c3-8cdf7f8ddd77.png" alt="Merkle Tree Proof" width="420">



## License

This project is licensed under the MIT License - see the 
[LICENSE.md](./LICENSE.md) file for details