use crate::hash::Hasher;
use crate::proof::{MerkleProof, Pair, Position};
use alloc::vec;
use alloc::vec::Vec;
/// Maximum supported depth of the tree. 32 corresponds to `2^32` elements in the tree, which
/// we unlikely to ever hit.
const MAX_TREE_DEPTH: usize = 32;

/// Merkle tree options.
#[derive(Debug, Clone, Default)]
pub struct MerkleOptions {
	/// If set, the tree will be padded to this size with zero hashes.
	// pub min_tree_size: Option<usize>,
	/// If set to `true`, the leaves will hashed using the set hashing algorithms.
	pub hash_leaves: Option<bool>,
	/// If `true`, the leaves are sorted before building the tree.
	pub sort_leaves: Option<bool>,
	/// If `true`, the pairs of adjacent leaves are sorted before computing the parent hash.
	pub sort_pairs: Option<bool>,

	/// If `true`, sort_pairs is set to `true` and sort_pairs is set to `true`.
	pub sort: Option<bool>,

	#[cfg(feature = "rayon")]
	pub parallel: Option<bool>,
}

impl MerkleOptions {
	pub fn new() -> Self {
		Self::default()
	}

	pub fn with_hash_leaves(mut self, hash_leaves: bool) -> Self {
		self.hash_leaves = Some(hash_leaves);
		self
	}

	pub fn with_sort_leaves(mut self, sort_leaves: bool) -> Self {
		self.sort_leaves = Some(sort_leaves);
		self
	}

	pub fn with_sort_pairs(mut self, sort_pairs: bool) -> Self {
		self.sort_pairs = Some(sort_pairs);
		self
	}

	pub fn with_sort(mut self, sort: bool) -> Self {
		self.sort = Some(sort);
		self
	}

	#[cfg(feature = "rayon")]
	pub fn with_parallel(mut self, parallel: bool) -> Self {
		self.parallel = Some(parallel);
		self
	}
}

/// Merkle tree.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct MerkleTree<H>
where
	H: Hasher,
{
	layers: Vec<Vec<H::Hash>>,
	leaves_count: usize,
	high: usize,
	hash_leaves: bool,
	sort_leaves: bool,
	sort_pairs: bool,
	sort: bool,

	#[cfg(feature = "rayon")]
	parallel: bool,
}

impl<H> MerkleTree<H>
where
	H: Hasher,
{
	/// Creates a new empty tree.
	///
	/// # Example
	///
	/// ```
	/// use tiny_merkle::{MerkleTree,hash::NoopHasher};
	///
	/// let tree = MerkleTree::<NoopHasher>::new();
	/// let root = tree.root();
	/// let expect_root = vec![];
	/// assert_eq!(root,expect_root);
	#[allow(clippy::new_without_default)]
	pub fn new() -> Self {
		let layers = Self::build_internal(Vec::new(), false, false);
		Self {
			layers,
			leaves_count: 0,
			high: 0,
			hash_leaves: false,
			sort_leaves: false,
			sort_pairs: false,
			sort: false,

			#[cfg(feature = "rayon")]
			parallel: false,
		}
	}

	/// Creates a new tree from the given leaves.
	/// # Example
	/// ```
	/// use tiny_merkle::{MerkleTree,hash::{NoopHasher,Hasher}};
	/// let leaves = vec!["a", "b", "c", "d", "e", "f"].iter().map(|x| NoopHasher::hash(x.as_bytes())).collect::<Vec<_>>();
	/// let tree = MerkleTree::<NoopHasher>::from_leaves(leaves, None);
	/// let root = tree.root();
	/// let expect_root = vec![0x61, 0x62, 0x63, 0x64, 0x65, 0x66];
	/// assert_eq!(root,expect_root);
	/// ```
	/// # Panics
	/// Will panic if the constant below is invalid.
	/// ```
	/// const MAX_TREE_DEPTH: usize = 32;
	/// ```
	pub fn from_leaves(leaves: impl IntoIterator<Item = H::Hash>, opts: Option<MerkleOptions>) -> Self {
		let (mut hash_leaves, mut sort_leaves, mut sort_pairs, mut sort) = (false, false, false, false);
		// #[cfg(feature = "rayon")]
		#[allow(unused_mut)]
		let mut parallel = false;
		if let Some(opts) = opts {
			hash_leaves = opts.hash_leaves.unwrap_or(false);
			sort_leaves = opts.sort_leaves.unwrap_or(false);
			sort_pairs = opts.sort_pairs.unwrap_or(false);
			sort = opts.sort.unwrap_or(false);
			if sort {
				sort_leaves = true;
				sort_pairs = true;
			}

			#[cfg(feature = "rayon")]
			{
				parallel = opts.parallel.unwrap_or(false);
			}
		}

		let mut hashes: Vec<_> = leaves
			.into_iter()
			.map(|bytes| if hash_leaves { H::hash(bytes.as_ref()) } else { bytes })
			.collect();

		if sort_leaves {
			hashes.sort();
		}

		let high = hashes.len().next_power_of_two();
		// if let Some(min_tree_size) = min_tree_size {
		// 	assert!(min_tree_size.is_power_of_two(), "tree size must be a power of 2");
		// 	high = min_tree_size.max(high);
		// }
		assert!(
			tree_depth_by_size(high) <= MAX_TREE_DEPTH,
			"Tree contains more items than supported"
		);
		let leaves_count = hashes.len();
		let layers = Self::build_internal(hashes, sort_pairs, parallel);

		Self {
			leaves_count,
			layers,
			high,
			hash_leaves,
			sort_leaves,
			sort_pairs,
			sort,

			#[cfg(feature = "rayon")]
			parallel,
		}
	}

	/// Returns the root hash of this tree.
	/// # Panics
	/// Will panic if the constant below is invalid.
	pub fn root(&self) -> H::Hash {
		if self.layers.is_empty() {
			panic!("merkle root of empty tree is not defined");
		} else {
			self.layers.last().unwrap()[0].clone()
		}
	}

	/// Returns the proof for the given leaf.
	/// # Example
	/// ```
	/// use tiny_merkle::{MerkleTree,hash::{NoopHasher,Hasher}};
	/// let leaves = vec!["a", "b", "c", "d", "e", "f"].iter().map(|x| NoopHasher::hash(x.as_bytes())).collect::<Vec<_>>();
	/// let tree = MerkleTree::<NoopHasher>::from_leaves(leaves, None);
	/// let root = tree.root();
	/// let leaf = NoopHasher::hash("a".as_bytes());
	/// let proof = tree.proof(&leaf).unwrap();
	/// assert!(tree.verify(&leaf, &root, &proof));
	/// ```
	pub fn proof<T: AsRef<[u8]>>(&self, leaf: T) -> Option<MerkleProof<H>> {
		if self.layers.is_empty()
		/* || self.layers[0].is_empty() */
		{
			return None;
		}

		let index = if self.sort_leaves {
			self.layers[0].binary_search_by(|probe| probe.as_ref().cmp(leaf.as_ref())).ok()?
		} else {
			self.layers[0].iter().position(|x| x.as_ref() == leaf.as_ref())?
		};

		let proof = self.make_proof(index);
		Some(proof)
	}

	/// Verifies the given proof against the given leaf and root.
	/// # Example
	/// ```
	/// use tiny_merkle::{MerkleTree,hash::{NoopHasher,Hasher}};
	/// let leaves = vec!["a", "b", "c", "d", "e", "f"].iter().map(|x| NoopHasher::hash(x.as_bytes())).collect::<Vec<_>>();
	/// let tree = MerkleTree::<NoopHasher>::from_leaves(leaves, None);
	/// let root = tree.root();
	/// let leaf = NoopHasher::hash("a".as_bytes());
	/// let proof = tree.proof(&leaf).unwrap();
	/// assert!(tree.verify(&leaf, &root, &proof));
	pub fn verify<T: AsRef<[u8]>>(&self, leaf: T, root: T, proof: &MerkleProof<H>) -> bool {
		self.get_root_from_proof(leaf, proof) == root.as_ref()
	}

	pub fn get_root_from_proof<T: AsRef<[u8]>>(&self, leaf: T, proof: &MerkleProof<H>) -> Vec<u8> {
		let mut hash = leaf.as_ref().to_vec();
		for p in proof.proofs.iter() {
			if self.sort_pairs {
				let mut v = vec![hash.clone(), p.data.as_ref().to_vec()];
				v.sort();
				let mut combine = v[0].clone();
				combine.extend(v[1].iter());
				hash = H::hash(&combine).as_ref().to_vec();
			} else if p.position == Position::Left {
				let mut combine = p.data.as_ref().to_vec();
				combine.extend(hash);
				hash = H::hash(combine.as_ref()).as_ref().to_vec();
			} else {
				let mut combine = hash.clone();
				combine.extend(p.data.as_ref());
				hash = H::hash(combine.as_ref()).as_ref().to_vec();
			}
		}

		hash
	}

    pub fn get_root_from_proof_unsorted<T: AsRef<[u8]>>(leaf: T, proof: &MerkleProof<H>) -> Vec<u8> {
        let mut hash = leaf.as_ref().to_vec();
        for p in proof.proofs.iter() {
            if p.position == Position::Left {
                let mut combine = p.data.as_ref().to_vec();
                combine.extend(hash);
                hash = H::hash(combine.as_ref()).as_ref().to_vec();
            } else {
                let mut combine = hash.clone();
                combine.extend(p.data.as_ref());
                hash = H::hash(combine.as_ref()).as_ref().to_vec();
            }
        }

        hash
    }

	/// appends a new leaf to the tree.
	pub fn append_leaf(&mut self, new_leaf: H::Hash) {
		// TODO make it more efficient
		let mut leaves = self.layers[0].clone();
		leaves.push(new_leaf);
		self.leaves_count += 1;
		self.high = leaves.len().next_power_of_two();

		if self.sort_leaves {
			leaves.sort();
		}

		#[cfg(feature = "rayon")]
		let parallel = self.parallel;
		#[cfg(not(feature = "rayon"))]
		let parallel = false;

		self.layers = Self::build_internal(leaves, self.sort_pairs, parallel);
	}

	pub fn make_proof(&self, index: usize) -> MerkleProof<H> {
		// let binary_tree_size = hashes.len().next_power_of_two();
		let depth = tree_depth_by_size(self.high);
		let mut merkle_path = vec![];
		let mut level_len = self.leaves_count;
		let mut index: usize = index;
		for level in 0..depth {
			let adjacent_idx = index ^ 1;
			if adjacent_idx < level_len {
				let p = Pair {
					data: self.layers[level][adjacent_idx].clone(),
					position: if adjacent_idx <= index { Position::Left } else { Position::Right },
				};

				merkle_path.push(p);
			}
			index /= 2;
			level_len = level_len / 2 + level_len % 2;
		}

		MerkleProof { proofs: merkle_path }
	}

	fn build_internal(leaves: Vec<H::Hash>, sort_pairs: bool, parallel: bool) -> Vec<Vec<H::Hash>> {
		let binary_tree_size = leaves.len().next_power_of_two();
		let depth = tree_depth_by_size(binary_tree_size);
		let mut layers = vec![];
		let mut hashes: Vec<H::Hash> = leaves.clone();
		let mut level_len = hashes.len();
		layers.push(leaves);

		for _level in 0..depth {
			if parallel {
				#[cfg(not(feature = "rayon"))]
				{
					for i in 0..(level_len / 2) {
						if sort_pairs {
							hashes[2 * i..2 * i + 2].sort();
						}
						// combine hashes[2 * i], &hashes[2 * i + 1]
						let mut combine = hashes[2 * i].as_ref().to_vec();
						combine.extend(hashes[2 * i + 1].as_ref());
						hashes[i] = H::hash(combine.as_ref());
					}
				}

				#[cfg(feature = "rayon")]
				{
					use rayon::prelude::{IntoParallelIterator, ParallelIterator};
					let layar_level = hashes[0..level_len]
						.chunks(2)
						.collect::<Vec<_>>()
						.into_par_iter()
						.map_with(&hashes, |_src, hash| {
							if hash.len() == 2 {
								let mut pair = [hash[0].clone(), hash[1].clone()];
								if sort_pairs {
									pair.sort();
								}
								let mut combine = pair[0].as_ref().to_vec();
								combine.extend(pair[1].as_ref());
								H::hash(combine.as_ref())
							} else {
								hash[0].clone()
							}
						})
						.collect::<Vec<_>>();

					hashes[..(level_len / 2)].clone_from_slice(&layar_level[..(level_len / 2)]);
				}
			} else {
				for i in 0..(level_len / 2) {
					if sort_pairs {
						hashes[2 * i..2 * i + 2].sort();
					}
					// combine hashes[2 * i], &hashes[2 * i + 1]
					let mut combine = hashes[2 * i].as_ref().to_vec();
					combine.extend(hashes[2 * i + 1].as_ref());
					hashes[i] = H::hash(combine.as_ref());
				}
			}

			if level_len % 2 == 1 {
				hashes[level_len / 2] = hashes[level_len - 1].clone();
			}

			level_len = level_len / 2 + level_len % 2;
			layers.push(hashes[..level_len].to_vec());
		}

		// leaves may be empty
		if hashes.is_empty() {
			layers.push(vec![H::hash(&[])]);
		} else {
			let root = hashes[0].clone();
			layers.push(vec![root]);
		}

		layers
	}
}

fn tree_depth_by_size(tree_size: usize) -> usize {
	debug_assert!(tree_size.is_power_of_two());
	tree_size.trailing_zeros() as usize
}

#[cfg(test)]
pub(super) mod tests {
	use crate::hash::NoopHasher;

	use super::*;

	use alloc::format;
	use alloc::string::{String, ToString};
	use hex_literal::hex;

	use tiny_keccak::{Hasher, Keccak};

	fn keccak256(value: &[u8]) -> [u8; 32] {
		let mut hasher = Keccak::v256();
		let mut hash = [0_u8; 32];
		hasher.update(value);
		hasher.finalize(&mut hash);
		hash
	}

	#[derive(Clone, Debug)]
	pub struct KeccakHasher;
	impl super::Hasher for KeccakHasher {
		type Hash = [u8; 32];

		fn hash(value: &[u8]) -> Self::Hash {
			keccak256(value)
		}
	}
	// [u8; 32] to hex string
	fn to_hex_string(hash: &[u8]) -> String {
		let mut s = String::new();
		for h in hash {
			s.push_str(&format!("{:02x}", h));
		}
		s
	}

	#[cfg(feature = "std")]
	impl core::fmt::Display for Pair<KeccakHasher> {
		fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
			write!(f, "data: {}, position: {}", to_hex_string(self.data.as_ref()), self.position)
		}
	}

	#[test]
	fn new_merkletree() {
		let tree = MerkleTree::<NoopHasher>::new();
		let root = tree.root();
		let expect_root = vec![];
		assert_eq!(
			root,
			expect_root,
			"merkle root mismatch, expect: {:?}, got: {:?}",
			to_hex_string(&expect_root),
			to_hex_string(&root)
		);
	}

	#[test]
	fn test_append() {
		use crate::hash::NoopHasher;

		let null_leaves = vec!["dd".as_bytes().to_vec(), "ee".as_bytes().to_vec()];
		let mut expect_root = "ddee".as_bytes().to_vec();
		let mut tree = MerkleTree::<NoopHasher>::from_leaves(null_leaves, None);
		let root = tree.root();

		assert_eq!(
			root,
			expect_root,
			"merkle root mismatch, expect: {:?}, got: {:?}",
			to_hex_string(&expect_root),
			to_hex_string(&root)
		);

		for i in 0..2_000 {
			tree.append_leaf(i.to_string().as_bytes().to_vec());
			let root = tree.root();
			expect_root.extend(i.to_string().as_bytes());
			// println!("a root: {:?}", to_hex_string(&root));
			assert_eq!(
				root,
				expect_root,
				"merkle root mismatch, expect: {:?}, got: {:?}",
				to_hex_string(&expect_root),
				to_hex_string(&root)
			);
		}
	}

	#[test]
	fn test_k256() {
		let null = keccak256(&[]);
		// println!("n: {:?}", to_hex_string(&n));
		let expect = hex!("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
		assert_eq!(
			null,
			expect,
			"keccak256 mismatch, expect: {:?}, got: {:?}",
			to_hex_string(&expect),
			to_hex_string(&null)
		);
	}

	#[test]
	fn test_merkle_root() {
		let null_leaves = vec![];
		let tree = MerkleTree::<KeccakHasher>::from_leaves(null_leaves, None);
		let root = tree.root();
		let expect_root = hex!("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
		assert_eq!(
			root,
			expect_root,
			"merkle root mismatch, expect: {:?}, got: {:?}",
			to_hex_string(&expect_root),
			to_hex_string(&root)
		);

		let leaves = vec![
			hex!("8bc6a1d45d6d4c063a0936e28d702bcc15bd5a2dc8eb65e85006915f191e294c"),
			hex!("f49675d9423d176411d875b32fd9f272269f0b4a44f52b16d40e575a6c1bea61"),
			hex!("84f2c42c72ab408b2a49be2c2ccf3f896b05308a0116bce5e93d073189b250f7"),
			hex!("e6a12952e10e9bd1585df31d4fdf615a41f2a797779bf7c9b55e6facdbde6430"),
			hex!("02582971c6440ea5aab5d02bc054c6ba3c3a6025790543420e0ca186de30f6cf"),
			hex!("b7732e74565cc365a9c58f349f11d94700bcee8fc5ba5ba5a508236ca1d300e4"),
			hex!("79a15a38292be04bf2376a164674d975a7a596afd8d6fe85981a6305c849bb99"),
			hex!("d6fd2aaabaebf50980d2184e9141ce286111b4f7a39b32bd0ecac22871a4ed14"),
			hex!("5b2f452cde6154eeb8227eb91d5fb1f2e31d1e16cac741d4ec6ce18593fd6792"),
			hex!("bbc69bfe1697e473296758de9b9796948a13b6b1ad2b91fcd6118916fdff8dea"),
			hex!("3389eff6964486b49edb5f54cf9a833aee42298ebe250c094ae3a0857944ba5c"),
			hex!("5b920af4c112b8bd1c3ef32c2f24f8f3f891fc3c85b8285bbf21cb9a4573b608"),
		];

		let tree = MerkleTree::<KeccakHasher>::from_leaves(
			leaves.clone(),
			Some(MerkleOptions {
				sort: Some(true),
				#[cfg(feature = "rayon")]
				parallel: Some(true),
				..Default::default()
			}),
		);

		let root = tree.root();
		let expect_root = hex!("fb2a038476ab757a1c8bd9bf1b329eb3c2a9e5db7415eaee9acdbbe1ae789aeb");
		assert_eq!(
			root,
			expect_root,
			"merkle root mismatch, expect: {:?}, got: {:?}",
			to_hex_string(&expect_root),
			to_hex_string(&root)
		);
		// 3a1c0c3404f3cb834b40c4c477d4da4e40df75a9bf771b0461277e25b8e1db88
		// 74af6d554f807094a752ff496ec0b907822d0775ee823cb92cf6ae01258b30ea
		// 315e78532a270b2954079858c4abfaebc0a49a36c3c1b2684da3847a161d5bd6
		// 15a8528ae2d9f85886bcc8f0ee24f8a6d0c1ec57ef3dc0bbcc964cbe820a7d95
		// 9861cae0002869d2f4c65e4a31500ea55d0a2686d44dbdeeedc29e09196a1e99

		let index = 0;

		let proof = tree.proof(leaves[index].as_ref()).unwrap();
		// for p in proof.iter() {
		// 	println!("proof +: {:?},{}", to_hex_string(p.data.as_ref()), p.position);
		// }

		let v = tree.verify(leaves[index].as_ref(), root.as_ref(), &proof);
		assert!(
			v,
			"verify failed, leaf: {:?}, root: {:?}",
			to_hex_string(leaves[index].as_ref()),
			to_hex_string(root.as_ref())
		);

		for l in leaves.iter() {
			let proof = tree.proof(l.as_ref()).unwrap();

			let v = tree.verify(l.as_ref(), root.as_ref(), &proof);
			assert!(
				v,
				"loop :verify failed, leaf: {:?}, root: {:?}",
				to_hex_string(l.as_ref()),
				to_hex_string(root.as_ref())
			);
		}

		assert_eq!(
			root,
			expect_root,
			"merkle root mismatch, expect: {:?}, got: {:?}",
			to_hex_string(&expect_root),
			to_hex_string(&root)
		);
		// println!("root: {:?}", to_hex_string(root.as_ref()));
	}

	#[test]
	fn test_build() {
		let mut leaves = vec![
			hex!("8bc6a1d45d6d4c063a0936e28d702bcc15bd5a2dc8eb65e85006915f191e294c"),
			hex!("f49675d9423d176411d875b32fd9f272269f0b4a44f52b16d40e575a6c1bea61"),
			hex!("84f2c42c72ab408b2a49be2c2ccf3f896b05308a0116bce5e93d073189b250f7"),
			hex!("e6a12952e10e9bd1585df31d4fdf615a41f2a797779bf7c9b55e6facdbde6430"),
			hex!("02582971c6440ea5aab5d02bc054c6ba3c3a6025790543420e0ca186de30f6cf"),
			hex!("b7732e74565cc365a9c58f349f11d94700bcee8fc5ba5ba5a508236ca1d300e4"),
			hex!("79a15a38292be04bf2376a164674d975a7a596afd8d6fe85981a6305c849bb99"),
			hex!("d6fd2aaabaebf50980d2184e9141ce286111b4f7a39b32bd0ecac22871a4ed14"),
			hex!("5b2f452cde6154eeb8227eb91d5fb1f2e31d1e16cac741d4ec6ce18593fd6792"),
			hex!("bbc69bfe1697e473296758de9b9796948a13b6b1ad2b91fcd6118916fdff8dea"),
			hex!("3389eff6964486b49edb5f54cf9a833aee42298ebe250c094ae3a0857944ba5c"),
			hex!("5b920af4c112b8bd1c3ef32c2f24f8f3f891fc3c85b8285bbf21cb9a4573b608"),
		];
		leaves.sort();

		#[cfg(feature = "rayon")]
		let parall: bool = true;
		#[cfg(not(feature = "rayon"))]
		let parall: bool = false;

		let hashes = MerkleTree::<KeccakHasher>::build_internal(leaves, true, parall);

		let root = hashes.last().unwrap()[0];
		let expect_root = hex!("fb2a038476ab757a1c8bd9bf1b329eb3c2a9e5db7415eaee9acdbbe1ae789aeb");
		assert_eq!(
			root,
			expect_root,
			"merkle root mismatch, expect: {:?}, got: {:?}",
			to_hex_string(&expect_root),
			to_hex_string(&root)
		);
		// println!("{:?}",hashes);

		// let pf = MerkleTree::<KeccakHasher>::cp_proof(&hashes, 5, 16, 12);
		// for p in pf.iter() {
		// 	println!("proof +: {:?},{}", to_hex_string(p.data.as_ref()), p.position);
		// }
	}

	#[test]
	fn test_index2() {
		let l1 =
			hex!("e6a12952e10e9bd1585df31d4fdf615a41f2a797779bf7c9b55e6facdbde6430f49675d9423d176411d875b32fd9f272269f0b4a44f52b16d40e575a6c1bea61");
		let _h1 = keccak256(l1.as_ref());
		let l2 =
			hex!("0db8d09ee11b02e821ef5624b60d658c297fc8142bdd59a94ce22d92d44a5a1e78da1389c734a3d24a3507be4031aa3ab3f703cbe59ed5fe868b04c787b68517")
				.to_vec();

		let h2 = keccak256(l2.as_ref());

		let mut l3 = hex!("a3647b2eff717882dabdf2e0ace205337209cf3d9f4b888810ef18939fc6834f").to_vec();
		l3.extend(h2);
		let h3 = keccak256(l3.as_ref());

		assert_eq!(h3, hex!("fb2a038476ab757a1c8bd9bf1b329eb3c2a9e5db7415eaee9acdbbe1ae789aeb"));
	}
}
