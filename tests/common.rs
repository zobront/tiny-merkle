use tiny_merkle::*;

use hex_literal::hex;
use sha2::{Digest, Sha256, Sha384, Sha512};
// use tiny_keccak::Sha3;

macro_rules! impl_sha2 {
	($s:ty,$t:ident,$size:literal) => {
		// combine the hasher and the hash type into a single struct
		pub struct $t;
		impl Hasher for $t {
			type Hash = [u8; $size];
			fn hash(value: &[u8]) -> Self::Hash {
				let mut hasher = <$s>::new();
				let mut hash = [0u8; $size];
				hasher.update(value);
				hash.copy_from_slice(hasher.finalize().as_slice());
				hash
			}
		}
	};
}

impl_sha2!(Sha256, Sha256Hasher, 32);
impl_sha2!(Sha384, Sha384Hasher, 48);
impl_sha2!(Sha512, Sha512Hasher, 64);

pub fn sha256(data: &[u8]) -> [u8; 32] {
	let mut hasher = Sha256::new();
	let mut hash = [0u8; 32];
	hasher.update(data);
	hash.copy_from_slice(hasher.finalize().as_slice());
	hash
}

#[test]
fn sha256_root_and_proof() {
	let leaf_values = ["a", "b", "c", "d", "e", "f"];
	let expected_root_hex = hex!("1f7379539707bcaea00564168d1d4d626b09b73f8a2a365234c62d763f854da2");
	let leaf_hashes: Vec<_> = leaf_values.iter().map(|x| sha256(x.as_bytes())).collect();
	let tree = MerkleTree::<Sha256Hasher>::new(leaf_hashes.clone(), None);
	assert_eq!(tree.root().as_ref(), expected_root_hex);

	for (i, leaf) in leaf_hashes.iter().enumerate() {
		let proof = tree.proof(leaf).expect("Failed to generate proof");
		assert!(
			tree.verify(leaf, &tree.root(), &proof),
			"Failed to verify proof, leaf: {:?}, value: {:?}",
			hex::encode(leaf),
			leaf_values[i]
		);
	}
}

macro_rules! test_sha2_case {
	($sh:ident,$fn:ident,$root_hex:literal) => {
		#[test]
		fn $fn() {
			let leaf_values = [
				"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z",
				"1", "2", "3", "4", "5", "6", "7", "8", "9", "0", "!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "-", "_", "+", "=", "[", "]",
				"{", "}", ";", ":", "'", "<", ">", ",", ".", "/", "?", "|", "\\", "~", "`", " ", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J",
				"K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "Aa", "Bb", "Cc", "Dd", "Ee", "Ff", "Gg", "Hh", "Ii",
				"Jj", "Kk", "Ll", "Mm", "Nn", "Oo", "Pp", "Qq", "Rr", "Ss", "Tt", "Uu", "Vv", "Ww", "Xx", "Yy", "Zz",
			];

			let leaf_hashes: Vec<_> = leaf_values
				.iter()
				.map(|x| {
					// let sha = $sh;
					$sh::hash(x.as_bytes())
				})
				.collect();
			let tree = MerkleTree::<$sh>::new(leaf_hashes.clone(), None);
			let root = tree.root();
			assert_eq!(root.as_ref(), hex!($root_hex));
			// println!("root: {:?}", hex::encode(root.as_ref()));
			for (i, leaf) in leaf_hashes.iter().enumerate() {
				let proof = tree.proof(leaf).expect("Failed to generate proof");
				assert!(
					tree.verify(leaf, &root, &proof),
					"Failed to verify proof, leaf: {:?}, value: {:?}",
					hex::encode(leaf),
					leaf_values[i]
				);
			}
		}
	};
}

test_sha2_case!(
	Sha256Hasher,
	sha256_proof,
	"69ce81988abd6a836fee46ff4a87391ce555dbaddbbd51d83c517464fa45f650"
);
test_sha2_case!(
	Sha384Hasher,
	sha384_proof,
	"3397e5dd75ce8ee6330c97084ef5631d50e3e7ccebf9de3444087f9da9c61c8bd80280755e332c60b3a1448ac4150c31"
);
test_sha2_case!(
	Sha512Hasher,
	sha512_proof,
	"409ec1499d4585bf1aeb17d5002196b0f766597c8c2c8fbe5c96713efbe41df1616dec8dcc7308aadefd88f26dad4a2b7547dd783b63664b8cf169025acfc117"
);
