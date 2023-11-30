use tiny_keccak::{Hasher, Keccak};
use tiny_merkle::{MerkleOptions, MerkleTree};

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

fn i32_to_uint256(i: i32) -> [u8; 32] {
	let mut res = [0u8; 32];
	res[31] = i as u8;
	res[30] = (i >> 8) as u8;
	res[29] = (i >> 16) as u8;
	res[28] = (i >> 24) as u8;
	res
}

fn main() {
	let data_raw = vec![
		("0x901Ab22EdCA65188686C9742F2C88c946698bc90", 100),
		("0x7b95d138cD923476b6e697391DD2aA01D15BAB27", 100),
		("0xaBA8e3eB6D782e3B85Aa1Dd6E5B07136D4F98236", 100),
		("0x519cD54891B30157f526485CCA49e9D0fa32BD86", 100),
		("0xBd5760bf0A1cA1879881351018383c00B126e23D", 100),
		("0x71a40d4D0110c99fe2f804378DD21D6aed50FFe8", 100),
		("0x5a3281D2d5b81C0c6591627617d6374fF6D8AD63", 100),
		("0xb1397d10bd332dbe3b0009DFB1732D86F9dF5653", 100),
		("0xcD7Ee7cb8A87816ddb21Caec344767Ca8D51902b", 100),
		("0x110d697D5921d22c3C581eCd660dfb0Cd00d0212", 100),
		("0x6Ffa3Ff180c26F58aE21aDD80Dd6D3C971c22c6D", 100),
		("0xd1D0DeD9Bd888F4754CB2fdA8B3250b8b06ac2aF", 100),
		("0x86015C5C3d6a882B025FA7428BF784B2dAd8e0CE", 100),
		("0x5271089D698fab4C6400d3BF53b0e9Bd947A5592", 100),
		("0x324152a714E266f85dBfbeEDe0CE6F1f91D8346f", 100),
		("0x667aC3f4283aa327D34F8E62742E4759F6ff9E72", 100),
		("0xEcaaDb6B56601CA05030647dCA9fAaf6426F8FB0", 100),
		("0xB184FEd855c51245711Ee4F5A3b13B928aE9a9A6", 100),
		("0x5B38Da6a701c568545dCfcB03FcB875f56beddC4", 100),
	];

	let leaves = data_raw
		.iter()
		.map(|(addr, amount)| {
			// mock abi.encodePacked here, 20 bytes address + 32 bytes amount
			// you can use your own encode method, or some lib like ethabi
			let mut leaf = [0u8; 52];
			leaf[..20].copy_from_slice(&hex::decode(&(*addr)[2..]).unwrap());
			leaf[20..].copy_from_slice(&i32_to_uint256(*amount));
			keccak256(&leaf)
		})
		.collect::<Vec<_>>();

	let tree = MerkleTree::new(
		KeccakHasher,
		leaves.clone(),
		Some(MerkleOptions {
			sort: Some(true),
			..Default::default()
		}),
	);

	println!("root: {}", hex::encode(tree.root()));

	let proof = tree.proof(&leaves[0]).unwrap();

	let ok = tree.verify(&leaves[0], &tree.root(), &proof);
	println!("verify: {}", ok);
}

#[test]
fn main_readme() {
	let data_raw = vec!["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"];

	let leaves = data_raw.iter().map(|s| keccak256(&s.as_bytes())).collect::<Vec<_>>();

	let tree = MerkleTree::new(KeccakHasher, leaves.clone(), Some(tiny_merkle::MerkleOptions::default().with_sort(true)));

	println!("root: {}", hex::encode(tree.root()));

	let proof = tree.proof(&leaves[0]).unwrap();

	let ok = tree.verify(&leaves[0], &tree.root(), &proof);
	println!("verify: {}", ok);
}
