mod common;

mod proof {

	use hex_literal::hex;
	use sha2::Digest;

	use tiny_merkle::*;

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
	impl tiny_merkle::Hasher for KeccakHasher {
		type Hash = [u8; 32];

		fn hash(&self, value: &[u8]) -> Self::Hash {
			keccak256(value)
		}
	}

	const SIMPLE_DATA: [&str; 127] = [
		"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "1", "2",
		"3", "4", "5", "6", "7", "8", "9", "0", "!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "-", "_", "+", "=", "[", "]", "{", "}", ";", ":",
		"'", "<", ">", ",", ".", "/", "?", "|", "\\", "~", "`", " ", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P",
		"Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "Aa", "Bb", "Cc", "Dd", "Ee", "Ff", "Gg", "Hh", "Ii", "Jj", "Kk", "Ll", "Mm", "Nn", "Oo",
		"Pp", "Qq", "Rr", "Ss", "Tt", "Uu", "Vv", "Ww", "Xx", "Yy", "Zz", "Aaa", "Bbb", "Ccc", "Ddd", "Eee", "Fff", "Ggg",
	];

	// fn merkle_proof_from_vec<H>(leaf_hashes: Vec<H::Hash>) -> MerkleProof<H>
	//     where H: tiny_merkle::Hasher
	// {

	//     MerkleProof {
	//         data: leaf_hashes,
	//         position: Position::Left,
	//     }
	// }

	#[test]
	fn merkle_root() {
		let expected_root_hex = hex!("5c0b53a1f24dbf1280ee00246e83b627fcaa45016b5c291a3f9608e5e2a38c6c");
		let leaf_hashes: Vec<_> = SIMPLE_DATA.iter().map(|x| keccak256(x.as_bytes())).collect();
		let tree = MerkleTree::<KeccakHasher>::new(KeccakHasher, leaf_hashes.clone(), Some(MerkleOptions::new().with_sort(true)));
		assert_eq!(
			tree.root().as_ref(),
			expected_root_hex,
			"root hash mismatch, expected: {:?}, actual: {:?}",
			hex::encode(expected_root_hex),
			hex::encode(tree.root().as_ref())
		);
	}

	macro_rules! test_proof_from_data {
		($name:ident, $src:expr, $proof_exp:expr) => {
			#[test]
			fn $name() {
				let mut leaf_hashes: Vec<_> = SIMPLE_DATA.iter().map(|x| keccak256(x.as_bytes())).collect();
				for i in 0..99_999 {
					leaf_hashes.push(keccak256(i.to_string().as_bytes()));
				}
				let tree = MerkleTree::<KeccakHasher>::new(KeccakHasher, leaf_hashes.clone(), Some(MerkleOptions::new().with_sort(true)));

				let proof = tree.proof(keccak256($src.as_bytes()).as_ref()).expect("Failed to generate proof");
				let p = proof.iter().map(|p| format!("0x{}", hex::encode(p.data))).collect::<Vec<_>>();
				assert_eq!(p, $proof_exp, "proof mismatch, expected: {:?}, actual: {:?}", $proof_exp, p);
			}
		};

		($name:ident, $src:expr, $proof_exp:expr,$pan:expr) => {
			#[test]
			#[should_panic(expected = $pan)]
			fn $name() {
				let mut leaf_hashes: Vec<_> = SIMPLE_DATA.iter().map(|x| keccak256(x.as_bytes())).collect();
				for i in 0..99_999 {
					leaf_hashes.push(keccak256(i.to_string().as_bytes()));
				}
				let tree = MerkleTree::<KeccakHasher>::new(
					KeccakHasher,
					leaf_hashes.clone(),
					Some(MerkleOptions {
						sort: Some(true),
						..Default::default()
					}),
				);

				let proof = tree.proof(keccak256($src.as_bytes()).as_ref()).expect("Failed to generate proof");
				let p = proof.iter().map(|p| format!("0x{}", hex::encode(p.data))).collect::<Vec<_>>();
				assert_eq!(p, $proof_exp, "proof mismatch, expected: {:?}, actual: {:?}", $proof_exp, p);
			}
		};
	}

	test_proof_from_data!(should_panic_on_non_existing_leaf, "non-existing", [""], "Failed to generate proof");

	test_proof_from_data!(
		case_a,
		"a",
		[
			"0x3ac24361cc3421815e1a52dd83d1e23f8cb737b9f938f155a77297e7b12fec76",
			"0x13ed6295c8859c44a873fcb131eca60f5891558f5f3dffbdd8a47d5a9a398648",
			"0xdb50b2c38002ba54d0740313198992fbce111ff87b5fb378531ef8f4c040532c",
			"0xb02c5a4fb26c4465ec139732e6fe33d61f84300b1edaa035b4516f38c72ff78a",
			"0xaa775effdfee6c60db91de57295f116bebab7dfe93b36be6df87e2c348bd3772",
			"0x0b1e7a12ce344bd3b97aa482558812297db8b6bb5eb5bc4c09e9998a4bbb88b3",
			"0x33f687567782c0d26f7dd59187ca48a285e8612802caf4f39a76ad8674be0eeb",
			"0xe36c39e40e8e0644a9f5b497529a511a33b318ba6bfd654e98a47feb09cb7766",
			"0x590e3dadf2abb16d4bd1dda35c6e6932602fb55ea540a97532b54a52b9151f2a",
			"0x6561a0fcfcba8b0bf92d179959c1f05f1dff1a43a6db8514d852311440c5e388",
			"0xb7f192b99b7d8af5f46756371f858268fa5c757c08965e06b035dcfbeae33302",
			"0x1836eb49ce70c168f34e2d82f20b5d407d74c214dfc2c1e46fdc609a172e578f",
			"0x85ba60e991b7c1aff1bd53cea204bb4b199e29bf6feaa6f3d5ae345ea2360fa6",
			"0x00d4584c181d5355ab5effe3e45a88f2d042824278bede00359aa0a57c2c0e3e",
			"0x5ee9b46725de57fa30639c3081d6d4f771a986df4607d3d3eee2e1ded35a2f41",
			"0x4c3a083393c8d4b7990f39cbe31e89d9037d64c51b2bce46a42863c637a0d3b7",
			"0x9b8d306967a28e96696bf30312d2d6427b9e2a1fa80c34212898b8d0f26e66fc"
		]
	);

	test_proof_from_data!(
		case_2011,
		"2011",
		[
			"0x81bc77838f6b5b5a8886b3ed03acf9b6a3f4411411c68e9dec7d5a6741dfc113",
			"0x120c1af406841eb4d70f41a6e97492258b4a9c46f18c2f763ee3d2239e38db8a",
			"0xc8dcf16ddd2175df6aa96573d9c309af599624c83c79713b914712f0d1bcc15f",
			"0x0fc494ca3a6187bdc54e25eb453419882a4dda08b40a1c91fd4c0db9a4bd2347",
			"0x450f2abed1b0456fcad1bb43e42c1cbcd042b7954572a5ce5335a138ac2caa21",
			"0x6c26f31e90e8710df47a00ec0c94e5b47daf176ca99167e1fecba98779784cf9",
			"0x59819d9fbe91b70c84dc0292ed41450c7f28ab999f1025d0ef78af5b6239e277",
			"0x6d378ad7c65f4564da16582c9cd9e3e6add58253c668092a721bcdedbdf644d3",
			"0xf2e31f8f7e1644a2756087d9082e595b44d980d4cd4ac6e5da02eb5099505ba0",
			"0xbf0f730c01e1d56407cf66b479faef1c2935b3a2c610823fb1fab7b67049bc6b",
			"0xf459a5288a7cbc4917d78d86407503d3bfdc474166b86c9011c213a4879ac25c",
			"0xe6a4ef7090ee3d6ef4b8ba985c9a4d90616e3f4a820fab17fa363b14c07738fe",
			"0x53db5af29d77ff6a4683c64ae7cbf2cc9c0ae5cc055de46532c83f9e33a2edac",
			"0x3abaf40ed2d3d75cee628bca314e80cebd51b820806671e7dc7f8037c540d0d1",
			"0xab7abf969ea8ad6e91d97930bb1e3eef97b7a4c70dfb98ac9040f3d02eee58cf",
			"0x802040d0e49f99f4eeb203d76b593f976405eabf5917b64016b8a2fa4ff7a79a",
			"0x9b8d306967a28e96696bf30312d2d6427b9e2a1fa80c34212898b8d0f26e66fc"
		]
	);

	test_proof_from_data!(
		case_99998,
		"99998",
		[
			"0x087625f4776a2f3830b88547091b75e5d5e7751f9d484a845af626d2450d12c0",
			"0x6b3be21547b9af4f8ce082a3de93a3c600c23c99b3d20fa724f7df39c6262315",
			"0x710aec7dc7fe696c8cdc2724ce7174a567a007529884c466757fd2670474f6ba",
			"0x729b7810ae71a8544407e4deb6fcae7b9b330fe6b1dddb9cca8393aff5d9e771",
			"0x7ae09f45c91779ca4397c70b44352c76776bed4715acc881e14649885d8b237b",
			"0x15efdca3da4d52213525e7e564f23339748ffbb7a3624778856aaec922aa4af6",
			"0x11dce373b2c63df97c8748e162e4558504e64bde747242b691c7b48bda7c91f0",
			"0xc9ee50f841d594a8cbc013bf998bdd3c9d5a5dd4bf832ff6df18a9074cc0e66c",
			"0x84bd5d689b3212a831d6408b573181844864409398a4b91494bd343954de1902",
			"0x7c087aea762931d00a1c99b100eecb5ef86b1dd17ff50e557b4575810c5a5753",
			"0xb986b3907dfa8b23964f8d38b5d4472cfa22a0f741755754b21be2b6342636cb",
			"0xd268001dd90df333cdaeb4a5445cb8f1cbae45f243adbd594468b68f88e39659",
			"0xd80e0ba195f702742befa5a5bf1b6e54cffb5c6087e760f8027519147c2e65ea",
			"0x2f9e7139e1629390ce8b72623239ae008e4b921ccd6e8027d33d76da749de11b",
			"0x11172242b4462878c6724f9e5643a59e9594d8a63551c8bff8f97eec878ad8b1",
			"0x4c3a083393c8d4b7990f39cbe31e89d9037d64c51b2bce46a42863c637a0d3b7",
			"0x9b8d306967a28e96696bf30312d2d6427b9e2a1fa80c34212898b8d0f26e66fc"
		]
	);

	test_proof_from_data!(
		case_div,
		"\\",
		[
			"0x73164de805ff1085f1f84748750ad2fcf1920f85fdb3398a9a38f00fd03f366b",
			"0xd8cb469a36ff4c839be1cf197b846325b5614b2d02c6267fee563d8629877fbf",
			"0xc36108ab91948541bece3b1645e428acee7df23a6aee02fa352923c810b26e64",
			"0x6eb9ba31bcde003855e44d03c518b4e8c5f06e35c2ca1d5dd81ae5fe000650bb",
			"0x06f1ea8e8c41a3e79ca9d29a4ceff520da38012daccae443e71dac187f3f384a",
			"0x530d280fe7459ef3b2075fa557c606accadbbd27167c74ffca034736632b4037",
			"0xe712a302b1c16fd2371db32a8a98b9b1d13df3ba419df0890547d9ada6c0908b",
			"0x31d8d65dfe5a0747109c81069c9b167c5ba9b0bc291ae0305d88a599715ba740",
			"0x55cddc54123803e6081a89d7403d4b2faf52e5199efaa0ea84237ab02b5c677b",
			"0x1e6b12891592f9f9002e2a8dfdd080955acebb6a15e53edae06cd2abd83435eb",
			"0x4fa8871f13c60a4299936c48bf500f90cfca88ab1e1141f255b7d5e4052c6a93",
			"0xe65e2ffa59b38daa280b79cb4c385a9a08d7a021ae1fc11000d0a9c1b5f7f668",
			"0x990b29a419e5a5f0b37e873022d3415876c997960f26b1d420b0c3cc88da246b",
			"0x24ee88383357b6e9b0c7c903ee97c438613176573d4da7ee8f89cfb72b92002c",
			"0x0a648aa2e067dab794ce9b9a995c45a95570cff8b142371c81e9c04a790c7e52",
			"0x802040d0e49f99f4eeb203d76b593f976405eabf5917b64016b8a2fa4ff7a79a",
			"0x9b8d306967a28e96696bf30312d2d6427b9e2a1fa80c34212898b8d0f26e66fc"
		]
	);

	#[test]
	#[ignore]
	fn keccak256_proof() {
		let mut leaf_hashes: Vec<_> = SIMPLE_DATA.iter().map(|x| keccak256(x.as_bytes())).collect();
		for i in 0..99_999 {
			leaf_hashes.push(keccak256(i.to_string().as_bytes()));
		}
		let tree = MerkleTree::<KeccakHasher>::new(
			KeccakHasher,
			leaf_hashes.clone(),
			Some(MerkleOptions {
				sort: Some(true),
				..Default::default()
			}),
		);

		for (i, leaf) in leaf_hashes.iter().enumerate() {
			let proof = tree.proof(leaf).expect("Failed to generate proof");
			assert!(
				tree.verify(leaf, &tree.root(), &proof),
				"Failed to verify proof, leaf: {:?}, value: {:?}",
				hex::encode(leaf),
				SIMPLE_DATA[i]
			);
		}
	}

	#[allow(dead_code)]
	fn sha256(data: &[u8]) -> [u8; 32] {
		let mut hasher = sha2::Sha256::new();
		let mut hash = [0u8; 32];
		hasher.update(data);
		hash.copy_from_slice(hasher.finalize().as_slice());
		hash
	}

	#[test]
	#[ignore]
	fn test_10w() {
		let start = std::time::Instant::now();
		let mut leaf_hashes: Vec<_> = SIMPLE_DATA.iter().map(|x| keccak256(x.as_bytes())).collect();
		for i in 0..99_999 {
			leaf_hashes.push(keccak256(i.to_string().as_bytes()));
		}
		// leaf_hashes.sort();

		let tree = MerkleTree::<KeccakHasher>::new(
			KeccakHasher,
			leaf_hashes.clone(),
			Some(MerkleOptions {
				sort: Some(true),
				..Default::default()
			}),
		);
		let _root = tree.root();
		let _root = tree.root();
		let _root = tree.root();

		let end = start.elapsed();
		println!("{}.{:03} s", end.as_secs(), end.subsec_millis());
	}
}
