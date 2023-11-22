pub trait Hasher {
	type Hash: AsRef<[u8]> + Clone + Ord;

	/// Gets the hash of the byte sequence.
	fn hash(&self, value: &[u8]) -> Self::Hash;
}
